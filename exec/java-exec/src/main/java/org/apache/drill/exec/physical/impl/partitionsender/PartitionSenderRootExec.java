/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.physical.impl.partitionsender;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;

import javax.inject.Named;

import org.apache.drill.common.expression.ErrorCollector;
import org.apache.drill.common.expression.ErrorCollectorImpl;
import org.apache.drill.common.expression.LogicalExpression;
import org.apache.drill.exec.exception.ClassTransformationException;
import org.apache.drill.exec.exception.OutOfMemoryException;
import org.apache.drill.exec.exception.SchemaChangeRuntimeException;
import org.apache.drill.exec.expr.ClassGenerator;
import org.apache.drill.exec.expr.CodeGenerator;
import org.apache.drill.exec.expr.ExpressionTreeMaterializer;
import org.apache.drill.exec.ops.AccountingDataTunnel;
import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.ops.MetricDef;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.ops.OperatorStats;
import org.apache.drill.exec.physical.MinorFragmentEndpoint;
import org.apache.drill.exec.physical.config.HashPartitionSender;
import org.apache.drill.exec.physical.impl.BaseRootExec;
import org.apache.drill.exec.physical.impl.IterationResult;
import org.apache.drill.exec.proto.ExecProtos.FragmentHandle;
import org.apache.drill.exec.proto.GeneralRPCProtos;
import org.apache.drill.exec.record.BatchSchema;
import org.apache.drill.exec.record.BatchSchema.SelectionVectorMode;
import org.apache.drill.exec.record.FragmentWritableBatch;
import org.apache.drill.exec.record.RecordBatch;
import org.apache.drill.exec.record.RecordBatch.IterOutcome;
import org.apache.drill.exec.record.VectorWrapper;
import org.apache.drill.exec.vector.CopyUtil;

import com.carrotsearch.hppc.IntArrayList;
import com.sun.codemodel.JExpr;
import com.sun.codemodel.JExpression;
import com.sun.codemodel.JType;

public class PartitionSenderRootExec extends BaseRootExec {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PartitionSenderRootExec.class);
  private RecordBatch incoming;
  private HashPartitionSender operator;
  // create a default partitioner that does nothing but maintaining outgoing tunnels until we get ok new schema.
  private Partitioner partitioner = new PartitionerTemplate() {

    @Override
    public void partitionBatch(RecordBatch incoming) {
      // invariant is that partitioner instance will be swapped with real one upon first OK_NEW_SCHEMA so we should
      // never receive a call to this method upon receiving OK.
      throw new UnsupportedOperationException();
    }

    @Override
    public void doSetup(@Named("context") FragmentContext context, @Named("incoming") RecordBatch incoming,
                        @Named("outgoing") OutgoingRecordBatch[] outgoing) { }

    @Override
    public int doEval(@Named("inIndex") int inIndex) {
      return -1;
    }

    @Override
    public void initialize() { }
  };

  private FragmentContext context;
  private boolean ok = true;
  private final int outGoingBatchCount;
  private final HashPartitionSender popConfig;
  private final double cost;

  private final AtomicIntegerArray remainingReceivers;
  private final AtomicInteger remaingReceiverCount;
  private volatile boolean done = false;
  private boolean first = true;

  long minReceiverRecordCount = Long.MAX_VALUE;
  long maxReceiverRecordCount = Long.MIN_VALUE;

  private IntArrayList terminations = new IntArrayList();

  public enum Metric implements MetricDef {
    BATCHES_SENT,
    RECORDS_SENT,
    MIN_RECORDS,
    MAX_RECORDS,
    N_RECEIVERS,
    BYTES_SENT,
    SENDING_THREADS_COUNT,
    COST;

    @Override
    public int metricId() {
      return ordinal();
    }
  }

  public PartitionSenderRootExec(FragmentContext context,
                                 RecordBatch incoming,
                                 HashPartitionSender operator) throws OutOfMemoryException {
    super(context, context.newOperatorContext(operator, null), operator);
    this.incoming = incoming;
    this.operator = operator;
    this.context = context;
    this.outGoingBatchCount = operator.getDestinations().size();
    this.popConfig = operator;
    this.remainingReceivers = new AtomicIntegerArray(outGoingBatchCount);
    this.remaingReceiverCount = new AtomicInteger(outGoingBatchCount);
    this.cost = operator.getChild().getCost();
    partitioner.setup(context, incoming, popConfig, stats, oContext, 0, outGoingBatchCount,
        getSendAvailabilityNotifier());
    stats.setDoubleStat(Metric.COST, this.cost);
    stats.setLongStat(Metric.N_RECEIVERS, outGoingBatchCount);
  }

  @Override
  protected boolean canSend() {
    return partitioner.canSend();
  }

  @Override
  public IterationResult innerNext() {
    if (!ok) {
      return IterationResult.COMPLETED;
    }

    final boolean isPendingIteration = hasPendingState();
    IterOutcome out;
    if (isPendingIteration) {
      out = pendingState.outcome;
      pendingState = null;
    } else if (!done) {
      out = next(incoming);
    } else {
      incoming.kill(true);
      out = IterOutcome.NONE;
    }

    logger.debug("Partitioner.next(): got next record batch with status {}", out);
    if (first && out == IterOutcome.OK) {
      out = IterOutcome.OK_NEW_SCHEMA;
    }
    switch(out){
      case NONE:
        if (!partitioner.flushOutgoingBatches(true, false)) {
          pendingState = IteratorState.of(IterOutcome.NONE);
          return IterationResult.SENDING_BUFFER_FULL;
        }
        return IterationResult.COMPLETED;

      case OUT_OF_MEMORY:
        throw new OutOfMemoryException();

      case STOP:
        partitioner.clear();
        return IterationResult.COMPLETED;

      case OK_NEW_SCHEMA:
        // send all existing batches
        if (!partitioner.flushOutgoingBatches(false, true)) {
          pendingState = IteratorState.of(IterOutcome.OK_NEW_SCHEMA);
          return IterationResult.SENDING_BUFFER_FULL;
        }
        partitioner.clear();

        synchronized (this) {
          partitioner = createPartitioner(outGoingBatchCount);
          partitioner.initialize();
          for (int index = 0; index < terminations.size(); index++) {
            partitioner.getOutgoingBatch(terminations.buffer[index]).terminate();
          }
          // TODO: clearing terminations seem wrong. commenting out for now. check again.
          // terminations.clear();
        }

        if (first) {
          // Send an empty batch for fast schema
          if (!sendEmptyBatch(false)) {
            pendingState = IteratorState.of(IterOutcome.OK_NEW_SCHEMA);
            return IterationResult.SENDING_BUFFER_FULL;
          }
          first = false;
        }
      // fall through
      case OK:
        if (!partitioner.flushIfReady()) {
          pendingState = IteratorState.of(IterOutcome.OK);
          return IterationResult.SENDING_BUFFER_FULL;
        }

        // we partition the incoming data if this is a new iteration because the old batch is already partitioned.
        if (!isPendingIteration) {
          partitioner.partitionBatch(incoming);
        }

        for (VectorWrapper<?> v : incoming) {
          v.clear();
        }
      case NOT_YET:
        return IterationResult.CONTINUE;
      default:
        throw new IllegalStateException();
    }
  }

  protected Partitioner createPartitioner(final int outgoingBatchCount) {
    final Partitioner partitioner = createClassInstances(1).get(0);
    partitioner.setup(context, incoming, popConfig, stats, oContext, 0, outgoingBatchCount,
        getSendAvailabilityNotifier());
    return partitioner;
  }

  private List<Partitioner> createClassInstances(int actualPartitions) {
    // set up partitioning function
    final LogicalExpression expr = operator.getExpr();
    final ErrorCollector collector = new ErrorCollectorImpl();
    final ClassGenerator<Partitioner> cg ;

    cg = CodeGenerator.getRoot(Partitioner.TEMPLATE_DEFINITION, context.getFunctionRegistry());
    ClassGenerator<Partitioner> cgInner = cg.getInnerGenerator("OutgoingRecordBatch");

    final LogicalExpression materializedExpr = ExpressionTreeMaterializer.materialize(expr, incoming, collector, context.getFunctionRegistry());
    if (collector.hasErrors()) {
      throw new SchemaChangeRuntimeException(String.format(
          "Failure while trying to materialize incoming schema.  Errors:\n %s.",
          collector.toErrorString()));
    }

    // generate code to copy from an incoming value vector to the destination partition's outgoing value vector
    JExpression bucket = JExpr.direct("bucket");

    // generate evaluate expression to determine the hash
    ClassGenerator.HoldingContainer exprHolder = cg.addExpr(materializedExpr);
    cg.getEvalBlock().decl(JType.parse(cg.getModel(), "int"), "bucket", exprHolder.getValue().mod(JExpr.lit(outGoingBatchCount)));
    cg.getEvalBlock()._return(cg.getModel().ref(Math.class).staticInvoke("abs").arg(bucket));

    CopyUtil.generateCopies(cgInner, incoming, incoming.getSchema().getSelectionVectorMode() == SelectionVectorMode.FOUR_BYTE);

    try {
      // compile and setup generated code
      List<Partitioner> subPartitioners = context.getImplementationClass(cg, actualPartitions);
      return subPartitioners;

    } catch (ClassTransformationException | IOException e) {
      throw new SchemaChangeRuntimeException("Failure while attempting to load generated class", e);
    }
  }

  /**
   * Find min and max record count seen across the outgoing batches and put them in stats.
   */
  private void updateAggregateStats() {
    for (PartitionOutgoingBatch o : partitioner.getOutgoingBatches()) {
      long totalRecords = o.getTotalRecords();
      minReceiverRecordCount = Math.min(minReceiverRecordCount, totalRecords);
      maxReceiverRecordCount = Math.max(maxReceiverRecordCount, totalRecords);
    }
    stats.setLongStat(Metric.MIN_RECORDS, minReceiverRecordCount);
    stats.setLongStat(Metric.MAX_RECORDS, maxReceiverRecordCount);
  }

  @Override
  public void receivingFragmentFinished(FragmentHandle handle) {
    final int id = handle.getMinorFragmentId();
    if (remainingReceivers.compareAndSet(id, 0, 1)) {
      synchronized (this) {
        terminations.add(id);
        partitioner.getOutgoingBatch(id).terminate();
      }

      int remaining = remaingReceiverCount.decrementAndGet();
      if (remaining == 0) {
        done = true;
      }
    }
  }

  @Override
  public void close() throws Exception {
    logger.debug("Partition sender stopping.");
    super.close();
    ok = false;
    updateAggregateStats();
    partitioner.clear();
  }

  public boolean sendEmptyBatch(boolean isLast) {
    BatchSchema schema = incoming.getSchema();
    if (schema == null) {
      // If the incoming batch has no schema (possible when there are no input records),
      // create an empty schema to avoid NPE.
      schema = BatchSchema.newBuilder().build();
    }

    FragmentHandle handle = context.getHandle();
    for (MinorFragmentEndpoint destination : popConfig.getDestinations()) {
      final AccountingDataTunnel tunnel = context.getDataTunnel(destination);
      FragmentWritableBatch writableBatch = FragmentWritableBatch.getEmptyBatchWithSchema(
          isLast,
          handle.getQueryId(),
          handle.getMajorFragmentId(),
          handle.getMinorFragmentId(),
          operator.getOppositeMajorFragmentId(),
          destination.getId(),
          schema);
      stats.startWait();
      try {
        if (!tunnel.isSendingBufferAvailable()) {
          return false;
        }
        tunnel.sendRecordBatch(writableBatch);
      } finally {
        stats.stopWait();
      }
    }
    stats.addLongStat(Metric.BATCHES_SENT, 1);
    return true;
  }

}
