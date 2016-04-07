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
package org.apache.drill.exec.physical.impl.producer;

import java.util.concurrent.BlockingDeque;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingDeque;

import com.google.common.base.Preconditions;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos.MajorType;
import org.apache.drill.exec.exception.OutOfMemoryException;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.physical.config.ProducerConsumer;
import org.apache.drill.exec.physical.impl.sort.RecordBatchData;
import org.apache.drill.exec.record.AbstractRecordBatch;
import org.apache.drill.exec.record.BatchSchema;
import org.apache.drill.exec.record.BatchSchema.SelectionVectorMode;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.record.RecordBatch;
import org.apache.drill.exec.record.TransferPair;
import org.apache.drill.exec.record.VectorContainer;
import org.apache.drill.exec.record.VectorWrapper;
import org.apache.drill.exec.vector.ValueVector;
import org.apache.drill.exec.work.batch.IncomingBatchProvider;
import org.apache.drill.exec.work.batch.ReadAvailabilityListener;

public class ProducerConsumerBatch extends AbstractRecordBatch<ProducerConsumer> implements IncomingBatchProvider {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProducerConsumerBatch.class);

  private final RecordBatch incoming;
  private final Thread producer = new Thread(new Producer(), Thread.currentThread().getName() + ":producer");
  private boolean running = false;
  private final BlockingDeque<RecordBatchDataWrapper> queue;
  private int recordCount;
  private volatile boolean populate = true;
  private final CountDownLatch cleanUpLatch = new CountDownLatch(1); // used to wait producer to clean up
  private ReadAvailabilityListener batchListener = ReadAvailabilityListener.LOGGING_SINK;


  protected ProducerConsumerBatch(final ProducerConsumer popConfig, final FragmentContext context, final RecordBatch incoming) throws OutOfMemoryException {
    super(popConfig, context);
    this.incoming = incoming;
    this.queue = new LinkedBlockingDeque<RecordBatchDataWrapper>(popConfig.getSize()) {
      @Override
      public void put(RecordBatchDataWrapper o) throws InterruptedException {
        super.put(o);
        fireReadAvailabilityListener();
      }

      @Override
      public void putFirst(RecordBatchDataWrapper o) throws InterruptedException {
        super.putFirst(o);
        fireReadAvailabilityListener();
      }

      @Override
      public void putLast(RecordBatchDataWrapper o) throws InterruptedException {
        super.putLast(o);
        fireReadAvailabilityListener();
      }
    };
  }

  @Override
  public void setReadAvailabilityListener(final ReadAvailabilityListener listener) {
    synchronized (queue) {
      if (queue.isEmpty()) {
        batchListener = Preconditions.checkNotNull(listener, "batch listener is required");
      } else {
        listener.onReadAvailable(this);
      }
    }
  }

  protected void fireReadAvailabilityListener() {
    synchronized (queue) {
      batchListener.onReadAvailable(ProducerConsumerBatch.this);
      batchListener = ReadAvailabilityListener.LOGGING_SINK;
    }
  }

  @Override
  public IterOutcome next() {
    return super.next();
  }

  @Override
  protected boolean buildSchema() throws SchemaChangeException {
    context.setBlockingIncomingBatchProvider(this);
    if (!running) {
      producer.start();
      running = true;
    }
    state = BatchState.FIRST;
    return false;
  }

  @Override
  public IterOutcome innerNext() {
    final RecordBatchDataWrapper wrapper = queue.poll();
    if (wrapper == null) {
      context.setBlockingIncomingBatchProvider(this);
      return IterOutcome.NOT_YET;
    }

    if (wrapper.finished) {
      return IterOutcome.NONE;
    } else if (wrapper.failed) {
      return IterOutcome.STOP;
    } else if (wrapper.outOfMemory) {
      throw new OutOfMemoryException();
    }

    recordCount = wrapper.batch.getRecordCount();
    final boolean newSchema = load(wrapper.batch);

    return newSchema ? IterOutcome.OK_NEW_SCHEMA : IterOutcome.OK;
  }

  private boolean load(final RecordBatchData batch) {
    final VectorContainer newContainer = batch.getContainer();
    final BatchSchema schema = getSchema();
    if (schema != null && newContainer.getSchema().equals(schema)) {
      container.zeroVectors();
      for (int i = 0; i < container.getNumberOfColumns(); i++) {
        final MaterializedField field = schema.getColumn(i);
        final MajorType type = field.getType();
        final ValueVector vOut = container.getValueAccessorById(TypeHelper.getValueVectorClass(type.getMinorType(), type.getMode()),
                container.getValueVectorId(SchemaPath.getSimplePath(field.getPath())).getFieldIds()).getValueVector();
        final ValueVector vIn = newContainer.getValueAccessorById(TypeHelper.getValueVectorClass(type.getMinorType(), type.getMode()),
                newContainer.getValueVectorId(SchemaPath.getSimplePath(field.getPath())).getFieldIds()).getValueVector();
        final TransferPair tp = vIn.makeTransferPair(vOut);
        tp.transfer();
      }
      return false;
    } else {
      container.clear();
      for (final VectorWrapper<?> w : newContainer) {
        container.add(w.getValueVector());
      }
      container.buildSchema(SelectionVectorMode.NONE);
      return true;
    }
  }

  private class Producer implements Runnable {
    RecordBatchDataWrapper wrapper;

    @Override
    public void run() {
      try {
        while (populate) {
          final IterOutcome upstream = incoming.next();
          switch (upstream) {
            case NONE:
              queue.putLast(RecordBatchDataWrapper.finished());
              return;
            case OUT_OF_MEMORY:
              queue.putFirst(RecordBatchDataWrapper.outOfMemory());
              return;
            case STOP:
              queue.putFirst(RecordBatchDataWrapper.failed());
              return;
            case OK_NEW_SCHEMA:
            case OK:
              wrapper = RecordBatchDataWrapper.batch(new RecordBatchData(incoming, oContext.getAllocator()));
              queue.putLast(wrapper);
              wrapper = null;
              break;
            default:
              throw new UnsupportedOperationException();
          }
        }
      } catch (final OutOfMemoryException e) {
        try {
          queue.putFirst(RecordBatchDataWrapper.outOfMemory());
        } catch (final InterruptedException ex) {
          logger.error("Unable to enqueue the last batch indicator. Something is broken.", ex);
          // TODO InterruptedException
        }
      } catch (final InterruptedException e) {
        logger.warn("Producer thread is interrupted.", e);
        // TODO InterruptedException
      } finally {
        if (wrapper!=null) {
          wrapper.batch.clear();
        }
        cleanUpLatch.countDown();
      }
    }
  }

  private void clearQueue() {
    RecordBatchDataWrapper wrapper;
    while ((wrapper = queue.poll()) != null) {
      if (wrapper.batch != null) {
        wrapper.batch.getContainer().clear();
      }
    }
  }

  @Override
  protected void killIncoming(final boolean sendUpstream) {
    populate = false;
    clearQueue();
  }

  @Override
  public void close() {
    populate = false;
    clearQueue();
    super.close();
  }

  @Override
  public int getRecordCount() {
    return recordCount;
  }

  private static class RecordBatchDataWrapper {
    final RecordBatchData batch;
    final boolean finished;
    final boolean failed;
    final boolean outOfMemory;

    RecordBatchDataWrapper(final RecordBatchData batch, final boolean finished, final boolean failed, final boolean outOfMemory) {
      this.batch = batch;
      this.finished = finished;
      this.failed = failed;
      this.outOfMemory = outOfMemory;
    }

    public static RecordBatchDataWrapper batch(final RecordBatchData batch) {
      return new RecordBatchDataWrapper(batch, false, false, false);
    }

    public static RecordBatchDataWrapper finished() {
      return new RecordBatchDataWrapper(null, true, false, false);
    }

    public static RecordBatchDataWrapper failed() {
      return new RecordBatchDataWrapper(null, false, true, false);
    }

    public static RecordBatchDataWrapper outOfMemory() {
      return new RecordBatchDataWrapper(null, false, false, true);
    }
  }

}
