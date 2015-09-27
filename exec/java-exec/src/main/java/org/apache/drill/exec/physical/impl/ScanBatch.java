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
package org.apache.drill.exec.physical.impl;

import io.netty.buffer.DrillBuf;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.exceptions.UserException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos.MinorType;
import org.apache.drill.common.types.Types;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.memory.OutOfMemoryException;
import org.apache.drill.exec.memory.OutOfMemoryRuntimeException;
import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.base.PhysicalOperator;
import org.apache.drill.exec.record.BatchSchema;
import org.apache.drill.exec.record.BatchSchema.SelectionVectorMode;
import org.apache.drill.exec.record.CloseableRecordBatch;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.record.TypedFieldId;
import org.apache.drill.exec.record.VectorContainer;
import org.apache.drill.exec.record.VectorWrapper;
import org.apache.drill.exec.record.WritableBatch;
import org.apache.drill.exec.record.selection.SelectionVector2;
import org.apache.drill.exec.record.selection.SelectionVector4;
import org.apache.drill.exec.server.options.OptionValue;
import org.apache.drill.exec.store.RecordReader;
import org.apache.drill.exec.testing.ControlsInjector;
import org.apache.drill.exec.testing.ControlsInjectorFactory;
import org.apache.drill.exec.util.CallBack;
import org.apache.drill.exec.vector.AllocationHelper;
import org.apache.drill.exec.vector.NullableVarCharVector;
import org.apache.drill.exec.vector.SchemaChangeCallBack;
import org.apache.drill.exec.vector.ValueVector;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * Record batch used for a particular scan. Operators against one or more
 */
public class ScanBatch implements CloseableRecordBatch {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ScanBatch.class);
  private static final ControlsInjector injector = ControlsInjectorFactory.getInjector(ScanBatch.class);

  private final Map<MaterializedField.Key, ValueVector> fieldVectorMap = Maps.newHashMap();

  private final VectorContainer container = new VectorContainer();
  private int recordCount;
  private final FragmentContext context;
  private final OperatorContext oContext;
  private Iterator<RecordReader> readers;
  private RecordReader currentReader;
  private BatchSchema schema;
  private final Mutator mutator = new Mutator();
  private Iterator<String[]> partitionColumns;
  private String[] partitionValues;
  private List<ValueVector> partitionVectors;
  private List<Integer> selectedPartitionColumns;
  private String partitionColumnDesignator;
  private boolean done = false;
  private SchemaChangeCallBack callBack = new SchemaChangeCallBack();
  private boolean hasReadNonEmptyFile = false;

  /** Whether {@link #next()} has returned {@link IterOutcome#OK_NEW_SCHEMA}
      yet.  Used to make sure that {@code next()} returns {@code OK_NEW_SCHEMA}
      at least once before returning {@link IterOutcome#NONE} (e.g., when scan
      has only empty files). */
  private boolean haveReturnedAnySchema = false;


  public ScanBatch(PhysicalOperator subScanConfig, FragmentContext context, OperatorContext oContext,
                   Iterator<RecordReader> readers, List<String[]> partitionColumns,
                   List<Integer> selectedPartitionColumns) throws ExecutionSetupException {
    this.context = context;
    this.readers = readers;
    if (!readers.hasNext()) {
      throw new ExecutionSetupException("A scan batch must contain at least one reader.");
    }
    currentReader = readers.next();
    this.oContext = oContext;

    boolean setup = false;
    try {
      oContext.getStats().startProcessing();
      currentReader.setup(oContext, mutator);
      setup = true;
    } finally {
      // if we had an exception during setup, make sure to release existing data.
      if (!setup) {
        try {
          currentReader.close();
        } catch(final Exception e) {
          throw new ExecutionSetupException(e);
        }
      }
      oContext.getStats().stopProcessing();
    }
    this.partitionColumns = partitionColumns.iterator();
    partitionValues = this.partitionColumns.hasNext() ? this.partitionColumns.next() : null;
    this.selectedPartitionColumns = selectedPartitionColumns;

    // TODO Remove null check after DRILL-2097 is resolved. That JIRA refers to test cases that do not initialize
    // options; so labelValue = null.
    final OptionValue labelValue = context.getOptions().getOption(ExecConstants.FILESYSTEM_PARTITION_COLUMN_LABEL);
    partitionColumnDesignator = labelValue == null ? "dir" : labelValue.string_val;

    addPartitionVectors();
  }

  public ScanBatch(PhysicalOperator subScanConfig, FragmentContext context,
                   Iterator<RecordReader> readers)
      throws ExecutionSetupException {
    this(subScanConfig, context,
        context.newOperatorContext(subScanConfig, false /* ScanBatch is not subject to fragment memory limit */),
        readers, Collections.<String[]> emptyList(), Collections.<Integer> emptyList());
  }

  @Override
  public FragmentContext getContext() {
    return context;
  }

  @Override
  public BatchSchema getSchema() {
    return schema;
  }

  @Override
  public int getRecordCount() {
    return recordCount;
  }

  @Override
  public void kill(boolean sendUpstream) {
    if (sendUpstream) {
      done = true;
    } else {
      releaseAssets();
    }
  }

  private void releaseAssets() {
    container.zeroVectors();
  }

  private void clearFieldVectorMap() {
    for (final ValueVector v : fieldVectorMap.values()) {
      v.clear();
    }
  }

  @Override
  public IterOutcome next() {
    if (done) {
      return IterOutcome.NONE;
    }
    oContext.getStats().startProcessing();
    try {
      try {
        injector.injectChecked(context.getExecutionControls(), "next-allocate", OutOfMemoryException.class);

        currentReader.allocate(fieldVectorMap);
      } catch (OutOfMemoryException | OutOfMemoryRuntimeException e) {
        logger.debug("Caught Out of Memory Exception", e);
        clearFieldVectorMap();
        return IterOutcome.OUT_OF_MEMORY;
      }
      while ((recordCount = currentReader.next()) == 0) {
        try {
          if (!readers.hasNext()) {
            // We're on the last reader.
            currentReader.close();
            releaseAssets();
            done = true;  // have any future call to next() return NONE
            if (mutator.isNewSchema()) {
              // This last reader has a new schema, but zero data rows of that
              // schema.  Therefore, we seem to have a file, or other source,
              // with zero rows.  However, the lack of rows does not necessarily
              // mean there is a null schema (as for an empty JSON file).

              container.buildSchema(SelectionVectorMode.NONE);
              schema = container.getSchema();

              System.err.println( "??? TEMP ScanBatch.next(): 2288 STATE:  (???)" );
              System.err.println( "??? TEMP ScanBatch.next(): schema.getFieldCount() = " + schema.getFieldCount() );
              final IterOutcome zeroRowReaderResult;
              final boolean emptyJsonCasePURGE = 
                  1 == schema.getFieldCount() 
                  && "*".equals(schema.getColumn(0).getLastName());
              if (! haveReturnedAnySchema) {
                // We haven't returned OK_NEW_SCHEMA yet, so per the (current)
                // IterOutcome/next() protocol (e.g., returning OK_NEW_SCHEMA
                // before returning NONE), we should return OK_NEW_SCHEMA (to
                // give the caller its expected OK_NEW_SCHEMA) before we return
                // NONE for the end of this scan batch.
                // However, ??? (RESOLVE).

                if (0 != schema.getFieldCount()) {
                  if (! emptyJsonCasePURGE) {
                    // Regular static-schema case--MUST return OK_NEW_SCHEMA
                    // so caller can get the schema.
                    zeroRowReaderResult = IterOutcome.OK_NEW_SCHEMA;
                  } else {
                    // Empty-JSON file case (dummy schema with one column "*")--
                    // ??? RESOLVE
                    zeroRowReaderResult = IterOutcome.OK_NEW_SCHEMA;
                  }
                } else {
                  // Empty-schema case (unknown whether can exist)--??? RESOLVE.
                  zeroRowReaderResult = IterOutcome.NONE; //????
                }
              } else {
                // We have already returned OK_NEW_SCHEMA, so, for raw purposes
                // of satisfying the (current) IterOutcome/next() protocol, we
                // can ignore this new schema for which there are no rows and
                // signal that we're finished.
                // However, ???? RESOLVE.

                if (0 != schema.getFieldCount()) {
                  if (! emptyJsonCasePURGE) {
                    // LOOKS LIKE regular static-schema case, except that we
                    // get reports of schema change at the end of some JSON
                    // files even though there is no schema change at the
                    // record boundary indicated by the previously and currently
                    // returned record counts--??? RESOLVE:  Is this ever a
                    // valid schema change that we need to return to the caller? ??? FIXED?
                    zeroRowReaderResult = IterOutcome.OK_NEW_SCHEMA; ///?????? TRY OK_NEW_SCHEMA
                  } else {
                    // Empty-JSON file case (dummy schema with one column "*")--
                    // ??? RESOLVE
                    zeroRowReaderResult = IterOutcome.OK_NEW_SCHEMA; //????
                  }
                } else {
                  // Empty-schema case (unknown whether can exist)--??? RESOLVE.
                  zeroRowReaderResult = IterOutcome.NONE; //????
                }
              }
              if (IterOutcome.OK_NEW_SCHEMA == zeroRowReaderResult) {
                haveReturnedAnySchema = true;
              }
              return zeroRowReaderResult;
            }
            return IterOutcome.NONE;
          }

          // If all the files we have read so far are just empty, the schema is not useful
          if (!hasReadNonEmptyFile) {
            container.clear();
            for (ValueVector v : fieldVectorMap.values()) {
              v.clear();
            }
            fieldVectorMap.clear();
          }

          currentReader.close();
          currentReader = readers.next();
          partitionValues = partitionColumns.hasNext() ? partitionColumns.next() : null;
          currentReader.setup(oContext, mutator);
          try {
            currentReader.allocate(fieldVectorMap);
          } catch (OutOfMemoryException e) {
            logger.debug("Caught OutOfMemoryException");
            clearFieldVectorMap();
            return IterOutcome.OUT_OF_MEMORY;
          }
          addPartitionVectors();

        } catch (ExecutionSetupException e) {
          this.context.fail(e);
          releaseAssets();
          return IterOutcome.STOP;
        }
      }

      hasReadNonEmptyFile = true;
      populatePartitionVectors();

      for (VectorWrapper w : container) {
        w.getValueVector().getMutator().setValueCount(recordCount);
      }


      // this is a slight misuse of this metric but it will allow Readers to report how many records they generated.
      final boolean isNewSchema = mutator.isNewSchema();
      oContext.getStats().batchReceived(0, getRecordCount(), isNewSchema);

      if (isNewSchema) {
        container.buildSchema(SelectionVectorMode.NONE);
        schema = container.getSchema();
        haveReturnedAnySchema = true;
        return IterOutcome.OK_NEW_SCHEMA;
      } else {
        return IterOutcome.OK;
      }
    } catch (OutOfMemoryRuntimeException ex) {
      context.fail(UserException.memoryError(ex).build(logger));
      return IterOutcome.STOP;
    } catch (Exception ex) {
      logger.debug("Failed to read the batch. Stopping...", ex);
      context.fail(ex);
      return IterOutcome.STOP;
    } finally {
      oContext.getStats().stopProcessing();
    }
  }

  private void addPartitionVectors() throws ExecutionSetupException {
    try {
      if (partitionVectors != null) {
        for (ValueVector v : partitionVectors) {
          v.clear();
        }
      }
      partitionVectors = Lists.newArrayList();
      for (int i : selectedPartitionColumns) {
        final MaterializedField field =
            MaterializedField.create(SchemaPath.getSimplePath(partitionColumnDesignator + i),
                                     Types.optional(MinorType.VARCHAR));
        final ValueVector v = mutator.addField(field, NullableVarCharVector.class);
        partitionVectors.add(v);
      }
    } catch(SchemaChangeException e) {
      throw new ExecutionSetupException(e);
    }
  }

  private void populatePartitionVectors() {
    for (int index = 0; index < selectedPartitionColumns.size(); index++) {
      final int i = selectedPartitionColumns.get(index);
      final NullableVarCharVector v = (NullableVarCharVector) partitionVectors.get(index);
      if (partitionValues.length > i) {
        final String val = partitionValues[i];
        AllocationHelper.allocate(v, recordCount, val.length());
        final byte[] bytes = val.getBytes();
        for (int j = 0; j < recordCount; j++) {
          v.getMutator().setSafe(j, bytes, 0, bytes.length);
        }
        v.getMutator().setValueCount(recordCount);
      } else {
        AllocationHelper.allocate(v, recordCount, 0);
        v.getMutator().setValueCount(recordCount);
      }
    }
  }

  @Override
  public SelectionVector2 getSelectionVector2() {
    throw new UnsupportedOperationException();
  }

  @Override
  public SelectionVector4 getSelectionVector4() {
    throw new UnsupportedOperationException();
  }

  @Override
  public TypedFieldId getValueVectorId(SchemaPath path) {
    return container.getValueVectorId(path);
  }

  @Override
  public VectorWrapper<?> getValueAccessorById(Class<?> clazz, int... ids) {
    return container.getValueAccessorById(clazz, ids);
  }

  private class Mutator implements OutputMutator {
    /** Whether schema has changed since last inquiry (via #isNewSchema}).  Is
     *  true before first inquiry. */
    boolean schemaChanged = true;


    @SuppressWarnings("unchecked")
    @Override
    public <T extends ValueVector> T addField(MaterializedField field,
                                              Class<T> clazz) throws SchemaChangeException {
      // Check if the field exists.
      ValueVector v = fieldVectorMap.get(field.key());
      if (v == null || v.getClass() != clazz) {
        // Field does not exist--add it to the map and the output container.
        v = TypeHelper.getNewVector(field, oContext.getAllocator(), callBack);
        if (!clazz.isAssignableFrom(v.getClass())) {
          throw new SchemaChangeException(
              String.format(
                  "The class that was provided %s does not correspond to the expected vector type of %s.",
                  clazz.getSimpleName(), v.getClass().getSimpleName()));
        }

        final ValueVector old = fieldVectorMap.put(field.key(), v);
        if (old != null) {
          old.clear();
          container.remove(old);
        }

        container.add(v);
        // Added new vectors to the container--mark that the schema has changed.
        schemaChanged = true;
      }

      return clazz.cast(v);
    }

    @Override
    public void allocate(int recordCount) {
      for (final ValueVector v : fieldVectorMap.values()) {
        AllocationHelper.allocate(v, recordCount, 50, 10);
      }
    }

    /**
     * Reports whether schema has changed (field was added or re-added) since
     * last call to {@link #isNewSchema}.  returns true at first call.
     */
    @Override
    public boolean isNewSchema() {
      // Check if top-level schema or any of the deeper map schemas has changed.

      // Note:  Callback's getSchemaChangeAndReset() must get called in order to
      // reset it and avoid false reports of schema changes in future.  (Be
      // careful with short-circuit OR (||) operator.)
      
      boolean deeperSchemaChanged = callBack.getSchemaChangedAndReset();
      if (schemaChanged || deeperSchemaChanged) {
        schemaChanged = false;
        return true;
      }
      return false;
    }

    @Override
    public DrillBuf getManagedBuffer() {
      return oContext.getManagedBuffer();
    }

    @Override
    public CallBack getCallBack() {
      return callBack;
    }
  }

  @Override
  public Iterator<VectorWrapper<?>> iterator() {
    return container.iterator();
  }

  @Override
  public WritableBatch getWritableBatch() {
    return WritableBatch.get(this);
  }

  @Override
  public void close() throws Exception {
    container.clear();
    for (final ValueVector v : partitionVectors) {
      v.clear();
    }
    fieldVectorMap.clear();
    currentReader.close();
  }

  @Override
  public VectorContainer getOutgoingContainer() {
    throw new UnsupportedOperationException(
        String.format("You should not call getOutgoingContainer() for class %s",
                      this.getClass().getCanonicalName()));
  }
}
