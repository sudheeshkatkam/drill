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
package org.apache.drill.exec.vector;

import com.google.common.base.Preconditions;
import org.apache.drill.exec.record.BatchSchema.SelectionVectorMode;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.record.RecordBatch;
import org.apache.drill.exec.record.VectorWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VectorValidator {
  private static final Logger logger = LoggerFactory.getLogger(VectorValidator.class);

  public static void validate(RecordBatch batch) {
    int batchNumRecords = batch.getRecordCount();
    for (VectorWrapper w : batch) {
      final ValueVector vector = w.getValueVector();
      final MaterializedField field = vector.getField();
      final ValueVector.Accessor accessor = vector.getAccessor();
      final int vectorNumRecords = accessor.getValueCount();
      Preconditions.checkNotNull(vectorNumRecords == batchNumRecords,
          String.format("vectors must have the same number of records with batch. batch has {} vector[{}] has {}",
          batchNumRecords, field, vectorNumRecords));
    }

    long hash = 12345;
    SelectionVectorMode mode = batch.getSchema().getSelectionVectorMode();
    switch(mode) {
      case NONE: {
        for (VectorWrapper w : batch) {
          ValueVector v = w.getValueVector();
          final MaterializedField field = v.getField();

          for (int i = 0; i < batchNumRecords; i++) {
            try {
              Object obj = v.getAccessor().getObject(i);
              if (obj != null) {
                hash = obj.hashCode() ^ hash;
              }
            } catch (final Exception ex) {
              logger.error("unable to validate row: {} - field: {}", i, field, ex);
              throw ex;
            }
          }
        }
        break;
      }
      case TWO_BYTE: {
        for (VectorWrapper w : batch) {
          ValueVector v = w.getValueVector();
          for (int i = 0; i < batchNumRecords; i++) {
            int index = batch.getSelectionVector2().getIndex(i);
            Object obj = v.getAccessor().getObject(index);
            if (obj != null) {
              hash = obj.hashCode() ^ hash;
            }
          }
        }
        break;
      }
      case FOUR_BYTE: {
        for (VectorWrapper w : batch) {
          ValueVector[] vv = w.getValueVectors();
          for (int i = 0; i < batchNumRecords; i++) {
            int index = batch.getSelectionVector4().get(i);
            ValueVector v = vv[index >> 16];
            Object obj = v.getAccessor().getObject(index & 65535);
            if (obj != null) {
              hash = obj.hashCode() ^ hash;
            }
          }
        }
      }
    }
    if (hash == 0) {
//      System.out.println(hash);
    }
  }
}
