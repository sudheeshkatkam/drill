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
package org.apache.drill.exec.planner.sql.handlers;

import com.google.common.collect.Lists;
import org.apache.calcite.rel.RelNode;
import org.apache.calcite.rel.RelShuttleImpl;
import org.apache.calcite.rel.logical.LogicalAggregate;
import org.apache.calcite.rel.logical.LogicalIntersect;
import org.apache.calcite.rel.logical.LogicalJoin;
import org.apache.calcite.rel.logical.LogicalMinus;
import org.apache.calcite.rel.logical.LogicalSort;
import org.apache.calcite.rel.logical.LogicalUnion;
import org.apache.calcite.rel.type.RelDataTypeField;
import org.apache.calcite.rex.RexLiteral;
import org.apache.calcite.rex.RexNode;
import org.apache.calcite.sql.SqlKind;
import org.apache.calcite.sql.type.SqlTypeName;
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.base.ScanStats;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.planner.logical.DrillConstExecutor;
import org.apache.drill.exec.planner.logical.DrillDirectScanRel;
import org.apache.drill.exec.planner.logical.DrillRel;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.direct.DirectGroupScan;

import java.util.List;

/**
 * Visitor that will identify whether the root portion of the RelNode tree contains a limit 0 pattern. In this case, we
 * inform the planner settings that this plan should be run as a single node plan to reduce the overhead associated with
 * executing a schema-only query.
 */
public class FindLimit0Visitor extends RelShuttleImpl {
//  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(FindLimit0Visitor.class);

  private boolean contains = false;

  public static boolean containsLimit0(RelNode rel) {
    FindLimit0Visitor visitor = new FindLimit0Visitor();
    rel.accept(visitor);
    return visitor.isContains();
  }

  public static DrillRel getTreeWithDirectSchemaScan(final RelNode rel) {
    final List<SqlTypeName> columnTypes = Lists.newArrayList();
    final List<RelDataTypeField> fieldList = rel.getRowType().getFieldList();
    for (final RelDataTypeField filed : fieldList) {
      final SqlTypeName sqlTypeName = filed.getType().getSqlTypeName();
      if (!DrillConstExecutor.CALCITE_TO_DRILL_TYPE_MAPPING.containsKey(sqlTypeName)) {
        return null;
      } else {
        columnTypes.add(sqlTypeName);
      }
    }

    // The types of all fields are know (i.e. the type is not {@link SqlTypeName#ANY})
    final ColumnNamesReader reader = new ColumnNamesReader(rel.getRowType().getFieldNames(), columnTypes);
    return new DrillDirectScanRel(rel.getCluster(), rel.getTraitSet(),
        new DirectGroupScan(reader, ScanStats.ZERO_RECORD_TABLE), rel.getRowType());
  }

  private FindLimit0Visitor() {
  }

  boolean isContains() {
    return contains;
  }

  private boolean isLimit0(RexNode fetch) {
    if (fetch != null && fetch.isA(SqlKind.LITERAL)) {
      RexLiteral l = (RexLiteral) fetch;
      switch (l.getTypeName()) {
      case BIGINT:
      case INTEGER:
      case DECIMAL:
        if (((long) l.getValue2()) == 0) {
          return true;
        }
      }
    }
    return false;
  }

  @Override
  public RelNode visit(LogicalSort sort) {
    if (isLimit0(sort.fetch)) {
      contains = true;
      return sort;
    }

    return super.visit(sort);
  }

  // The following set of RelNodes should terminate a search for the limit 0 pattern as they want convey its meaning.

  @Override
  public RelNode visit(LogicalAggregate aggregate) {
    return aggregate;
  }

  @Override
  public RelNode visit(LogicalIntersect intersect) {
    return intersect;
  }

  @Override
  public RelNode visit(LogicalJoin join) {
    return join;
  }

  @Override
  public RelNode visit(LogicalMinus minus) {
    return minus;
  }

  @Override
  public RelNode visit(LogicalUnion union) {
    return union;
  }

  /**
   * Reader for column names and types.
   */
  public static class ColumnNamesReader extends AbstractRecordReader {

    public final List<String> columnNames;
    public final List<SqlTypeName> columnTypes;

    public ColumnNamesReader(List<String> columnNames, List<SqlTypeName> columnTypes) {
      this.columnNames = columnNames;
      this.columnTypes = columnTypes;
    }

    @Override
    public void setup(OperatorContext context, OutputMutator output) throws ExecutionSetupException {
      for (int i = 0; i < columnNames.size(); i++) {
        final TypeProtos.MajorType type = TypeProtos.MajorType.newBuilder()
            .setMinorType(DrillConstExecutor.CALCITE_TO_DRILL_TYPE_MAPPING.get(columnTypes.get(i)))
            .build();
        final MaterializedField field = MaterializedField.create(SchemaPath.getSimplePath(columnNames.get(i)), type);
        final Class vvClass = TypeHelper.getValueVectorClass(type.getMinorType(), type.getMode());
        try {
          output.addField(field, vvClass);
        } catch (SchemaChangeException e) {
          throw new ExecutionSetupException(e);
        }
      }
    }

    @Override
    public int next() {
      return 0;
    }

    @Override
    public void close() throws Exception {
    }
  }
}
