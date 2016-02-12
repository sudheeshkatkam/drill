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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import org.apache.calcite.plan.RelTraitSet;
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

  public static ImmutableMap<SqlTypeName, TypeProtos.MinorType> TYPES =
      ImmutableMap.<SqlTypeName, TypeProtos.MinorType> builder()
          .put(SqlTypeName.INTEGER, TypeProtos.MinorType.INT)
          .put(SqlTypeName.BIGINT, TypeProtos.MinorType.BIGINT)
          .put(SqlTypeName.FLOAT, TypeProtos.MinorType.FLOAT4)
          .put(SqlTypeName.DOUBLE, TypeProtos.MinorType.FLOAT8)
          .put(SqlTypeName.VARCHAR, TypeProtos.MinorType.VARCHAR)
          .put(SqlTypeName.BOOLEAN, TypeProtos.MinorType.BIT)
          .put(SqlTypeName.DATE, TypeProtos.MinorType.DATE)
          // (1) Disabling decimal type
          //.put(SqlTypeName.DECIMAL, TypeProtos.MinorType.DECIMAL9)
          //.put(SqlTypeName.DECIMAL, TypeProtos.MinorType.DECIMAL18)
          //.put(SqlTypeName.DECIMAL, TypeProtos.MinorType.DECIMAL28SPARSE)
          //.put(SqlTypeName.DECIMAL, TypeProtos.MinorType.DECIMAL38SPARSE)
          .put(SqlTypeName.TIME, TypeProtos.MinorType.TIME)
          .put(SqlTypeName.TIMESTAMP, TypeProtos.MinorType.TIMESTAMP)
          //.put(SqlTypeName.VARBINARY, TypeProtos.MinorType.VARBINARY)
          .put(SqlTypeName.INTERVAL_YEAR_MONTH, TypeProtos.MinorType.INTERVALYEAR)
          .put(SqlTypeName.INTERVAL_DAY_TIME, TypeProtos.MinorType.INTERVALDAY)
          //.put(SqlTypeName.MAP, TypeProtos.MinorType.MAP)
          //.put(SqlTypeName.ARRAY, TypeProtos.MinorType.LIST)
          .put(SqlTypeName.CHAR, TypeProtos.MinorType.VARCHAR)
          // (2) Avoid late binding
          //.put(SqlTypeName.ANY, TypeProtos.MinorType.LATE)
          // (3) These 2 types are defined in the Drill type system but have been turned off for now
          //.put(SqlTypeName.TINYINT, TypeProtos.MinorType.TINYINT)
          //.put(SqlTypeName.SMALLINT, TypeProtos.MinorType.SMALLINT)
          // (4) Calcite types currently not supported by Drill, nor defined in the Drill type list:
          //      - SYMBOL, MULTISET, DISTINCT, STRUCTURED, ROW, OTHER, CURSOR, COLUMN_LIST
          .build();

  public static boolean containsLimit0(RelNode rel) {
    FindLimit0Visitor visitor = new FindLimit0Visitor();
    rel.accept(visitor);
    return visitor.isContains();
  }

  /**
   * If all field types of the given node are {@link #TYPES recognized types} and honored by execution, then this
   * method returns the tree:
   *   DrillLimitRel(0)
   *     \
   *     DrillDirectScanRel(field types)
   * Otherwise, the method returns null.
   *
   * @param rel calcite logical rel tree
   * @return drill logical rel tree
   */
  public static DrillRel getDirectScanRelIfFullySchemaed(RelNode rel) {
    final List<SqlTypeName> columnTypes = Lists.newArrayList();
    final List<RelDataTypeField> fieldList = rel.getRowType().getFieldList();
    final List<TypeProtos.DataMode> dataModes = Lists.newArrayList();

    for (final RelDataTypeField field : fieldList) {
      final SqlTypeName sqlTypeName = field.getType().getSqlTypeName();
      if (!TYPES.containsKey(sqlTypeName)) {
        return null;
      } else {
        columnTypes.add(sqlTypeName);
        dataModes.add(field.getType().isNullable() ? TypeProtos.DataMode.OPTIONAL : TypeProtos.DataMode.REQUIRED);
      }
    }

    final RelTraitSet traits = rel.getTraitSet().plus(DrillRel.DRILL_LOGICAL);
    final RelDataTypeReader reader = new RelDataTypeReader(rel.getRowType().getFieldNames(), columnTypes,
        dataModes);
    return new DrillDirectScanRel(rel.getCluster(), traits, new DirectGroupScan(reader, ScanStats.ZERO_RECORD_TABLE),
        rel.getRowType());
  }

  private boolean contains = false;

  private FindLimit0Visitor() {
  }

  boolean isContains() {
    return contains;
  }

  private static boolean isLimit0(RexNode fetch) {
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

  // The following set of RelNodes should terminate a search for the limit 0 pattern.
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
  public static class RelDataTypeReader extends AbstractRecordReader {

    public final List<String> columnNames;
    public final List<SqlTypeName> columnTypes;
    public final List<TypeProtos.DataMode> dataModes;

    public RelDataTypeReader(List<String> columnNames, List<SqlTypeName> columnTypes,
                             List<TypeProtos.DataMode> dataModes) {
      this.columnNames = columnNames;
      this.columnTypes = columnTypes;
      this.dataModes = dataModes;
    }

    @Override
    public void setup(OperatorContext context, OutputMutator output) throws ExecutionSetupException {
      for (int i = 0; i < columnNames.size(); i++) {
        final TypeProtos.MajorType type = TypeProtos.MajorType.newBuilder()
            .setMode(dataModes.get(i))
            .setMinorType(TYPES.get(columnTypes.get(i)))
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
