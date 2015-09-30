/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.planner.sql.logical;

import com.google.common.collect.Lists;
import org.apache.calcite.plan.RelOptRuleCall;
import org.apache.calcite.rex.RexLiteral;
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.base.ScanStats;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.planner.logical.DrillLimitRel;
import org.apache.drill.exec.planner.logical.DrillScanRel;
import org.apache.drill.exec.planner.logical.RelOptHelper;
import org.apache.drill.exec.planner.physical.PrelUtil;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.server.options.OptionManager;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.StoragePluginOptimizerRule;
import org.apache.drill.exec.store.direct.DirectGroupScan;
import org.apache.drill.exec.store.hive.HiveScan;
import org.apache.drill.exec.store.hive.HiveUtilities;
import org.apache.hadoop.hive.metastore.api.FieldSchema;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.serde2.typeinfo.TypeInfo;
import org.apache.hadoop.hive.serde2.typeinfo.TypeInfoUtils;

import java.util.List;

/**
 * For {@code SELECT ... FROM hive.table LIMIT 0} statement that results in:
 *
 *  x
 *   \
 *   Limit(0)
 *     \
 *   HiveScan(table)
 *
 * This rule converts the above tree into:
 *
 *  x
 *   \
 *   DirectGroupScan(HiveColumnNamesReader(table))
 */
public class HiveLimitZeroToDirectScan extends StoragePluginOptimizerRule {
//  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HiveLimitZeroToDirectScan.class);

  public static HiveLimitZeroToDirectScan INSTANCE = new HiveLimitZeroToDirectScan();

  private HiveLimitZeroToDirectScan() {
    super(RelOptHelper.some(DrillLimitRel.class, RelOptHelper.any(DrillScanRel.class)), "HiveLimitZeroToDesc:");
  }

  @Override
  public boolean matches(RelOptRuleCall call) {
    final DrillLimitRel limitRel = (DrillLimitRel) call.rel(0);
    final DrillScanRel scanRel = (DrillScanRel) call.rel(1);

    // match Hive group scan with limit 0
    return scanRel.getGroupScan() instanceof HiveScan && RexLiteral.intValue(limitRel.getFetch()) == 0;
  }

  @Override
  public void onMatch(RelOptRuleCall call) {
    final DrillScanRel scanRel = (DrillScanRel) call.rel(1);
    final HiveScan hiveScan = (HiveScan) scanRel.getGroupScan();

    final OptionManager options = PrelUtil.getPlannerSettings(call.getPlanner()).getOptions();
    final DirectGroupScan directGroupScan = new DirectGroupScan(
      new HiveColumnNamesReader(hiveScan.hiveReadEntry.table.getTable(), options), ScanStats.ZERO_RECORD_TABLE);

    final DrillScanRel convertedScanRel = new DrillScanRel(scanRel.getCluster(), scanRel.getTraitSet(),
      scanRel.getTable(), directGroupScan, scanRel.getRowType(), scanRel.getColumns());
    call.transformTo(convertedScanRel);
  }

  /**
   * Readers that populates the names of columns in the Hive table.
   */
  public static class HiveColumnNamesReader extends AbstractRecordReader {

    public final Table table;
    public final OptionManager options;

    public HiveColumnNamesReader(Table table, OptionManager options) {
      this.table = table;
      this.options = options;
    }

    @Override
    public void setup(OperatorContext context, OutputMutator output) throws ExecutionSetupException {
      final List<TypeInfo> columnTypes = Lists.newArrayList();
      final List<String> columnNames  = Lists.newArrayList();
      for (final FieldSchema fieldSchema : table.getSd().getCols()) {
        columnTypes.add(TypeInfoUtils.getTypeInfoFromTypeString(fieldSchema.getType()));
        columnNames.add(fieldSchema.getName());
      }
      for (int i = 0; i < columnNames.size(); i++) {
        final TypeProtos.MajorType type = HiveUtilities.getMajorTypeFromHiveTypeInfo(columnTypes.get(i), options);
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
