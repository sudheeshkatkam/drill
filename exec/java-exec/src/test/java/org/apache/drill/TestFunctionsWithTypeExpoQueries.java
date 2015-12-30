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
package org.apache.drill;

import org.apache.drill.common.types.TypeProtos;
import org.apache.drill.common.util.FileUtils;
import org.junit.Ignore;
import org.junit.Test;

public class TestFunctionsWithTypeExpoQueries extends BaseTestQuery {

  @Test
  public void testViewShield() throws Exception {
    try {
      test("use dfs_test.tmp;");
      final String view1 =
          "create view TestFunctionsWithTypeExpoQueries_testViewShield1 as \n" +
              "select rnum, position_id, " +
              "   ntile(4) over(order by position_id) " +
              " from (select position_id, row_number() " +
              "       over(order by position_id) as rnum " +
              "       from cp.`employee.json`)";


      final String view2 =
          "create view TestFunctionsWithTypeExpoQueries_testViewShield2 as \n" +
              "select row_number() over(order by position_id) as rnum, " +
              "    position_id, " +
              "    ntile(4) over(order by position_id) " +
              " from cp.`employee.json`";

      test(view1);
      test(view2);

      testBuilder()
          .sqlQuery("select * from TestFunctionsWithTypeExpoQueries_testViewShield1")
          .ordered()
          .sqlBaselineQuery("select * from TestFunctionsWithTypeExpoQueries_testViewShield2")
          .build()
          .run();
    } finally {
      test("drop view TestFunctionsWithTypeExpoQueries_testViewShield1;");
      test("drop view TestFunctionsWithTypeExpoQueries_testViewShield2;");
    }
  }

  @Test
  public void testAverage() throws Exception {
    test("select avg(cast(n_nationkey as integer)) from cp.`tpch/nation.parquet`;");
  }

  @Test
  public void testViewAverage() throws Exception {
    try {
      test("use dfs_test.tmp;");
      test("create view TestFunctionsWithTypeExpoQueries_testViewAverage as \n" +
          "select avg(n_nationkey) from cp.`tpch/nation.parquet`;");
      test("select * from TestFunctionsWithTypeExpoQueries_testViewAverage;");
    } finally {
      test("drop view TestFunctionsWithTypeExpoQueries_testViewAverage;");
    }
  }

  @Test
  public void testCastVarbinaryToInt() throws Exception {
    test("explain plan for select cast(a as int) \n" +
      "from cp.`tpch/region.parquet`");
  }

  @Test
  public void testConcatWithMoreThanTwoArgs() throws Exception {
    final String query = "select concat(r_name, r_name, r_name) as col \n" +
        "from cp.`tpch/region.parquet`";
    testBuilder()
        .sqlQuery(query)
        .unOrdered()
        .csvBaselineFile("testframework/testFunctionsWithTypeExpoQueries/testConcatWithMoreThanTwoArgs.tsv")
        .baselineTypes(TypeProtos.MinorType.VARCHAR)
        .baselineColumns("col")
        .build()
        .run();
  }

  @Test
  public void testTrimOnlyOneArg() throws Exception {
    final String query1 = "SELECT ltrim('drill') as col FROM (VALUES(1))";
    final String query2 = "SELECT rtrim('drill') as col FROM (VALUES(1))";
    final String query3 = "SELECT btrim('drill') as col FROM (VALUES(1))";

    testBuilder()
        .sqlQuery(query1)
        .ordered()
        .baselineColumns("col")
        .baselineValues("drill")
        .build()
        .run();

    testBuilder()
        .sqlQuery(query2)
        .ordered()
        .baselineColumns("col")
        .baselineValues("drill")
        .build()
        .run();

    testBuilder()
        .sqlQuery(query3)
        .ordered()
        .baselineColumns("col")
        .baselineValues("drill")
        .build()
        .run();
  }

  @Test
  public void testLengthWithVariArg() throws Exception {
    final String query1 = "SELECT length('drill', 'utf8') as col FROM (VALUES(1))";
    final String query2 = "SELECT length('drill') as col FROM (VALUES(1))";

    testBuilder()
        .sqlQuery(query1)
        .ordered()
        .baselineColumns("col")
        .baselineValues(5l)
        .build()
        .run();

    testBuilder()
        .sqlQuery(query2)
        .ordered()
        .baselineColumns("col")
        .baselineValues(5l)
        .build()
        .run();
  }

  @Test
  public void testPadWithTwoArg() throws Exception {
    final String query1 = "SELECT rpad('drill', 1) as col FROM (VALUES(1))";
    final String query2 = "SELECT lpad('drill', 1) as col FROM (VALUES(1))";

    testBuilder()
        .sqlQuery(query1)
        .ordered()
        .baselineColumns("col")
        .baselineValues("d")
        .build()
        .run();

    testBuilder()
        .sqlQuery(query2)
        .ordered()
        .baselineColumns("col")
        .baselineValues("d")
        .build()
        .run();
  }

  /**
   * In the following query, the extract function would be borrowed from Calcite,
   * which asserts the return type as be BIG-INT
   */
  @Test
  public void testExtractSecond() throws Exception {
    test("select extract(second from time '02:30:45.100') from cp.`tpch/region.parquet`");
  }

  @Test
  public void testNegativeConstants() throws Exception {
    final String query = String.format("select CAST(NEGATIVE(-1993) as Integer) as col \n" +
        "from cp.`tpch/region.parquet` \n" +
        "where (`year` IN (negative(-1993)) and `month`=sqrt(100)) or (`year` IN (cast(abs(-1994.0) as int)) and `month`=cast('5' as int))");

    test(query);
  }

  @Test
  public void testMetaDataExposeType() throws Exception {
    final String root = FileUtils.getResourceAsFile("/typeExposure/metadata_caching").toURI().toString();
    final String query = String.format("select count(*) as col \n" +
        "from dfs_test.`%s` \n" +
        "where concat(a, 'asdf') = 'asdf'", root);

    // Validate the plan
    final String[] expectedPlan = {"Scan.*a.parquet.*numFiles=1"};
    final String[] excludedPlan = {"Filter"};
    PlanTestBase.testPlanMatchingPatterns(query, expectedPlan, excludedPlan);

    // Validate the result
    testBuilder()
        .sqlQuery(query)
        .ordered()
        .baselineColumns("col")
        .baselineValues(1l)
        .build()
        .run();
  }

  @Test
  public void testNegativeByInterpreter() throws Exception {
    final String query = "select * from cp.`tpch/region.parquet` \n" +
        "where r_regionkey = negative(-1)";

    // Validate the plan
    final String[] expectedPlan = {"Filter.*condition=\\[=\\(.*, 1\\)\\]\\)"};
    final String[] excludedPlan = {};
    PlanTestBase.testPlanMatchingPatterns(query, expectedPlan, excludedPlan);
  }

  @Test
  @Ignore
  public void testNegativeInterval() throws Exception {
    final String query = "explain plan including all attributes for select * from cp.`tpch/region.parquet` \n" +
        "where r_regionkey = negative(INTERVAL '1-2' year to month)";

    test(query);
  }

  @Test
  @Ignore
  public void testNegativeIntervalInSelect() throws Exception {
    final String query = "explain plan including all attributes for SELECT  negative(INTERVAL '1-2' year to month) FROM (VALUES(1));";

    test(query);
  }

  @Test
  public void test() throws Exception {
    test("explain plan including all attributes for SELECT " +
         "SUM((CASE WHEN ((CAST(EXTRACT(YEAR FROM CAST(`rfm_sales`.`business_date` AS DATE)) AS INTEGER) = 2014) AND (CAST((EXTRACT(MONTH FROM CAST(`rfm_sales`.`business_date` AS DATE)) - 1) / 3 + 1 AS INTEGER) <= 4)) THEN `rfm_sales`.`pos_netsales` ELSE NULL END)) AS `sum_Calculation_CIDBACJBCCCBHDGB_ok` \n" +
         "from cp.`tpch/region.parquet` `rfm_sales` GROUP BY CAST(EXTRACT(MONTH FROM CAST(`rfm_sales`.`business_date` AS DATE)) AS INTEGER)");
  }
}
