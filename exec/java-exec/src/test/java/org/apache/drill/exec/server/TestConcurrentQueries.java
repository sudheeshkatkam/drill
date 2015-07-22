/*******************************************************************************
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
 ******************************************************************************/
package org.apache.drill.exec.server;

import org.apache.drill.BaseTestQuery;
import org.apache.drill.common.util.TestTools;
import org.apache.drill.exec.client.PrintingResultsListener;
import org.apache.drill.exec.client.QuerySubmitter;
import org.apache.drill.exec.fn.interp.TestConstantFolding;
import org.apache.drill.exec.proto.UserBitShared;
import org.apache.drill.exec.util.VectorUtil;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestRule;

import java.util.ArrayList;
import java.util.List;

import static org.apache.drill.QueryTestUtil.normalizeQuery;

public class TestConcurrentQueries extends BaseTestQuery {

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Rule public final TestRule TIMEOUT = TestTools.getTimeoutRule(500000);

  @Test
  public void testLaggingFragment() throws Exception {
    new TestConstantFolding.SmallFileCreator(folder).createFiles(1, 100_000, "csv");
    test("alter session set `planner.slice_target` = 1");
//    String slowQuery = "select test_debugging_function_wait(columns[0]) from dfs.`/Users/jaltekruse/test_data_drill/bunch_o_csv`";
//    String slowQuery = "select test_debugging_function_wait(columns[0]) from dfs.`" + folder.getRoot().toPath() +"/bigfile` order by columns[2]";
    String slowQuery = "select columns[0] from dfs.`" + folder.getRoot().toPath() +"/bigfile` order by columns[2]";
    String query = normalizeQuery(slowQuery);
    List<SilentListener> listeners = new ArrayList();
    int numQueries = 50;
    try {
      // for (int i = 0; i < numQueries; i++) {
      //   final SilentListener listener = new SilentListener();
      //   listeners.add(listener);
      //   client.runQuery(UserBitShared.QueryType.SQL, query, listener);
      //   Thread.sleep(1000);
      // }

      for (int i = 1; i < 21; i++) {
        final SilentListener listener = new SilentListener();
        listeners.add(listener);
        query = normalizeQuery(getFile("queries/tpch/" + String.format("%02d", i) + ".sql")).replace(';',' ');
        client.runQuery(UserBitShared.QueryType.SQL, query, listener);
        Thread.sleep(100);
      }
      for (int i = 0; i < numQueries; i++) {
        listeners.get(i).waitForCompletion();
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}