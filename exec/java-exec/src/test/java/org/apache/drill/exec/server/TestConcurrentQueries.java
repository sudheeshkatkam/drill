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

import com.google.common.collect.Lists;
import org.apache.drill.BaseTestQuery;
import org.apache.drill.common.util.TestTools;
import org.apache.drill.exec.fn.interp.TestConstantFolding;
import org.apache.drill.exec.proto.UserBitShared;
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
  public void testLaggingFragment() throws Throwable {
    new TestConstantFolding.SmallFileCreator(folder).createFiles(1, 100_000, "csv");
    test("alter session set `planner.slice_target` = 1");
    List<SilentListener> listeners = new ArrayList<>();
    try {
      List<Integer> tpchToSkip = Lists.newArrayList(2,11, 15,16, 17, 19);
      for (int j = 1; j < 5; j++) {
        for (int i = 1; i < 21; i++) {
          if (tpchToSkip.contains(i)) {
            continue;
          }
          final SilentListener listener = new SilentListener();
          listeners.add(listener);
          String query = normalizeQuery(getFile("queries/tpch/" + String.format("%02d", i) + ".sql")).replace(';',' ');
          client.runQuery(UserBitShared.QueryType.SQL, query, listener);
          Thread.sleep(100);
        }
      }
      for (SilentListener listener : listeners) {
        listener.waitForCompletion();
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}