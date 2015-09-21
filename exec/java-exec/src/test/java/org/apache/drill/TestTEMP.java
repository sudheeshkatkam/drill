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

import org.junit.Test;


public class TestTEMP extends BaseTestQuery {
  
  /* 
   * voter2/:
   * 
   * -rw-r--r-- 1 dbarclay dbarclay 38 Sep 17 10:47 voter1.json
   * -rw-r--r-- 1 dbarclay dbarclay  0 Sep 17 21:55 voter2.json
   * -rw-r--r-- 1 dbarclay dbarclay 40 Sep 17 10:47 voter3.json
   * ----------
   * voter1.json
   * {"onecf" : {"name" : "someName1"}  }
   * ----------
   * ----------
   * voter2.json
   * ----------
   * ----------
   * voter3.json
   * {"onecf" : {"NOTname" : "someName2"} }
   *
   * ----------
   */

  @Test
  public void testTEMP() throws Exception {
    test("alter session set `planner.slice_target` = 1");
    
    test( "SELECT COUNT(*) \n"
          + " FROM `dfs.tmp`.`voter3/` AS voter \n"
          + " GROUP BY voter.onecf.name" );
  }

}
