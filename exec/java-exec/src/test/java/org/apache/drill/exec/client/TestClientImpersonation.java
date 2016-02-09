/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.client;

import com.google.common.collect.Maps;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.impersonation.BaseTestImpersonation;
import org.apache.drill.exec.rpc.user.UserSession;
import org.apache.drill.exec.rpc.user.security.testing.UserAuthenticatorTest2Impl;
import org.apache.drill.exec.store.dfs.WorkspaceConfig;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Map;
import java.util.Properties;

public class TestClientImpersonation extends BaseTestImpersonation {

  /**
   * The below users belong to group "group0_1". See {@link #org1Groups}.
   */
  public static final String TEST_USER_0 = org1Users[0];
  public static final String TEST_USER_0_PASSWORD = "user1Password";

  public static final String ADMIN_USER = org1Users[1];
  public static final String ADMIN_USER_PASSWORD = "adminUserPassword";

  public static final String USER_GROUP = org1Groups[0];

  @BeforeClass
  public static void setup() throws Exception {
    startMiniDfsCluster(TestClientImpersonation.class.getSimpleName());
    Properties props = cloneDefaultTestConfigProperties();
    props.setProperty(ExecConstants.IMPERSONATION_ENABLED, Boolean.toString(true));
    props.setProperty(ExecConstants.USER_AUTHENTICATION_ENABLED, Boolean.toString(true));
    props.setProperty(ExecConstants.USER_AUTHENTICATOR_IMPL, UserAuthenticatorTest2Impl.TYPE);

    startDrillCluster(props);
    addMiniDfsBasedStorage(createTestWorkspaces());
  }

  private static Map<String, WorkspaceConfig> createTestWorkspaces() throws Exception {
    // Create "/tmp" folder and set permissions to "777"
    final Path tmpPath = new Path("/tmp");
    fs.delete(tmpPath, true);
    FileSystem.mkdirs(fs, tmpPath, new FsPermission((short)0777));

    Map<String, WorkspaceConfig> workspaces = Maps.newHashMap();
    createAndAddWorkspace(TEST_USER_0, getUserHome(TEST_USER_0), (short)0755, TEST_USER_0, USER_GROUP, workspaces);
    return workspaces;
  }

  @Test
  public void simpleQuery() throws Exception {
    // (1) Create table accessible only by TEST_USER_0
    final String tableName = "lineitem";
    updateClient(TEST_USER_0, TEST_USER_0_PASSWORD);
    test("USE " + getWSSchema(TEST_USER_0));
    test(String.format("CREATE TABLE %s as SELECT * FROM cp.`tpch/%s.parquet`;", tableName, tableName));

    // Change the ownership and permissions manually.
    // Currently there is no option to specify the default permissions and ownership for new tables.
    final Path tablePath = new Path(getUserHome(TEST_USER_0), tableName);

    fs.setOwner(tablePath, TEST_USER_0, USER_GROUP);
    fs.setPermission(tablePath, new FsPermission((short)0750));

    // (2) Now connect as ADMIN_USER and query
    final Properties connectionProps = new Properties();
    connectionProps.setProperty(UserSession.USER, ADMIN_USER);
    connectionProps.setProperty(UserSession.PASSWORD, ADMIN_USER_PASSWORD);
    connectionProps.setProperty(UserSession.DELEGATION_UID, ADMIN_USER);
    updateClient(connectionProps);

    test(String.format("SELECT * FROM %s.lineitem ORDER BY l_orderkey LIMIT 1", getWSSchema(TEST_USER_0)));
  }
}
