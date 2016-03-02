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
package org.apache.drill.exec.delegation;

import com.google.common.collect.Maps;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.dotdrill.DotDrillType;
import org.apache.drill.exec.impersonation.BaseTestImpersonation;
import org.apache.drill.exec.rpc.user.UserSession;
import org.apache.drill.exec.rpc.user.security.testing.UserAuthenticatorToTestDelegation;
import org.apache.drill.exec.store.dfs.WorkspaceConfig;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertEquals;

public class TestUserDelegation extends BaseTestImpersonation {

  public static final String OWNER = org1Users[0];
  public static final String OWNER_PASSWORD = "delegator";

  public static final String DELEGATOR_NAME = org1Users[1];
  public static final String DELEGATOR_PASSWORD = "delegator";

  public static final String DATA_GROUP = org1Groups[0];

  public static final String DELEGATE_NAME = org1Users[2];
  public static final String DELEGATE_PASSWORD = "delegate";

  @BeforeClass
  public static void setup() throws Exception {
    startMiniDfsCluster(TestUserDelegation.class.getSimpleName());
    Properties props = cloneDefaultTestConfigProperties();
    props.setProperty(ExecConstants.IMPERSONATION_ENABLED, Boolean.toString(true));
    props.setProperty(ExecConstants.USER_AUTHENTICATION_ENABLED, Boolean.toString(true));
    props.setProperty(ExecConstants.USER_AUTHENTICATOR_IMPL, UserAuthenticatorToTestDelegation.TYPE);
    props.setProperty(ExecConstants.USER_DELEGATION_ENABLED, Boolean.toString(true));

    startDrillCluster(props);
    addMiniDfsBasedStorage(createTestWorkspaces());
    createTestData();
  }

  private static Map<String, WorkspaceConfig> createTestWorkspaces() throws Exception {
    Map<String, WorkspaceConfig> workspaces = Maps.newHashMap();
    createAndAddWorkspace(OWNER, getUserHome(OWNER), (short) 0755, OWNER, DATA_GROUP, workspaces);
    createAndAddWorkspace(DELEGATE_NAME, getUserHome(DELEGATE_NAME), (short) 0755, DELEGATE_NAME, DATA_GROUP,
        workspaces);
    return workspaces;
  }

  private static void createTestData() throws Exception {
    // Create table accessible only by OWNER
    final String tableName = "lineitem";
    updateClient(OWNER, OWNER_PASSWORD);
    test("USE " + getWSSchema(OWNER));
    test(String.format("CREATE TABLE %s as SELECT * FROM cp.`tpch/%s.parquet`;", tableName, tableName));

    // Change the ownership and permissions manually.
    // Currently there is no option to specify the default permissions and ownership for new tables.
    final Path tablePath = new Path(getUserHome(OWNER), tableName);
    fs.setOwner(tablePath, OWNER, DATA_GROUP);
    fs.setPermission(tablePath, new FsPermission((short) 0700));

    // Create a view on top of lineitem table; allow DELEGATOR to read the view
    // /user/user0_1    u0_lineitem    750    user0_1:group0_1
    final String viewName = "u0_lineitem";
    test(String.format("ALTER SESSION SET `%s`='%o';", ExecConstants.NEW_VIEW_DEFAULT_PERMS_KEY, (short) 0750));
    test(String.format("CREATE VIEW %s.%s AS SELECT l_orderkey, l_partkey FROM %s.%s;",
        getWSSchema(OWNER), viewName, getWSSchema(OWNER), "lineitem"));
    // Verify the view file created has the expected permissions and ownership
    final Path viewFilePath = new Path(getUserHome(OWNER), viewName + DotDrillType.VIEW.getEnding());
    final FileStatus status = fs.getFileStatus(viewFilePath);
    assertEquals(org1Groups[0], status.getGroup());
    assertEquals(OWNER, status.getOwner());
    assertEquals((short) 0750, status.getPermission().toShort());

    // Authorize DELEGATOR to delegate for DELEGATE
    updateClient(UserAuthenticatorToTestDelegation.PROCESS_USER,
        UserAuthenticatorToTestDelegation.PROCESS_USER_PASSWORD);
    test("ALTER SYSTEM SET `%s`='%s'", ExecConstants.DELEGATES_KEY, DELEGATE_NAME);
    test("ALTER SYSTEM SET `%s`='%s=%s'", ExecConstants.USER_DELEGATION_DEFINITIONS_KEY,
        DELEGATE_NAME, DELEGATOR_NAME);
  }

  @Test
  public void selectChainedView() throws Exception {
    // Connect as DELEGATE and query for DELEGATOR
    // data belongs to OWNER, however a view is shared with DELEGATOR
    final Properties connectionProps = new Properties();
    connectionProps.setProperty(UserSession.USER, DELEGATE_NAME);
    connectionProps.setProperty(UserSession.PASSWORD, DELEGATE_PASSWORD);
    connectionProps.setProperty(UserSession.DELEGATOR, DELEGATOR_NAME);
    updateClient(connectionProps);

    testBuilder()
        .sqlQuery("SELECT * FROM %s.u0_lineitem ORDER BY l_orderkey LIMIT 1", getWSSchema(OWNER))
        .ordered()
        .baselineColumns("l_orderkey", "l_partkey")
        .baselineValues(1, 1552)
        .go();
  }
}
