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
package org.apache.drill.exec.delegation;

import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.impersonation.BaseTestImpersonation;
import org.apache.drill.exec.server.options.OptionValue;
import org.apache.drill.exec.util.UserDelegationUtil;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;

public class TestDelegationPrivileges extends BaseTestImpersonation {

  // definitions on which the tests are based
  private static final String DELEGATES = "user0_1,user2_1,user4_1,user3_2";
  private static final String USER_DELEGATION_DEFINITIONS = "user0_1=*;user2_1=user3_1;user4_1=user1_1,user3_1";
  private static final String GROUP_DELEGATION_DEFINITIONS = "user0_1=*;user2_1=group2_1;user3_2=group3_2,group1_2";

  private static boolean checkPrivileges(final String delegateName, final String delegatorName,
                                         final String delegates, final String userDefinitions,
                                         final String groupDefinitions) {
    ExecConstants.GROUP_DELEGATION_DEFINITIONS_VALIDATOR.validate(
        OptionValue.createString(OptionValue.OptionType.SYSTEM,
            ExecConstants.GROUP_DELEGATION_DEFINITIONS_KEY,
            groupDefinitions));
    ExecConstants.USER_DELEGATION_DEFINITIONS_VALIDATOR.validate(
        OptionValue.createString(OptionValue.OptionType.SYSTEM,
            ExecConstants.USER_DELEGATION_DEFINITIONS_KEY,
            userDefinitions));

    return UserDelegationUtil.hasDelegationPrivileges(delegateName, delegatorName,
        delegates, userDefinitions, groupDefinitions);
  }

  private static class PrivilegeTest {
    private final String delegate;
    private final String delegator;
    private String delegates = DELEGATES;
    private String userDefinitions = USER_DELEGATION_DEFINITIONS;
    private String groupDefinitions = GROUP_DELEGATION_DEFINITIONS;

    public PrivilegeTest(final String delegate, final String delegator) {
      this.delegate = delegate;
      this.delegator = delegator;
    }

    public PrivilegeTest withDelegates(final String delegates) {
      this.delegates = delegates;
      return this;
    }

    public PrivilegeTest withUserDefinitions(final String userDefinitions) {
      this.userDefinitions = userDefinitions;
      return this;
    }

    public PrivilegeTest withGroupDefinitions(final String groupDefinitions) {
      this.groupDefinitions = groupDefinitions;
      return this;
    }

    public boolean run() {
      return checkPrivileges(delegate, delegator, delegates, userDefinitions, groupDefinitions);
    }
  }

  private static void runWithNoGroupDefinitions(final String delegate, final String delegator,
                                                final boolean result) {
    assertEquals(new PrivilegeTest(delegate, delegator).withGroupDefinitions("").run(), result);
  }

  @Test
  public void userAuthz() {
    for (final String user : org1Users) {
      runWithNoGroupDefinitions("user0_1", user, true);
    }
    for (final String user : org2Users) {
      runWithNoGroupDefinitions("user0_1", user, true);
    }

    for (final String user : org1Users) {
      runWithNoGroupDefinitions("user1_1", user, false);
    }
    for (final String user : org2Users) {
      runWithNoGroupDefinitions("user1_1", user, false);
    }

    runWithNoGroupDefinitions("user2_1", "user3_1", true);
    for (final String user : org1Users)  {
      if (!user.equals("user3_1")) {
        runWithNoGroupDefinitions("user2_1", user, false);
      }
    }
    for (final String user : org2Users) {
      runWithNoGroupDefinitions("user2_1", user, false);
    }

    runWithNoGroupDefinitions("user4_1", "user1_1", true);
    runWithNoGroupDefinitions("user4_1", "user3_1", true);
    for (final String user : org1Users)  {
      if (!user.equals("user1_1") && !user.equals("user3_1")) {
        runWithNoGroupDefinitions("user2_1", user, false);
      }
    }
    for (final String user : org2Users) {
      runWithNoGroupDefinitions("user2_1", user, false);
    }
  }

  private static void runWithNoUserDefinitions(final String delegate, final String delegator,
                                                final boolean result) {
    assertEquals(new PrivilegeTest(delegate, delegator).withUserDefinitions("").run(), result);
  }

  @Test
  public void groupAuthz() {
    for (final String user : org1Users) {
      runWithNoUserDefinitions("user0_1", user, true);
    }
    for (final String user : org2Users) {
      runWithNoUserDefinitions("user0_1", user, true);
    }

    runWithNoUserDefinitions("user2_1", "user3_1", true);
    runWithNoUserDefinitions("user2_1", "user1_1", false);
    runWithNoUserDefinitions("user2_1", "user4_1", false);
    for (final String user : org2Users) {
      runWithNoUserDefinitions("user2_1", user, false);
    }

    runWithNoUserDefinitions("user3_2", "user4_2", true);
    runWithNoUserDefinitions("user3_2", "user1_2", true);
    runWithNoUserDefinitions("user3_2", "user2_2", true);
    runWithNoUserDefinitions("user3_2", "user0_2", false);
    runWithNoUserDefinitions("user3_2", "user5_2", false);
    for (final String user : org1Users) {
      runWithNoUserDefinitions("user3_2", user, false);
    }
  }

  private static void run(final String delegate, final String delegator,
                                               final boolean result) {
    assertEquals(new PrivilegeTest(delegate, delegator).run(), result);
  }

  @Test
  public void userAndGroupAuthz() {
    for (final String user : org1Users) {
      run("user0_1", user, true);
    }
    for (final String user : org2Users) {
      run("user0_1", user, true);
    }

    for (final String user : org1Users) {
      run("user1_1", user, false);
    }
    for (final String user : org2Users) {
      run("user1_1", user, false);
    }

    run("user2_1", "user3_1", true);
    for (final String user : org1Users)  {
      if (!user.equals("user3_1") && !user.equals("user2_1")) {
        run("user2_1", user, false);
      }
    }
    for (final String user : org2Users) {
      run("user2_1", user, false);
    }

    run("user4_1", "user1_1", true);
    run("user4_1", "user3_1", true);
    for (final String user : org1Users)  {
      if (!user.equals("user1_1") && !user.equals("user2_1") && !user.equals("user3_1")) {
        run("user2_1", user, false);
      }
    }
    for (final String user : org2Users) {
      run("user2_1", user, false);
    }

    for (final String user : org1Users) {
      run("user0_1", user, true);
    }
    for (final String user : org2Users) {
      run("user0_1", user, true);
    }

    run("user2_1", "user3_1", true);
    run("user2_1", "user1_1", false);
    run("user2_1", "user4_1", false);
    for (final String user : org2Users) {
      run("user2_1", user, false);
    }

    run("user3_2", "user4_2", true);
    run("user3_2", "user1_2", true);
    run("user3_2", "user2_2", true);
    run("user3_2", "user0_2", false);
    run("user3_2", "user5_2", false);
    for (final String user : org1Users) {
      run("user3_2", user, false);
    }
  }
}
