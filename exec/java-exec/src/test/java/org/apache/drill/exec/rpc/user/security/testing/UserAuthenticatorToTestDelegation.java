package org.apache.drill.exec.rpc.user.security.testing;
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
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.rpc.user.security.UserAuthenticationException;
import org.apache.drill.exec.rpc.user.security.UserAuthenticator;
import org.apache.drill.exec.rpc.user.security.UserAuthenticatorTemplate;
import org.apache.drill.exec.util.ImpersonationUtil;

import java.io.IOException;

import static org.apache.drill.exec.delegation.TestUserDelegation.OWNER;
import static org.apache.drill.exec.delegation.TestUserDelegation.OWNER_PASSWORD;
import static org.apache.drill.exec.delegation.TestUserDelegation.DELEGATOR_NAME;
import static org.apache.drill.exec.delegation.TestUserDelegation.DELEGATOR_PASSWORD;
import static org.apache.drill.exec.delegation.TestUserDelegation.DELEGATE_NAME;
import static org.apache.drill.exec.delegation.TestUserDelegation.DELEGATE_PASSWORD;

/**
 * Used by {@link org.apache.drill.exec.delegation.TestUserDelegation}.
 *
 * Needs to be in this package.
 */
@UserAuthenticatorTemplate(type = UserAuthenticatorToTestDelegation.TYPE)
public class UserAuthenticatorToTestDelegation implements UserAuthenticator {
  public static final String TYPE = "delegationAuth";

  public static final String PROCESS_USER = ImpersonationUtil.getProcessUserName();
  public static final String PROCESS_USER_PASSWORD = "process";

  @Override
  public void setup(DrillConfig drillConfig) throws DrillbitStartupException {
    // Nothing to setup.
  }

  @Override
  public void authenticate(String user, String password) throws UserAuthenticationException {

    if ("anonymous".equals(user)) {
      // Allow user "anonymous" for test framework to work.
      return;
    }

    if (!(OWNER.equals(user) && OWNER_PASSWORD.equals(password)) &&
        !(DELEGATOR_NAME.equals(user) && DELEGATOR_PASSWORD.equals(password)) &&
        !(DELEGATE_NAME.equals(user) && DELEGATE_PASSWORD.equals(password)) &&
        !(PROCESS_USER.equals(user) && PROCESS_USER_PASSWORD.equals(password))) {
      throw new UserAuthenticationException();
    }
  }

  @Override
  public void close() throws IOException {
    // Nothing to cleanup.
  }
}
