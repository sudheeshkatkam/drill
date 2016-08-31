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
package org.apache.drill.exec.rpc.security;

import com.google.common.collect.Lists;
import com.typesafe.config.ConfigValueFactory;
import org.apache.drill.BaseTestQuery;
import org.apache.drill.common.config.ConnectionParams;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.ExecConstants;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Properties;

public class TestSaslExchange extends BaseTestQuery {

  @BeforeClass
  public static void setup() {
    Security.addProvider(new SimpleProvider());
    FastSaslServerFactory.reload();

    final Properties props = cloneDefaultTestConfigProperties();
    final DrillConfig newConfig = new DrillConfig(DrillConfig.create(props)
        .withValue(ExecConstants.USER_AUTHENTICATION_ENABLED,
            ConfigValueFactory.fromAnyRef("true"))
        .withValue("drill.exec.security.user.auth.mechanisms",
            ConfigValueFactory.fromIterable(Lists.newArrayList(SimpleMechanism.MECHANISM_NAME))),
        false);

    final Properties connectionProps = new Properties();
    connectionProps.setProperty(ConnectionParams.PASSWORD, "anything works!");
    updateTestCluster(3, newConfig, connectionProps);
  }

  @AfterClass
  public static void destroy() {
    Security.removeProvider(SimpleProvider.NAME);
    FastSaslServerFactory.reload();
  }

  @Test
  public void success() {
  }

}
