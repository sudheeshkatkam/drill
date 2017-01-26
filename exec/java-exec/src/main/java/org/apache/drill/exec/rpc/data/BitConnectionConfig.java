/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.rpc.data;

import org.apache.drill.common.KerberosUtil;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.common.config.DrillProperties;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.proto.CoordinationProtos.DrillbitEndpoint;
import org.apache.drill.exec.rpc.AbstractConnectionConfig;
import org.apache.drill.exec.rpc.security.AuthStringUtil;
import org.apache.drill.exec.rpc.security.AuthenticatorFactory;
import org.apache.drill.exec.server.BootStrapContext;
import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public abstract class BitConnectionConfig extends AbstractConnectionConfig {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BitConnectionConfig.class);

  private final String authMechanismToUse;
  private final String clusterId;

  protected BitConnectionConfig(BufferAllocator allocator, BootStrapContext context) throws DrillbitStartupException {
    super(allocator, context);

    final DrillConfig config = context.getConfig();
    if (config.getBoolean(ExecConstants.BIT_AUTHENTICATION_ENABLED)) {
      this.authMechanismToUse = config.getString(ExecConstants.BIT_AUTHENTICATION_MECHANISM);
      try {
        getAuthProvider().getAuthenticatorFactory(authMechanismToUse);
      } catch (final SaslException e) {
        throw new DrillbitStartupException(String.format(
            "%s mechanism not found. Please check authentication configuration.", authMechanismToUse));
      }
      logger.info("Configured all connections to require authentication using: {}", authMechanismToUse);
      if (config.getBoolean(ExecConstants.USE_CLUSTER_ID_AS_KERBEROS_INSTANCE_NAME)) {
        final String serviceName = config.getString(ExecConstants.SERVICE_NAME);
        final String lowercaseName = serviceName.toLowerCase();
        if (!serviceName.equals(lowercaseName)) {
          logger.warn("Converting cluster name ({}) to lowercase to use as service name, see HADOOP-7988.",
              serviceName);
        }
        this.clusterId = lowercaseName;
      } else {
        this.clusterId = null;
      }
    } else {
      this.authMechanismToUse = null;
      this.clusterId = null;
    }
  }

  // returns null iff auth is disabled
  public String getAuthMechanismToUse() {
    return authMechanismToUse;
  }

  // convenience method
  public AuthenticatorFactory getAuthFactory(final List<String> remoteMechanisms) throws SaslException {
    if (authMechanismToUse == null) {
      throw new SaslException("Authentication is not enabled");
    }
    if (!AuthStringUtil.listContains(remoteMechanisms, authMechanismToUse)) {
      throw new SaslException(String.format("Remote does not support authentication using %s", authMechanismToUse));
    }
    return getAuthProvider().getAuthenticatorFactory(authMechanismToUse);
  }

  public Map<String, ?> getSaslClientProperties(final DrillbitEndpoint remoteEndpoint) throws IOException {
    final DrillProperties properties = DrillProperties.createEmpty();

    if (UserGroupInformation.getLoginUser().getAuthenticationMethod() ==
        UserGroupInformation.AuthenticationMethod.KERBEROS) {

      final UserGroupInformation loginUser = UserGroupInformation.getLoginUser();
      final HadoopKerberosName serviceName = new HadoopKerberosName(loginUser.getUserName());
      properties.setProperty(DrillProperties.SERVICE_PRINCIPAL,
          KerberosUtil.getPrincipalFromParts(serviceName.getShortName(),
              clusterId == null ? remoteEndpoint.getAddress() : clusterId,
              serviceName.getRealm()));
    }
    return properties.stringPropertiesAsMap();
  }
}
