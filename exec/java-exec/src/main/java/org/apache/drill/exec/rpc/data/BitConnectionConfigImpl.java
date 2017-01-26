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
import org.apache.drill.exec.proto.CoordinationProtos;
import org.apache.drill.exec.rpc.BitConnectionConfig;
import org.apache.drill.exec.rpc.security.AuthenticatorProvider;
import org.apache.drill.exec.server.BootStrapContext;
import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.util.Map;

// package private
class BitConnectionConfigImpl implements BitConnectionConfig {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BitConnectionConfigImpl.class);

  private final BufferAllocator allocator;
  private final BootStrapContext context;
  private final DataServerRequestHandler handler;

  private final AuthenticatorProvider authProvider;
  private final String authMechanismToUse;
  private final String clusterId;

  BitConnectionConfigImpl(BufferAllocator allocator, BootStrapContext context, DataServerRequestHandler handler)
      throws DrillbitStartupException {
    this.allocator = allocator;
    this.context = context;
    this.handler = handler;

    final DrillConfig config = context.getConfig();
    if (config.getBoolean(ExecConstants.BIT_AUTHENTICATION_ENABLED)) {
      this.authProvider = context.getAuthProvider();
      this.authMechanismToUse = config.getString(ExecConstants.BIT_AUTHENTICATION_MECHANISM);
      try {
        authProvider.getAuthenticatorFactory(authMechanismToUse);
      } catch (IllegalArgumentException e) {
        throw new DrillbitStartupException(
            String.format("%s mechanism not found. Please check authentication configuration.", authMechanismToUse));
      }
      logger.info("Configured all data connections to require authentication using: {}", authMechanismToUse);
      this.clusterId = config.getBoolean(ExecConstants.USE_CLUSTER_ID_AS_KERBEROS_INSTANCE_NAME)
          ? config.getString(ExecConstants.SERVICE_NAME)
          : null;
    } else {
      this.authProvider = null;
      this.authMechanismToUse = null;
      this.clusterId = null;
    }
  }

  @Override
  public String getName() {
    return "data server";
  }

  @Override
  public BootStrapContext getBootstrapContext() {
    return context;
  }

  @Override
  public BufferAllocator getAllocator() {
    return allocator;
  }

  @Override
  public AuthenticatorProvider getAuthProvider() {
    return authProvider;
  }

  public String getAuthMechanismToUse() {
    return authMechanismToUse;
  }

  public DataServerRequestHandler getMessageHandler() {
    return handler;
  }

  public Map<String, ?> getSaslClientProperties(final CoordinationProtos.DrillbitEndpoint remoteEndpoint)
      throws IOException {
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
