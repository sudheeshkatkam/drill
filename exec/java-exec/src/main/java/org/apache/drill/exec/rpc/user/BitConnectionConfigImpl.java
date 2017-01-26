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
package org.apache.drill.exec.rpc.user;

import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.rpc.RequestHandler;
import org.apache.drill.exec.rpc.BitConnectionConfig;
import org.apache.drill.exec.rpc.security.AuthenticatorProvider;
import org.apache.drill.exec.server.BootStrapContext;

// package private
class BitConnectionConfigImpl implements BitConnectionConfig {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BitConnectionConfigImpl.class);

  private final BufferAllocator allocator;
  private final BootStrapContext context;
  private final AuthenticatorProvider authProvider;
  private final InboundImpersonationManager impersonationManager;

  private final UserServerRequestHandler handler;

  BitConnectionConfigImpl(BufferAllocator allocator, BootStrapContext context,
                          UserServerRequestHandler handler)
      throws DrillbitStartupException {
    this.allocator = allocator;
    this.context = context;
    this.handler = handler;

    if (context.getConfig().getBoolean(ExecConstants.USER_AUTHENTICATION_ENABLED)) {
      authProvider = context.getAuthProvider();
      if (authProvider.getAllFactoryNames().size() == 0) {
        throw new DrillbitStartupException("Authentication enabled, but no mechanisms found. Please check " +
            "authentication configuration.");
      }
    } else {
      authProvider = null;
    }

    impersonationManager = !context.getConfig().getBoolean(ExecConstants.IMPERSONATION_ENABLED) ? null :
        new InboundImpersonationManager();
  }

  @Override
  public String getName() {
    return "user server";
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

  public InboundImpersonationManager getImpersonationManager() {
    return impersonationManager;
  }

  public RequestHandler<UserServer.BitToUserConnection> getMessageHandler() {
    return handler;
  }
}
