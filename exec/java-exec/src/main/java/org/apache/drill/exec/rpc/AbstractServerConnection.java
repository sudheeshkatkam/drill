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
package org.apache.drill.exec.rpc;

import io.netty.channel.socket.SocketChannel;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;

import javax.security.auth.login.LoginException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;

public abstract class AbstractServerConnection<C extends AbstractServerConnection>
    extends AbstractRemoteConnection
    implements ServerConnection<C> {

  private final BitConnectionConfig config;

  private RequestHandler<C> currentHandler;
  private SaslServer saslServer;

  public AbstractServerConnection(SocketChannel channel, String name, BitConnectionConfig config,
                                  RequestHandler<C> handler) {
    super(channel, name);
    this.config = config;
    this.currentHandler = handler;
  }

  public AbstractServerConnection(SocketChannel channel, BitConnectionConfig config,
                                  RequestHandler<C> handler) {
    this(channel, config.getName(), config, handler);
  }

  @Override
  public BufferAllocator getAllocator() {
    return config.getAllocator();
  }

  protected abstract Logger getLogger();

  @Override
  public void initSaslServer(String mechanismName) throws IllegalArgumentException, SaslException {
    assert saslServer == null && config.getAuthProvider() != null;
    try {
      this.saslServer = config.getAuthProvider()
          .getAuthenticatorFactory(mechanismName)
          .createSaslServer(UserGroupInformation.getLoginUser(), null
              /** properties; default QOP is auth */);
    } catch (final IOException e) {
      getLogger().debug("Login failed.", e);
      final Throwable cause = e.getCause();
      if (cause instanceof LoginException) {
        throw new SaslException("Failed to login.", cause);
      }
      throw new SaslException("Unexpected failure trying to login.", cause);
    }
    if (saslServer == null) {
      throw new SaslException("Server could not initiate authentication. Insufficient parameters?");
    }
  }

  @Override
  public SaslServer getSaslServer() {
    assert saslServer != null;
    return saslServer;
  }

  @Override
  public void finalizeSession() throws IOException {
    final String authorizationID = getSaslServer().getAuthorizationID();
    final String remoteShortName = new HadoopKerberosName(authorizationID).getShortName();
    final String localShortName = UserGroupInformation.getLoginUser().getShortUserName();
    if (!localShortName.equalsIgnoreCase(remoteShortName)) {
      throw new SaslException(String.format("'primary' of remote drillbit's service principal " +
          "does not match with this drillbit's. Expected: %s Actual: %s", localShortName, remoteShortName));
    }
    getLogger().debug("Authenticated data connection for {}", authorizationID);
  }

  @Override
  public RequestHandler<C> getCurrentHandler() {
    return currentHandler;
  }

  @Override
  public void changeHandlerTo(final RequestHandler<C> handler) {
    assert handler != null;
    this.currentHandler = handler;
  }

  @Override
  public void close() {
    try {
      if (saslServer != null) {
        saslServer.dispose();
        saslServer = null;
      }
    } catch (final SaslException e) {
      getLogger().warn("Unclean disposal.", e);
    }
    super.close();
  }
}
