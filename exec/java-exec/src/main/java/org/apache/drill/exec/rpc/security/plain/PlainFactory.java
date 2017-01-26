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
package org.apache.drill.exec.rpc.security.plain;

import org.apache.drill.common.config.DrillProperties;
import org.apache.drill.exec.rpc.security.AuthenticatorFactory;
import org.apache.drill.exec.rpc.security.FastSaslServerFactory;
import org.apache.drill.exec.rpc.security.FastSaslClientFactory;
import org.apache.drill.exec.rpc.user.security.UserAuthenticationException;
import org.apache.drill.exec.rpc.user.security.UserAuthenticator;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.security.Security;
import java.util.Map;

public class PlainFactory implements AuthenticatorFactory {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PlainFactory.class);

  public static final String SIMPLE_NAME = PlainServer.MECHANISM_NAME;

  static {
    Security.addProvider(new PlainServer.PlainServerProvider());
  }

  private final UserAuthenticator authenticator;

  public PlainFactory() {
    this.authenticator = null;
  }

  public PlainFactory(final UserAuthenticator authenticator) {
    this.authenticator = authenticator;
  }

  @Override
  public String getSimpleName() {
    return SIMPLE_NAME;
  }

  @Override
  public UserGroupInformation createAndLoginUser(Map<String, ?> properties) throws IOException {
    final Configuration conf = new Configuration();
    conf.set("hadoop.login", "simple");
    UserGroupInformation.setConfiguration(conf);
    try {
      return UserGroupInformation.getCurrentUser();
    } catch (final IOException e) {
      logger.debug("Login failed.", e);
      final Throwable cause = e.getCause();
      if (cause instanceof LoginException) {
        throw new SaslException("Failed to login.", cause);
      }
      throw new SaslException("Unexpected failure trying to login. ", cause);
    }
  }

  @Override
  public SaslServer createSaslServer(final UserGroupInformation ugi, final Map<String, ?> properties)
      throws SaslException {
    return FastSaslServerFactory.getInstance().createSaslServer(SIMPLE_NAME, null /** protocol */,
        null /** serverName */, properties, new PlainServerCallbackHandler());
  }

  @Override
  public SaslClient createSaslClient(final UserGroupInformation ugi, final Map<String, ?> properties)
      throws SaslException {
    final String userName = (String) properties.get(DrillProperties.USER);
    final String password = (String) properties.get(DrillProperties.PASSWORD);

    return FastSaslClientFactory.getInstance().createSaslClient(new String[]{SIMPLE_NAME},
        null /** authorization ID */, null, null, properties, new CallbackHandler() {
          @Override
          public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (final Callback callback : callbacks) {
              if (callback instanceof NameCallback) {
                NameCallback.class.cast(callback).setName(userName);
                continue;
              }
              if (callback instanceof PasswordCallback) {
                PasswordCallback.class.cast(callback).setPassword(password.toCharArray());
                continue;
              }
              throw new UnsupportedCallbackException(callback);
            }
          }
        });
  }

  @Override
  public void close() throws IOException {
    if (authenticator != null) {
      authenticator.close();
    }
  }

  private class PlainServerCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      NameCallback nameCallback = null;
      PasswordCallback passwordCallback = null;
      AuthorizeCallback authorizeCallback = null;
      for (final Callback callback : callbacks) {
        if (callback instanceof NameCallback) {
          nameCallback = NameCallback.class.cast(callback);
        } else if (callback instanceof PasswordCallback) {
          passwordCallback = PasswordCallback.class.cast(callback);
        } else if (callback instanceof AuthorizeCallback) {
          authorizeCallback = AuthorizeCallback.class.cast(callback);
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }

      if (nameCallback == null || passwordCallback == null || authorizeCallback == null) {
        throw new SaslException("Insufficient credentials.");
      }

      try {
        assert authenticator != null;
        authenticator.authenticate(nameCallback.getName(), new String(passwordCallback.getPassword()));
      } catch (UserAuthenticationException e) {
        throw new SaslException(e.getMessage());
      }

      if (!authorizeCallback.getAuthenticationID()
          .equals(authorizeCallback.getAuthorizationID())) {
        throw new SaslException("Drill expects authorization ID and authentication ID to match. " +
            "Use inbound impersonation feature so one entity can act on behalf of another.");
      } else {
        authorizeCallback.setAuthorized(true);
      }
    }
  }

  @Deprecated // used for clients < 1.10
  public UserAuthenticator getAuthenticator() {
    return authenticator;
  }
}
