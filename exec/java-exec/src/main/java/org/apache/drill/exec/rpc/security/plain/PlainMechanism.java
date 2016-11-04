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
package org.apache.drill.exec.rpc.security.plain;

import org.apache.drill.exec.rpc.security.AuthenticationMechanism;
import org.apache.drill.exec.rpc.security.FastSaslServerFactory;
import org.apache.drill.exec.rpc.security.SaslMechanism;
import org.apache.drill.exec.rpc.user.security.UserAuthenticationException;
import org.apache.drill.exec.rpc.user.security.UserAuthenticator;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.security.Security;
import java.util.Map;

@SaslMechanism(name = PlainMechanism.MECHANISM_NAME)
public class PlainMechanism implements AuthenticationMechanism {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PlainMechanism.class);

  public static final String MECHANISM_NAME = PlainServer.MECHANISM_NAME;

  static {
    Security.addProvider(new PlainServer.PlainServerProvider());
  }

  private final UserAuthenticator authenticator;

  public PlainMechanism(final UserAuthenticator authenticator) {
    this.authenticator = authenticator;
  }

  @Override
  public SaslServer createSaslServer(Map<String, ?> properties) throws SaslException {
    return FastSaslServerFactory.getInstance().createSaslServer(MECHANISM_NAME, null /** protocol */ ,
        null /** serverName */, properties, new PlainServerCallbackHandler());
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

  @Override
  public void close() throws IOException {
    authenticator.close();
  }

  @Deprecated // used for clients <= 1.8
  public UserAuthenticator getAuthenticator() {
    return authenticator;
  }
}
