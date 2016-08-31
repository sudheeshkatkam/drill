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
package org.apache.drill.exec.rpc.security.plain;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.IOException;
import java.security.Provider;
import java.util.Map;

/**
 * Plain SaslServer implementation. See https://tools.ietf.org/html/rfc4616
 */
public class PlainServer implements SaslServer {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PlainServer.class);

  public static class PlainServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName,
                                       final Map<String, ?> props, final CallbackHandler cbh)
        throws SaslException {
      return "PLAIN".equals(mechanism) ?
          props == null || "false".equals(props.get(Sasl.POLICY_NOPLAINTEXT)) ?
              new PlainServer(cbh) :
              null :
          null;
    }

    @Override
    public String[] getMechanismNames(final Map<String, ?> props) {
      return props == null || "false".equals(props.get(Sasl.POLICY_NOPLAINTEXT)) ?
          new String[]{"PLAIN"} :
          new String[0];
    }
  }

  @SuppressWarnings("serial")
  public static class PlainServerProvider extends Provider {

    public PlainServerProvider() {
      super("PlainServer", 1.0, "PLAIN SASL Server Provider");
      put("SaslServerFactory.PLAIN", PlainServerFactory.class.getName());
    }
  }

  private CallbackHandler cbh;
  private boolean completed = false;
  private String authorizationID;

  PlainServer(final CallbackHandler cbh) throws SaslException {
    if (cbh == null) {
      throw new SaslException("PLAIN: A callback handler must be specified");
    }
    this.cbh = cbh;
  }

  @Override
  public String getMechanismName() {
    return "PLAIN";
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    if (completed) {
      throw new IllegalStateException("PLAIN authentication already completed");
    }

    if (response == null) {
      throw new SaslException("Received null response");
    }

    final String payload;
    try {
      payload = new String(response, "UTF-8");
    } catch (final Exception e) {
      throw new SaslException("Received corrupt response", e);
    }

    // Separator defined in PlainClient is 0
    // three parts: [ authorizationID, authenticationID, password ]
    final String[] parts = payload.split("\u0000", 3);
    if (parts.length != 3) {
      throw new SaslException("Received corrupt response. Expected 3 parts, but received "
          + parts.length);
    }
    if (parts[0].isEmpty()) {
      parts[0] = parts[1]; // authorizationID = authenticationID
    }

    final NameCallback nc = new NameCallback("PLAIN authentication ID: ");
    nc.setName(parts[1]);
    final PasswordCallback pc = new PasswordCallback("PLAIN password: ", false);
    pc.setPassword(parts[2].toCharArray());

    final AuthorizeCallback ac = new AuthorizeCallback(parts[1], parts[0]);
    try {
      cbh.handle(new Callback[]{nc, pc, ac});
    } catch (final UnsupportedCallbackException | IOException e) {
      throw new SaslException("PLAIN authentication failed", e);
    }
    authorizationID = ac.getAuthorizedID();
    completed = true;

    return null;
  }

  @Override
  public boolean isComplete() {
    return completed;
  }

  @Override
  public String getAuthorizationID() {
    if (completed) {
      return authorizationID;
    }
    throw new IllegalStateException("PLAIN authentication not completed");
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if (completed) {
      return Sasl.QOP.equals(propName) ? "auth" : null;
    }
    throw new IllegalStateException("PLAIN authentication not completed");
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    if (completed) {
      throw new SaslException("PLAIN supports neither integrity nor privacy");
    } else {
      throw new IllegalStateException("PLAIN authentication not completed");
    }
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    if (completed) {
      throw new SaslException("PLAIN supports neither integrity nor privacy");
    } else {
      throw new IllegalStateException("PLAIN authentication not completed");
    }
  }

  @Override
  public void dispose() throws SaslException {
    cbh = null;
    authorizationID = null;
  }
}
