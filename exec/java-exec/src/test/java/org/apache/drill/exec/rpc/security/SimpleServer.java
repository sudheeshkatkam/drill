/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.rpc.security;

import com.google.common.primitives.Ints;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Map;

public class SimpleServer implements SaslServer {

  private boolean completed;
  private String authorizationId;
  private final int total;
  private int count = 0;

  SimpleServer(final int total) {
    this.total = total;
  }

  @Override
  public String getMechanismName() {
    return SimpleProvider.MECHANISM_NAME;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    if (completed) {
      throw new IllegalStateException("SimpleSasl authentication already completed");
    }
    if (response == null || response.length < 1) {
      throw new SaslException("Received challenge is empty when secret expected");
    }

    if (count == 0) { // first expect authorization ID
      //This SaslServer simply permits a client to authenticate according to whatever username
      //was supplied in client's response[]
      authorizationId = new String(response);
    } else { // then expect (count + 1)
      final int number = Ints.fromByteArray(response);
      if (number != count + 1) {
        throw new SaslException("SIMPLE authentication failed. " +
            "Expected: " + (count + 1) + " but received: " + number);
      }
    }

    count++;
    if (count >= total) {
      completed = true;
      return null; // last should be null
    } else {
      return Ints.toByteArray(count);
    }
  }

  @Override
  public boolean isComplete() {
    return completed;
  }

  @Override
  public String getAuthorizationID() {
    if (!completed) {
      throw new IllegalStateException("SIMPLE authentication not completed");
    }
    return authorizationId;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len)
      throws SaslException {
    if (!completed) {
      throw new IllegalStateException("SIMPLE authentication not completed");
    }
    // nothing to do
    return incoming;
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    if (!completed) {
      throw new IllegalStateException("SIMPLE authentication not completed");
    }
    // nothing to do
    return outgoing;
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if (!completed) {
      throw new IllegalStateException("SIMPLE authentication not completed");
    }
    // nothing to do
    return null;
  }

  @Override
  public void dispose() throws SaslException {
    authorizationId = null;
  }

  public static class SimpleServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(
        String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
      if (SimpleProvider.MECHANISM_NAME.equals(mechanism)) {
        final Integer total = (Integer) props.get(SimpleProvider.NUM_EXCHANGES);
        return new SimpleServer(total == null ? 0 : total);
      }
      return null;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[]{SimpleProvider.MECHANISM_NAME};
    }
  }

}