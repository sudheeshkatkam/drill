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
package org.apache.drill.exec.rpc.security;

import com.google.common.primitives.Ints;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.Map;

public class SimpleClient implements SaslClient {

  private boolean completed;
  private String currentId;
  private final int total;
  private int count = 0;

  public SimpleClient(final int total) {
    AccessControlContext context = AccessController.getContext();
    Subject subject = Subject.getSubject(context);
    if (subject != null && !subject.getPrincipals().isEmpty()) {
      // determine client principal from subject.
      final Principal clientPrincipal = subject.getPrincipals().iterator().next();
      currentId = clientPrincipal.getName();
    } else {
      // could not get for some reason
      currentId = "";
    }

    this.total = total;
  }

  @Override
  public String getMechanismName() {
    return SimpleProvider.MECHANISM_NAME;
  }

  @Override
  public boolean hasInitialResponse() {
    return true;
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    if (completed) {
      throw new IllegalStateException("SimpleSasl authentication already completed");
    }

    byte[] response;
    if (count == 0) {
      count++;
      if (count >= total) { // first expect authorization ID
        completed = true;
      }
      return currentId.getBytes();
    }

    final int number = Ints.fromByteArray(challenge);
    if (number != count) {
      throw new SaslException("SIMPLE authentication failed. Expected: " + count + " but received: " + number);
    }
    count++;

    if (count >= total) {
      response = null;
      completed = true;
    } else {
      response = Ints.toByteArray(count);
    }
    return response;
  }

  @Override
  public boolean isComplete() {
    return completed;
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
    currentId = null;
  }

  public static class SimpleClientFactory implements SaslClientFactory {

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[]{SimpleProvider.MECHANISM_NAME};
    }

    @Override
    public SaslClient createSaslClient(String[] mechanisms,
                                       String authorizationId, String protocol, String serverName,
                                       Map<String, ?> props, CallbackHandler cbh) throws SaslException {
      if (mechanisms != null) {
        for (String mechanism : mechanisms) {
          if (SimpleProvider.MECHANISM_NAME.equals(mechanism)) {
            return new SimpleClient(0);
          }
        }
      }
      return null;
    }
  }
}
