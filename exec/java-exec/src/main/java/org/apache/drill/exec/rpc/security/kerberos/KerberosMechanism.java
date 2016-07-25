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
package org.apache.drill.exec.rpc.security.kerberos;

import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.rpc.security.AuthenticationMechanism;
import org.apache.drill.exec.rpc.security.FastSaslServerFactory;
import org.apache.drill.exec.rpc.security.SaslMechanism;
import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;

@SaslMechanism(name = KerberosMechanism.SIMPLE_NAME)
public class KerberosMechanism implements AuthenticationMechanism {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KerberosMechanism.class);

  public static final String SIMPLE_NAME = "KERBEROS";

  private static final String MECHANISM_NAME = "GSSAPI";

  private final String serviceName; // server primary name
  private final String serviceHostname; // server instance name

  public KerberosMechanism(final String servicePrincipal) throws DrillbitStartupException {
    final HadoopKerberosName name = new HadoopKerberosName(servicePrincipal);
    logger.trace("Server principal name: {}", name);

    serviceName = name.getServiceName();
    serviceHostname = name.getHostName();
  }

  @Override
  public SaslServer createSaslServer(final Map<String, ?> properties) throws SaslException {
    try {
      final SaslServer saslServer = UserGroupInformation.getLoginUser() // gets service ugi
          .doAs(new PrivilegedExceptionAction<SaslServer>() {
            @Override
            public SaslServer run() throws Exception {
              return FastSaslServerFactory.getInstance()
                  .createSaslServer(MECHANISM_NAME, serviceName, serviceHostname, properties,
                      new KerberosServerCallbackHandler());
            }
          });
      logger.trace("GSSAPI SaslServer created.");
      return saslServer;
    } catch (final UndeclaredThrowableException e) {
      if (e.getCause() instanceof SaslException) {
        throw (SaslException) e.getCause();
      } else {
        throw new SaslException("Unexpected failure trying to authenticate using Kerberos", e.getCause());
      }
    } catch (final IOException | InterruptedException e) {
      throw new SaslException("Unexpected failure trying to authenticate using Kerberos", e);
    }
  }

  @Override
  public void close() throws Exception {
    // no-op
  }

  private static class KerberosServerCallbackHandler implements CallbackHandler {

    @Override
    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      for (final Callback callback : callbacks) {
        if (callback instanceof AuthorizeCallback) {
          final AuthorizeCallback authorizeCallback = AuthorizeCallback.class.cast(callback);
          if (!authorizeCallback.getAuthenticationID()
              .equals(authorizeCallback.getAuthorizationID())) {
            throw new SaslException("Drill expects authorization ID and authentication ID to match. " +
                "Use inbound impersonation feature so one entity can act on behalf of another.");
          } else {
            authorizeCallback.setAuthorized(true);
          }
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
    }
  }
}
