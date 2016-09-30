/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.rpc.user;

import com.google.common.base.Function;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterators;
import org.apache.drill.common.KerberosUtil;
import org.apache.drill.common.config.ConnectionParameters;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.UserGroupInformation;

import javax.annotation.Nullable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Set;

public final class UserAuthenticationUtil {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserAuthenticationUtil.class);

  private static final String PLAIN_MECHANISM = "PLAIN";

  private static final String DEFAULT_SERVICE_NAME = System.getProperty("service.name.primary", "drill");

  private static final String DEFAULT_REALM_NAME = System.getProperty("service.name.realm", "default");

  public enum ClientAuthenticationProvider {

    KERBEROS {
      @Override
      public UserGroupInformation login(final ConnectionParameters parameters) throws SaslException {
        final Configuration conf = new Configuration();
        conf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION,
            UserGroupInformation.AuthenticationMethod.KERBEROS.toString());
        UserGroupInformation.setConfiguration(conf);

        final String keytab = parameters.getParameter(ConnectionParameters.KEYTAB);
        try {
          final UserGroupInformation ugi;
          if (keytab != null) {
            ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(
                parameters.getParameter(ConnectionParameters.USER), keytab);
            logger.debug("Logged in using keytab.");
          } else {
            // includes Kerberos ticket login
            ugi = UserGroupInformation.getCurrentUser();
            logger.debug("Logged in using ticket.");
          }
          return ugi;
        } catch (final IOException e) {
          logger.debug("Login failed.", e);
          final Throwable cause = e.getCause();
          if (cause instanceof LoginException) {
            throw new SaslException("Failed to login.", cause);
          }
          throw new SaslException("Unexpected failure trying to login.", cause);
        }
      }

      @Override
      public SaslClient createSaslClient(final UserGroupInformation ugi,
                                         final ConnectionParameters parameters) throws SaslException {
        final String servicePrincipal = getServicePrincipal(parameters);

        final String parts[] = KerberosUtil.splitPrincipalIntoParts(servicePrincipal);
        final String serviceName = parts[0];
        final String serviceHostName = parts[1];
        // ignore parts[2]; GSSAPI gets the realm info from the ticket
        try {
          final SaslClient saslClient = ugi.doAs(new PrivilegedExceptionAction<SaslClient>() {

            @Override
            public SaslClient run() throws Exception {
              return Sasl.createSaslClient(new String[]{KerberosUtil.KERBEROS_SASL_NAME},
                  null /** authorization ID */, serviceName, serviceHostName,
                  null /** properties; default QOP is auth */, new CallbackHandler() {
                    @Override
                    public void handle(final Callback[] callbacks)
                        throws IOException, UnsupportedCallbackException {
                      throw new UnsupportedCallbackException(callbacks[0]);
                    }
                  });
            }
          });
          logger.debug("GSSAPI SaslClient created to authenticate to {} running on {}",
              serviceName, serviceHostName);
          return saslClient;
        } catch (final UndeclaredThrowableException e) {
          throw new SaslException(String.format("Unexpected failure trying to authenticate to %s using GSSAPI",
              serviceHostName), e.getCause());
        } catch (final IOException | InterruptedException e) {
          if (e instanceof SaslException) {
            throw (SaslException) e;
          }
          throw new SaslException(String.format("Unexpected failure trying to authenticate to %s using GSSAPI",
              serviceHostName), e);
        }
      }
    },

    PLAIN {
      @Override
      public UserGroupInformation login(final ConnectionParameters parameters) throws SaslException {
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
      public SaslClient createSaslClient(final UserGroupInformation ugi,
                                         final ConnectionParameters parameters) throws SaslException {
        final String userName = parameters.getParameter(ConnectionParameters.USER);
        final String password = parameters.getParameter(ConnectionParameters.PASSWORD);

        return Sasl.createSaslClient(new String[]{PLAIN_MECHANISM}, null /** authorization ID */,
            null, null, null /** properties; default QOP is auth */, new CallbackHandler() {
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
    };

    public abstract UserGroupInformation login(ConnectionParameters parameters) throws SaslException;

    public abstract SaslClient createSaslClient(UserGroupInformation ugi, ConnectionParameters parameters)
        throws SaslException;

  }

  public static ClientAuthenticationProvider getClientAuthenticationProvider(
      final ConnectionParameters parameters, final List<String> supportedAuthMechanisms) throws SaslException {
    // canonicalization
    final Set<String> supportedAuthMechanismSet = ImmutableSet.copyOf(
        Iterators.transform(supportedAuthMechanisms.iterator(), new Function<String, String>() {
          @Nullable
          @Override
          public String apply(@Nullable String input) {
            return input == null ? null : input.toUpperCase();
          }
        }));

    // first, check if a certain mechanism must be used
    String authMechanism = parameters.getParameter(ConnectionParameters.AUTH_MECHANISM);
    if (authMechanism != null) {
      authMechanism = authMechanism.toUpperCase();
      final ClientAuthenticationProvider authenticator;
      try {
        authenticator = Enum.valueOf(ClientAuthenticationProvider.class, authMechanism);
      } catch (final IllegalArgumentException e) {
        throw new SaslException(String.format("Unknown mechanism: %s", authMechanism));
      }

      if (!supportedAuthMechanismSet.contains(authMechanism)) {
        throw new SaslException(String.format("Server does not support authentication using: %s", authMechanism));
      }
      return authenticator;
    }

    // check if Kerberos is supported, and the service principal is provided
    if (supportedAuthMechanismSet.contains(KerberosUtil.KERBEROS_SIMPLE_NAME) &&
        parameters.getParameter(ConnectionParameters.SERVICE_PRINCIPAL) != null) {
      return ClientAuthenticationProvider.KERBEROS;
    }

    // check if username/password is supported, and username/password are provided
    if (supportedAuthMechanismSet.contains(PLAIN_MECHANISM) &&
        parameters.getParameter(ConnectionParameters.USER) != null &&
        !Strings.isNullOrEmpty(parameters.getParameter(ConnectionParameters.PASSWORD))) {
      return ClientAuthenticationProvider.PLAIN;
    }

    throw new SaslException(String.format("Server requires authentication using %s. Insufficient credentials?",
        supportedAuthMechanisms));
  }

  private static String getServicePrincipal(final ConnectionParameters parameters) throws SaslException {
    final String principal = parameters.getParameter(ConnectionParameters.SERVICE_PRINCIPAL);
    if (principal != null) {
      return principal;
    }

    final String serviceHostname = parameters.getParameter(ConnectionParameters.SERVICE_HOST);
    if (serviceHostname == null) {
      throw new SaslException("Unknown Drillbit hostname. Check connection parameters?");
    }

    final String serviceName = parameters.getParameter(ConnectionParameters.SERVICE_NAME);
    final String realm = parameters.getParameter(ConnectionParameters.REALM);
    return KerberosUtil.getPrincipalFromParts(
        serviceName == null ? DEFAULT_SERVICE_NAME : serviceName,
        serviceHostname.toLowerCase(), // see HADOOP-7988
        realm == null ? DEFAULT_REALM_NAME : realm
    );
  }

  // prevent instantiation
  private UserAuthenticationUtil() {
  }
}
