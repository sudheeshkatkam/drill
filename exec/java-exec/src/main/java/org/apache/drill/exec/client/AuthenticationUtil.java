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
package org.apache.drill.exec.client;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import org.apache.drill.common.config.ConnectionParameters;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.UserGroupInformation;

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

public final class AuthenticationUtil {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthenticationUtil.class);

  private static final String PLAIN_MECHANISM = "PLAIN";

  private static final String KERBEROS_MECHANISM = "GSSAPI";

  private static final String DEFAULT_SERVICE_NAME = System.getProperty("service.name", "drill");

  // mapping: simple name -> official SASL name (sent by server)
  private static final ImmutableMap<String, String> MECHANISM_MAPPING = ImmutableMap.<String, String>builder()
      .put("PLAIN", PLAIN_MECHANISM)
      .put("KERBEROS", KERBEROS_MECHANISM)
      .build();

  private static final String DEFAULT_HADOOP_AUTHENTICATION =
      UserGroupInformation.AuthenticationMethod.KERBEROS.toString();

  public static String getMechanismFromParameters(final ConnectionParameters parameters) {
    if (parameters.getParameter(ConnectionParameters.AUTH_MECHANISM) != null) {
      return MECHANISM_MAPPING.get(parameters.getParameter(ConnectionParameters.AUTH_MECHANISM)
          .toUpperCase());
    }

    if (parameters.getParameter(ConnectionParameters.SERVICE_PRINCIPAL) != null ||
        (parameters.getParameter(ConnectionParameters.SERVICE_HOST) != null &&
            parameters.getParameter(ConnectionParameters.SERVICE_NAME) != null)) {
      return KERBEROS_MECHANISM;
    }

    if (!Strings.isNullOrEmpty(parameters.getParameter(ConnectionParameters.PASSWORD))) {
      return PLAIN_MECHANISM;
    }
    return null;
  }

  public static UserGroupInformation login(final String mechanism, final ConnectionParameters parameters)
      throws SaslException {
    if (mechanism.equals(KERBEROS_MECHANISM)) {
      final Configuration conf = new Configuration();
      conf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION, DEFAULT_HADOOP_AUTHENTICATION);
      UserGroupInformation.setConfiguration(conf);
    }

    final String keytab = parameters.getParameter(ConnectionParameters.KEYTAB);
    try {
      final UserGroupInformation ugi;
      if (keytab != null) {
        ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(
            parameters.getParameter(ConnectionParameters.USER), keytab);
        logger.debug("Logged in using keytab.");
      } else {
        // includes Kerberos ticket login
        ugi = UserGroupInformation.getLoginUser();
        logger.debug("Logged in using ticket.");
      }
      return ugi;
    } catch (final IOException e) {
      logger.debug("Login failed.", e);
      if (e.getCause() instanceof LoginException) {
        throw new SaslException("Failed to login.", e.getCause());
      }
      throw new SaslException("Unexpected failure trying to login: " + e.getCause().getMessage());
    }
  }

  public static SaslClient createSaslClient(final UserGroupInformation ugi, final String mechanism,
                                            final ConnectionParameters parameters) throws SaslException {
    final String userName = parameters.getParameter(ConnectionParameters.USER);
    final String password = parameters.getParameter(ConnectionParameters.PASSWORD);

    final String servicePrincipal = getServicePrincipal(parameters);
    final String parts[] = splitPrincipalIntoParts(servicePrincipal); // ignore parts[2]
    final String serviceName = parts[0];
    final String serviceHostName = parts[1];
    try {
      final SaslClient saslClient = ugi.doAs(new PrivilegedExceptionAction<SaslClient>() {
        @Override
        public SaslClient run() throws Exception {
          return Sasl.createSaslClient(new String[]{mechanism}, null /** authorizationID */,
              serviceName, serviceHostName, null /** properties */, new CallbackHandler() {
                @Override
                public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                  for (final Callback callback : callbacks) {
                    if (callback instanceof NameCallback) { // used by PLAIN
                      NameCallback.class.cast(callback).setName(userName);
                      continue;
                    }
                    if (callback instanceof PasswordCallback) { // used by PLAIN
                      PasswordCallback.class.cast(callback).setPassword(password.toCharArray());
                      continue;
                    }
                    throw new UnsupportedCallbackException(callback);
                  }
                }
              });
        }
      });
      logger.debug("{} SaslClient created to authenticate to {} running on {}",
          mechanism, serviceName, serviceHostName);
      return saslClient;
    } catch (final UndeclaredThrowableException e) {
      if (e.getCause() instanceof SaslException) {
        throw (SaslException) e.getCause();
      } else {
        throw new SaslException(String.format("Unexpected failure trying to authenticate to %s using %s",
            serviceHostName, mechanism), e.getCause());
      }
    } catch (final IOException | InterruptedException e) {
      throw new SaslException(String.format("Unexpected failure trying to authenticate to %s using %s",
          serviceHostName, mechanism), e);
    }
  }

  private static String getServicePrincipal(final ConnectionParameters parameters) throws SaslException {
    final String principal = parameters.getParameter(ConnectionParameters.SERVICE_PRINCIPAL);
    if (principal != null) {
      return principal;
    }

    final StringBuilder principalBuilder = new StringBuilder();
    final String serviceName = parameters.getParameter(ConnectionParameters.SERVICE_NAME);
    if (serviceName == null) {
      principalBuilder.append(DEFAULT_SERVICE_NAME);
    } else {
      principalBuilder.append(serviceName);
    }
    principalBuilder.append("/");

    final String serviceHostname = parameters.getParameter(ConnectionParameters.SERVICE_HOST);
    if (serviceHostname == null) {
      throw new SaslException("Unknown Drillbit hostname. Check connection parameters?");
    }
    principalBuilder.append(serviceHostname);
    principalBuilder.append("@");

    final String realm = parameters.getParameter(ConnectionParameters.REALM);
    if (realm != null) {
      principalBuilder.append(realm);
    }
    return principalBuilder.toString();
  }

  // primary/instance@REALM
  private static String[] splitPrincipalIntoParts(final String principal) {
    return principal.split("[/@]");
  }

  // prevent instantiation
  private AuthenticationUtil() {
  }
}
