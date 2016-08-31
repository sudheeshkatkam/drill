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
package org.apache.drill.exec.client;

import org.apache.drill.common.config.ConnectionParams;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.parquet.Strings;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedExceptionAction;

public final class AuthenticationUtil {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthenticationUtil.class);

  private static final String PLAIN_NAME = "PLAIN";

  private static final String KERBEROS_NAME = "GSSAPI";

  public static String getMechanismFromParams(final ConnectionParams params) {
    if (params.getParam(ConnectionParams.AUTH_MECHANISM) != null) {
      return params.getParam(ConnectionParams.AUTH_MECHANISM);
    }
    if (params.getParam(ConnectionParams.SERVICE_PRINCIPAL) != null ||
        (params.getParam(ConnectionParams.SERVICE_HOST) != null &&
            params.getParam(ConnectionParams.SERVICE_NAME) != null)) {
      return "KERBEROS";
    }
    if (!Strings.isNullOrEmpty(params.getParam(ConnectionParams.PASSWORD))) {
      return "PLAIN";
    }
    return null;
  }

  public static SaslClient getPlainSaslClient(final String userName, final String password) throws SaslException {
    return Sasl.createSaslClient(new String[]{PLAIN_NAME}, null /* authorizationID */, null, null, null,
        new CallbackHandler() {
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

  public static String deriveKerberosName(final ConnectionParams params) {
    final String principal = params.getParam(ConnectionParams.SERVICE_PRINCIPAL);
    if (principal != null) {
      return principal;
    }

    final StringBuilder principalBuilder = new StringBuilder();
    final String serviceNameProp = params.getParam(ConnectionParams.SERVICE_NAME);
    if (serviceNameProp != null) {
      principalBuilder.append(serviceNameProp);
    } else {
      principalBuilder.append(System.getProperty("drill.service.name", "drill"));
    }
    principalBuilder.append("/");

    final String serviceHostnameProp = params.getParam(ConnectionParams.SERVICE_HOST);
    if (serviceHostnameProp != null) {
      principalBuilder.append(serviceHostnameProp);
    } else {
      final String serviceHostnameDefault = System.getProperty("drill.service.hostname");
      if (serviceHostnameDefault != null) {
        principalBuilder.append(serviceHostnameDefault);
      } else {
        throw new IllegalArgumentException("Cannot derive Kerberos name of Drill service.");
      }
    }
    principalBuilder.append("@");

    final String realmProp = params.getParam(ConnectionParams.REALM);
    if (realmProp != null) {
      principalBuilder.append(realmProp);
    }
    return principalBuilder.toString();
  }

  // primary/instance@REALM
  public static String[] splitKerberosName(final String fullName) {
    return fullName.split("[/@]");
  }

  // bin/sqlline -u "jdbc:drill:drillbit=10.10.30.206;principal=mapr/CCDrillCluster@QA.LAB"
  public static SaslClient getKerberosSaslClient(final String serviceName, final String serviceHostname,
                                                 final ConnectionParams params) throws SaslException {
    final Configuration conf = new Configuration();
    conf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION, "KERBEROS");
    UserGroupInformation.setConfiguration(conf);
    try {
      final SaslClient saslClient = UserGroupInformation.getLoginUser() // gets user ugi
          .doAs(new PrivilegedExceptionAction<SaslClient>() {
            @Override
            public SaslClient run() throws Exception {
              return Sasl.createSaslClient(new String[]{KERBEROS_NAME}, null /** authorizationID */,
                  serviceName, serviceHostname, null /** properties */, null /** cbh */);
            }
          });
      logger.debug("Will try to login to {} running on {}", serviceName, serviceHostname);
      return saslClient;
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

  // prevent instantiation
  private AuthenticationUtil() {
  }
}
