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
package org.apache.drill.exec.security;

import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

/**
 * {@link UserGroupInformation} based LoginManager that uses Krb5LoginModule with keytab.
 */
public class LoginManagerImpl implements LoginManager {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LoginManagerImpl.class);

  public static final String HOSTNAME_PATTERN = "_HOST";

  private static final String SERVICE_LOGIN_PREFIX = "drill.exec.security.auth";

  public static final String SERVICE_PRINCIPAL = SERVICE_LOGIN_PREFIX + ".principal";

  public static final String SERVICE_KEYTAB_LOCATION = SERVICE_LOGIN_PREFIX + ".keytab";

  public static final String HADOOP_AUTHENTICATION = SERVICE_LOGIN_PREFIX + ".mechanism";

  private static final String DEFAULT_HADOOP_AUTHENTICATION =
      UserGroupInformation.AuthenticationMethod.KERBEROS.toString();

  private static final String DEFAULT_SERVICE_NAME = System.getProperty("service.name", "drill");

  private final String serviceName; // primary
  private final String serviceHostName; // instance

  public LoginManagerImpl(DrillConfig config) throws DrillbitStartupException {
    try {
      if (config.hasPath(SERVICE_PRINCIPAL)) {
        // service principal canonicalization
        final String principal = config.getString(SERVICE_PRINCIPAL);
        final String parts[] = splitPrincipalIntoParts(principal);
        if (parts.length != 3) {
          throw new DrillbitStartupException(
              String.format("Invalid %s, Drill service principal must be of format: primary/instance@REALM",
                  SERVICE_PRINCIPAL));
        }

        if (HOSTNAME_PATTERN.equalsIgnoreCase(parts[1])) {
          parts[1] = getCanonicalHostName();
        }
        final String canonicalizedPrincipal = getPrincipalFromParts(parts[0], parts[1], parts[2]);

        final String keytab = getStringFromConfig(config, SERVICE_KEYTAB_LOCATION, "");

        // hadoop login configuration
        Configuration loginConf = new Configuration();
        final String hadoopAuthName = getStringFromConfig(config, HADOOP_AUTHENTICATION,
            DEFAULT_HADOOP_AUTHENTICATION);
        loginConf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION, hadoopAuthName);
        UserGroupInformation.setConfiguration(loginConf);

        // login to KDC (AS)
        // Note that this call must happen before any call to UserGroupInformation#getLoginUser,
        // but there is no way to enforce the order (this static init. call and parameters from
        // DrillConfig are both required).
        UserGroupInformation.loginUserFromKeytab(canonicalizedPrincipal, keytab);

        serviceName = parts[0];
        serviceHostName = parts[1];
        logger.info("Logged in successfully as {}", canonicalizedPrincipal);
      } else {
        serviceName = DEFAULT_SERVICE_NAME;
        serviceHostName = getCanonicalHostName();
      }
    } catch (final IOException e) {
      throw new DrillbitStartupException("Failed to login.", e);
    }
  }

  // primary/instance@REALM
  private static String[] splitPrincipalIntoParts(final String principal) {
    return principal.split("[/@]");
  }

  private static String getPrincipalFromParts(final String primary, final String instance, final String realm) {
    return primary + "/" + instance + "@" + realm;
  }

  private static String getStringFromConfig(final DrillConfig config, final String path,
                                            final String defaultValue) {
    if (config.hasPath(path)) {
      return config.getString(path);
    } else {
      return defaultValue;
    }
  }

  private static String getCanonicalHostName() throws IOException {
    final String name = InetAddress.getLocalHost().getCanonicalHostName();
    final String lowercaseName = name.toLowerCase();
    if (!name.equals(lowercaseName)) {
      logger.warn("Service host name must be lowercase (see HADOOP-7988). " +
          "You may ignore this message if Kerberos is not enabled.");
    }
    return lowercaseName;
  }

  @Override
  public String getServiceName() {
    return serviceName;
  }

  @Override
  public String getServiceHostName() {
    return serviceHostName;
  }

  @Override
  public <T> T doAsLoginUser(PrivilegedAction<T> action) throws IOException {
    return UserGroupInformation.getLoginUser()
        .doAs(action);
  }

  @Override
  public <T> T doAsLoginUser(PrivilegedExceptionAction<T> action) throws IOException, InterruptedException {
    return UserGroupInformation.getLoginUser()
        .doAs(action);
  }

  @Override
  public void close() throws Exception {
    // no-op: ugi does not support logout
  }
}
