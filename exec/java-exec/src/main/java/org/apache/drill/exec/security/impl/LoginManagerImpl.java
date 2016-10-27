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
package org.apache.drill.exec.security.impl;

import org.apache.drill.common.KerberosUtil;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.security.LoginManager;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

/**
 * {@link UserGroupInformation} based LoginManager.
 */
public class LoginManagerImpl implements LoginManager {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LoginManagerImpl.class);

  public static final String HOSTNAME_PATTERN = "_HOST";

  private static final String SERVICE_LOGIN_PREFIX = "drill.exec.security.auth";

  public static final String SERVICE_PRINCIPAL = SERVICE_LOGIN_PREFIX + ".principal";

  public static final String SERVICE_KEYTAB_LOCATION = SERVICE_LOGIN_PREFIX + ".keytab";

  public static final String KERBEROS_NAME_MAPPING = SERVICE_LOGIN_PREFIX + ".auth_to_local";

  private static final String KERBEROS_HADOOP_AUTHENTICATION =
      UserGroupInformation.AuthenticationMethod.KERBEROS.toString();

  private final String serviceName; // primary
  private final String serviceHostName; // instance

  public LoginManagerImpl(DrillConfig config) throws DrillbitStartupException {
    try {
      if (config.hasPath(SERVICE_PRINCIPAL)) {
        // providing a service principal => Kerberos mechanism
        final Configuration loginConf = new Configuration();
        loginConf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION, KERBEROS_HADOOP_AUTHENTICATION);

        // set optional user name mapping
        if (config.hasPath(KERBEROS_NAME_MAPPING)) {
          loginConf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTH_TO_LOCAL,
              config.getString(KERBEROS_NAME_MAPPING));
        }

        UserGroupInformation.setConfiguration(loginConf);

        // service principal canonicalization
        final String principal = config.getString(SERVICE_PRINCIPAL);
        final String parts[] = KerberosUtil.splitPrincipalIntoParts(principal);
        if (parts.length != 3) {
          throw new DrillbitStartupException(
              String.format("Invalid %s, Drill service principal must be of format: primary/instance@REALM",
                  SERVICE_PRINCIPAL));
        }
        parts[1] = canonicalizedInstanceName(parts[1]);

        final String canonicalizedPrincipal = KerberosUtil.getPrincipalFromParts(parts[0], parts[1], parts[2]);
        final String keytab = config.getString(SERVICE_KEYTAB_LOCATION);

        // login to KDC (AS)
        // Note that this call must happen before any call to UserGroupInformation#getLoginUser,
        // but there is no way to enforce the order (this static init. call and parameters from
        // DrillConfig are both required).
        UserGroupInformation.loginUserFromKeytab(canonicalizedPrincipal, keytab);

        serviceName = parts[0];
        serviceHostName = parts[1];
        logger.info("Logged in successfully as {}", canonicalizedPrincipal);
      } else {
        serviceName = UserGroupInformation.getLoginUser().getShortUserName(); // init
        serviceHostName = canonicalizedInstanceName(null);
      }
    } catch (final IOException e) {
      throw new DrillbitStartupException("Failed to login.", e);
    }
  }

  private static String canonicalizedInstanceName(String instanceName) throws IOException {
    if (instanceName == null || HOSTNAME_PATTERN.equalsIgnoreCase(instanceName)) {
      instanceName = InetAddress.getLocalHost().getCanonicalHostName();
    }

    final String lowercaseName = instanceName.toLowerCase();
    if (!instanceName.equals(lowercaseName)) {
      logger.warn("Converting service name ({}) to lowercase, see HADOOP-7988.", instanceName);
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
  public String translateToLocalName(final String name) throws IOException {
    // translate name based on the user name mapping (set in this constructor)
    return new HadoopKerberosName(name).getShortName();
  }

  @Override
  public void close() throws Exception {
    // no-op: ugi does not support logout
  }
}
