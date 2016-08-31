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
package org.apache.drill.exec.rpc.user.security;

import com.google.common.collect.Lists;
import com.typesafe.config.ConfigValueFactory;
import org.apache.drill.BaseTestQuery;
import org.apache.drill.common.config.ConnectionParams;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.rpc.security.kerberos.KerberosMechanism;
import org.apache.drill.exec.rpc.security.plain.PlainMechanism;
import org.apache.drill.exec.rpc.user.security.testing.UserAuthenticatorTestImpl;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.Properties;

import static org.junit.Assert.assertTrue;

public class TestKerberosSaslAuthentication extends BaseTestQuery {
  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(TestKerberosSaslAuthentication.class);

  private static SimpleKdcServer kdc;
  private static KrbConfig clientConfig;
  private static File keytabDir;
  private static int kdcPort;

  private static final String HOSTNAME = "localhost";
  private static final String REALM = "realm";

  private static final String CLIENT_PRINCIPAL = "client@" + REALM;
  private static final String SERVER_PRINCIPAL = "drill/" + HOSTNAME + "@" + REALM;

  private static File clientKeytab;
  private static File serverKeytab;

  private static boolean kdcStarted;

  @BeforeClass
  public static void setupKdc() throws Exception {
    kdc = new SimpleKdcServer();
    final File target = new File(getTempDir("kerberos_target"));

    final File kdcDir = new File(target, TestKerberosSaslAuthentication.class.getSimpleName());
    if (kdcDir.exists()) {
      deleteRecursively(kdcDir);
    }
    kdcDir.mkdirs();
    kdc.setWorkDir(kdcDir);

    kdc.setKdcHost(HOSTNAME);
    kdcPort = getFreePort();
    kdc.setAllowTcp(true);
    kdc.setAllowUdp(false);
    kdc.setKdcTcpPort(kdcPort);

    logger.info("Starting KDC server at {}:{}", HOSTNAME, kdcPort);

    kdc.init();
    kdc.start();
    kdcStarted = true;


    keytabDir = new File(target, TestKerberosSaslAuthentication.class.getSimpleName()
        + "_keytabs");
    if (keytabDir.exists()) {
      deleteRecursively(keytabDir);
    }
    keytabDir.mkdirs();
    setupUsers(keytabDir);

    clientConfig = new KrbConfig();
    clientConfig.setString(KrbConfigKey.KDC_HOST, HOSTNAME);
    clientConfig.setInt(KrbConfigKey.KDC_TCP_PORT, kdcPort);
    clientConfig.setString(KrbConfigKey.DEFAULT_REALM, REALM);

    // Kerby sets "java.security.krb5.conf" for us!
    System.clearProperty("java.security.auth.login.config");
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
//    System.setProperty("sun.security.spnego.debug", "true");
//    System.setProperty("sun.security.krb5.debug", "true");

    // Create a new DrillConfig which has user authentication enabled and authenticator set to
    // UserAuthenticatorTestImpl.
    final Properties props = cloneDefaultTestConfigProperties();
    final DrillConfig newConfig = new DrillConfig(DrillConfig.create(props)
        .withValue(ExecConstants.USER_AUTHENTICATION_ENABLED,
            ConfigValueFactory.fromAnyRef("true"))
        .withValue(ExecConstants.USER_AUTHENTICATOR_IMPL,
            ConfigValueFactory.fromAnyRef(UserAuthenticatorTestImpl.TYPE))
        .withValue(KerberosMechanism.SERVER_PRINCIPAL,
            ConfigValueFactory.fromAnyRef(SERVER_PRINCIPAL))
        .withValue(KerberosMechanism.SERVER_KEYTAB_LOCATION,
            ConfigValueFactory.fromAnyRef(SERVER_PRINCIPAL))
        .withValue("drill.exec.security.user.auth.mechanisms",
            ConfigValueFactory.fromIterable(Lists.newArrayList(PlainMechanism.SIMPLE_NAME,
                KerberosMechanism.SIMPLE_NAME))),
        false);

    final Properties connectionProps = new Properties();
    connectionProps.setProperty(ConnectionParams.USER, "anonymous");
    connectionProps.setProperty(ConnectionParams.PASSWORD, "anything works!");
    updateTestCluster(1, newConfig, connectionProps);
  }

  private static void deleteRecursively(final File d) {
    if (d.isDirectory()) {
      for (final String name : d.list()) {
        final File child = new File(d, name);
        if (child.isFile()) {
          child.delete();
        } else {
          deleteRecursively(d);
        }
      }
    }
    d.delete();
  }

  private static int getFreePort() throws IOException {
    ServerSocket s = null;
    try {
      s = new ServerSocket(0);
      s.setReuseAddress(true);
      return s.getLocalPort();
    } finally {
      if (s != null) {
        s.close();
      }
    }
  }

  private static void setupUsers(File keytabDir) throws KrbException {
    // Create the client user
    String clientPrincipal = CLIENT_PRINCIPAL.substring(0, CLIENT_PRINCIPAL.indexOf('@'));
    clientKeytab = new File(keytabDir, clientPrincipal.replace('/', '_') + ".keytab");
    if (clientKeytab.exists()) {
      deleteRecursively(clientKeytab);
    }
    logger.info("Creating {} with keytab {}", clientPrincipal, clientKeytab);
    setupUser(kdc, clientKeytab, clientPrincipal);

    // Create the server user
    String serverPrincipal = SERVER_PRINCIPAL.substring(0, SERVER_PRINCIPAL.indexOf('@'));
    serverKeytab = new File(keytabDir, serverPrincipal.replace('/', '_') + ".keytab");
    if (serverKeytab.exists()) {
      deleteRecursively(serverKeytab);
    }
    logger.info("Creating {} with keytab {}", SERVER_PRINCIPAL, serverKeytab);
    setupUser(kdc, serverKeytab, SERVER_PRINCIPAL);
  }

  private static void setupUser(SimpleKdcServer kdc, File keytab, String principal)
      throws KrbException {
    kdc.createPrincipal(principal);
    kdc.exportPrincipal(principal, keytab);
  }

  @AfterClass
  public static void stopKdc() throws Exception {
    if (kdcStarted) {
      logger.info("Stopping KDC on {}", kdcPort);
      kdc.stop();
    }
  }

  @Test
  public void success() throws Exception {
    final Properties connectionProps = new Properties();
    connectionProps.setProperty(ConnectionParams.SERVICE_PRINCIPAL, SERVER_PRINCIPAL);
    updateClient(connectionProps);

    // Run few queries using the new client
    test("SHOW SCHEMAS");
    test("USE INFORMATION_SCHEMA");
    test("SHOW TABLES");
    test("SELECT * FROM INFORMATION_SCHEMA.`TABLES` WHERE TABLE_NAME LIKE 'COLUMNS'");
    test("SELECT * FROM cp.`region.json` LIMIT 5");
  }
}
