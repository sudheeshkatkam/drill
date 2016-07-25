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

import org.apache.drill.BaseTestQuery;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;

import static org.junit.Assert.assertTrue;

public class TestKerberosSaslAuthentication extends BaseTestQuery {
  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(TestKerberosSaslAuthentication.class);

  private static SimpleKdcServer kdc;
  private static KrbConfig clientConfig;
  private static File keytabDir;

  private static int kdcPort;
  private static File clientKeytab;
  private static File serverKeytab;

  private static boolean kdcStarted;

  @BeforeClass
  public static void setupKdc() throws Exception {
    kdc = new SimpleKdcServer();
    File target = new File(System.getProperty("user.dir"), "target");
    assertTrue(target.exists());

    File kdcDir = new File(target, TestKerberosSaslAuthentication.class.getSimpleName());
    if (kdcDir.exists()) {
      deleteRecursively(kdcDir);
    }
    kdcDir.mkdirs();
    kdc.setWorkDir(kdcDir);

    final String localhost = "localhost";
    final String realm = "realm";

    kdc.setKdcHost(localhost);
    kdcPort = 0;
    kdc.setAllowTcp(true);
    kdc.setAllowUdp(false);
    kdc.setKdcTcpPort(kdcPort);

    logger.info("Starting KDC server at {}:{}", localhost, kdcPort);

    kdc.init();
    kdc.start();
    kdcStarted = true;


    keytabDir = new File(target, TestKerberosSaslAuthentication.class.getSimpleName()
        + "_keytabs");
    if (keytabDir.exists()) {
      deleteRecursively(keytabDir);
    }
    keytabDir.mkdirs();
    setupServerUser(keytabDir);

    clientConfig = new KrbConfig();
    clientConfig.setString(KrbConfigKey.KDC_HOST, localhost);
    clientConfig.setInt(KrbConfigKey.KDC_TCP_PORT, kdcPort);
    clientConfig.setString(KrbConfigKey.DEFAULT_REALM, realm);

    // Kerby sets "java.security.krb5.conf" for us!
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
    // System.setProperty("sun.security.spnego.debug", "true");
    // System.setProperty("sun.security.krb5.debug", "true");
  }

  @AfterClass
  public static void stopKdc() throws Exception {
    if (kdcStarted) {
      logger.info("Stopping KDC on {}", kdcPort);
      kdc.stop();
    }
  }

  private static void setupServerUser(File keytabDir) throws KrbException {
    final String CLIENT_PRINCIPAL = "bah";
    final String SERVER_PRINCIPAL = "bah";
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

  public static void deleteRecursively(final File d) {
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

  public static void setupUser(SimpleKdcServer kdc, File keytab, String principal)
      throws KrbException {
    kdc.createPrincipal(principal);
    kdc.exportPrincipal(principal, keytab);
  }
}
