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

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.util.Map;

/**
 * Mechanism will be initialized once and used as a factory to authenticate clients.
 *
 * Custom authenticators:
 * + must implement one constructor that takes LoginManager and DrillConfig as parameters
 * + must be annotated with {@link SaslMechanism}
 * + may throw DrillbitStartupException in case of any misconfiguration
 *
 * Examples: PlainMechanism and KerberosMechanism.
 */
public interface AuthenticationMechanism extends AutoCloseable {

  /**
   * The caller is responsible for {@link SaslServer#dispose disposing} the returned SaslServer.
   * @param properties
   * @return
   * @throws SaslException
   */
  SaslServer createSaslServer(Map<String, ?> properties) throws SaslException;

}
