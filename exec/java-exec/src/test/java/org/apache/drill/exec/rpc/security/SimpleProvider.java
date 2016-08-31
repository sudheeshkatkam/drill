/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.rpc.security;

import java.security.Provider;

@SuppressWarnings("serial")
public class SimpleProvider extends Provider {

  public static final String NAME = "SimpleSasl";

  public static final String MECHANISM_NAME = "SIMPLE-SECURITY";

  public static final String NUM_EXCHANGES = "sasl.simple.exchanges";

  public SimpleProvider() {
    super(NAME, 1.0, "Simple SASL provider");
    put("SaslClientFactory." + MECHANISM_NAME, SimpleClient.SimpleClientFactory.class.getName());
    put("SaslServerFactory." + MECHANISM_NAME, SimpleServer.SimpleServerFactory.class.getName());
  }
}
