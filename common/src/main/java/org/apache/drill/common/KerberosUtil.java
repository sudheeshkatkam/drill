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
package org.apache.drill.common;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

public final class KerberosUtil {
//  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KerberosUtil.class);

  public static final String KERBEROS_SASL_NAME = "GSSAPI";

  public static final String KERBEROS_SIMPLE_NAME = "KERBEROS";

  /**
   * Returns principal of format primary/instance@REALM.
   *
   * @param primary non-null primary component
   * @param instance non-null instance component
   * @param realm non-null realm component
   * @return principal of format primary/instance@REALM
   */
  public static String getPrincipalFromParts(final String primary, final String instance, final String realm) {
    return checkNotNull(primary) + "/" +
        checkNotNull(instance) + "@" +
        checkNotNull(realm);
  }

  /**
   * Expects principal of the format primary/instance@REALM.
   *
   * @param principal principal
   * @return components
   */
  public static String[] splitPrincipalIntoParts(final String principal) {
    final String[] components = principal.split("[/@]");
    checkState(components.length == 3);
    checkNotNull(components[0]);
    checkNotNull(components[1]);
    checkNotNull(components[2]);
    return components;
  }

  // prevent instantiation
  private KerberosUtil() {
  }
}
