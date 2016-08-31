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
package org.apache.drill.common.config;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import org.apache.drill.exec.proto.UserProtos.Property;
import org.apache.drill.exec.proto.UserProtos.UserProperties;

import java.util.Properties;

public final class ConnectionParams {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConnectionParams.class);

  // PROPERTY KEYS
  // definitions should be in lowercase

  public static final String ZOOKEEPER_CONNECTION = "zk";

  public static final String DRILLBIT_CONNECTION = "drillbit";

  public static final String SCHEMA = "schema";

  public static final String USER = "user";

  public static final String PASSWORD = "password";

  public static final String IMPERSONATION_TARGET = "impersonation_target";

  public static final String AUTH_MECHANISM = "authentication_mechanism";

  public static final String SERVICE_PRINCIPAL = "principal";

  public static final String SERVICE_NAME = "service_name";

  public static final String SERVICE_HOST = "service_host";

  public static final String REALM = "realm";

  // SPECIAL PROPERTY VALUES RECOGNIZED EITHER BY SERVER OR CLIENT
  // definitions should be in lowercase

  public static final String LOCAL_ZOOKEEPER_VALUE = "local";

  // CONVENIENCE SETS OF PROPERTIES

  public static final ImmutableSet<String> ALLOWED_BY_CLIENT =
      ImmutableSet.of(ZOOKEEPER_CONNECTION, DRILLBIT_CONNECTION, SCHEMA, USER, PASSWORD, IMPERSONATION_TARGET,
          AUTH_MECHANISM, SERVICE_PRINCIPAL, SERVICE_NAME, SERVICE_HOST, REALM);

  public static final ImmutableSet<String> ACCEPTED_BY_SERVER =
      ImmutableSet.of(SCHEMA, USER /** deprecated */, PASSWORD /** deprecated */, IMPERSONATION_TARGET);

  private final Properties properties; // keys must be lower case

  private ConnectionParams(Properties properties) {
    this.properties = properties;
  }

  public String getParam(final String key) {
    return properties.getProperty(key.toLowerCase());
  }

  public String getParam(final String key, final String defaultValue) {
    return properties.getProperty(key.toLowerCase(), defaultValue);
  }

  public boolean setParam(final String key, final String value) {
    return properties.setProperty(key.toLowerCase(), value) == null;
  }

  public void merge(final ConnectionParams overrides) {
    for (final String key : overrides.properties.stringPropertyNames()) {
      properties.setProperty(key, overrides.properties.getProperty(key));
    }
  }

  public String getUserName() {
    final String name = properties.getProperty(USER);
    return Strings.isNullOrEmpty(name) ? "anonymous" : name;
  }

  /**
   * Serializes properties that are accepted by the server.
   *
   * @return the serialized properties
   */
  public UserProperties serializeForServer() {
    final UserProperties.Builder propsBuilder = UserProperties.newBuilder();
    for (final String key : properties.stringPropertyNames()) {
      if (ACCEPTED_BY_SERVER.contains(key)) {
        propsBuilder.addProperties(Property.newBuilder()
            .setKey(key)
            .setValue(properties.getProperty(key))
            .build());
      }
    }
    return propsBuilder.build();
  }

  /**
   * Deserializes the given properties into ConnectionParams, ignoring the ones not accepted by the server.
   *
   * @param userProperties serialized user properties
   * @return params
   */
  public static ConnectionParams createParamsFromProperties(final UserProperties userProperties) {
    final Properties canonicalizedProperties = new Properties();
    for (final Property property : userProperties.getPropertiesList()) {
      final String key = property.getKey().toLowerCase();
      if (ACCEPTED_BY_SERVER.contains(key)) {
        canonicalizedProperties.setProperty(key, property.getValue());
      } else {
        logger.warn("Server does not recognize property: {}", key);
      }
    }
    return new ConnectionParams(canonicalizedProperties);
  }

  /**
   * Returns a new instance of ConnectionParams from the given properties, ignoring the ones not allowed by the client.
   *
   * @param properties user properties
   * @return params
   */
  public static ConnectionParams createParamsFromProperties(final Properties properties) {
    final Properties canonicalizedProperties = new Properties();
    if (properties != null) {
      for (final String key : properties.stringPropertyNames()) {
        final String lowerCaseKey = key.toLowerCase();
        final String value = properties.getProperty(key);
        if (ALLOWED_BY_CLIENT.contains(lowerCaseKey)) {
          canonicalizedProperties.setProperty(lowerCaseKey, value);
        } else {
          logger.warn("Client does not recognize property: {}:{}", key, value);
        }
      }
    }
    return new ConnectionParams(canonicalizedProperties);
  }
}
