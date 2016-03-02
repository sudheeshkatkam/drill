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
package org.apache.drill.exec.rpc.user;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import org.apache.calcite.schema.SchemaPlus;
import org.apache.calcite.tools.ValidationException;
import org.apache.drill.common.exceptions.DrillRuntimeException;
import org.apache.drill.common.exceptions.UserException;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.planner.sql.SchemaUtilites;
import org.apache.drill.exec.proto.UserBitShared.UserCredentials;
import org.apache.drill.exec.proto.UserProtos.Property;
import org.apache.drill.exec.proto.UserProtos.UserProperties;
import org.apache.drill.exec.server.options.OptionManager;
import org.apache.drill.exec.server.options.SessionOptionManager;

import com.google.common.collect.Maps;
import org.apache.drill.exec.util.UserDelegationUtil;

public class UserSession {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserSession.class);

  public static final String SCHEMA = "schema";
  public static final String USER = "user";
  public static final String PASSWORD = "password";
  public static final String DELEGATOR = "delegator";

  // known property names in lower case
  private static final Set<String> knownProperties = ImmutableSet.of(SCHEMA, USER, PASSWORD, DELEGATOR);

  private boolean supportComplexTypes = false;
  private UserCredentials credentials;
  private Map<String, String> properties;
  private OptionManager sessionOptions;
  private boolean enableDelegation = false;
  private final AtomicInteger queryCount;

  /**
   * Implementations of this interface are allowed to increment queryCount.
   * {@link org.apache.drill.exec.work.user.UserWorker} should have a member that implements the interface.
   * No other core class should implement this interface. Test classes may implement (see ControlsInjectionUtil).
   */
  public static interface QueryCountIncrementer {
    public void increment(final UserSession session);
  }

  public static class Builder {
    UserSession userSession;

    public static Builder newBuilder() {
      return new Builder();
    }

    public Builder withCredentials(UserCredentials credentials) {
      userSession.credentials = credentials;
      return this;
    }

    public Builder withOptionManager(OptionManager systemOptions) {
      userSession.sessionOptions = new SessionOptionManager(systemOptions, userSession);
      return this;
    }

    public Builder withUserProperties(UserProperties properties) {
      userSession.properties = Maps.newHashMap();
      if (properties != null) {
        for (int i = 0; i < properties.getPropertiesCount(); i++) {
          final Property property = properties.getProperties(i);
          final String propertyName = property.getKey().toLowerCase();
          if (knownProperties.contains(propertyName)) {
            userSession.properties.put(propertyName, property.getValue());
          } else {
            logger.warn("Ignoring unknown property: {}", propertyName);
          }
        }
      }
      return this;
    }

    public Builder enableDelegation(boolean enableDelegation) {
      userSession.enableDelegation = enableDelegation;
      return this;
    }

    public Builder setSupportComplexTypes(boolean supportComplexTypes) {
      userSession.supportComplexTypes = supportComplexTypes;
      return this;
    }

    public UserSession build() {
      if (userSession.enableDelegation && userSession.properties.containsKey(DELEGATOR)) {
        userSession.replaceUserCredentials(userSession.properties.get(DELEGATOR));
      }
      UserSession session = userSession;
      userSession = null;
      return session;
    }

    Builder() {
      userSession = new UserSession();
    }
  }

  private UserSession() {
    queryCount = new AtomicInteger(0);
  }

  public boolean isSupportComplexTypes() {
    return supportComplexTypes;
  }

  public OptionManager getOptions() {
    return sessionOptions;
  }

  public UserCredentials getCredentials() {
    return credentials;
  }

  /**
   * Replace current user credentials with the given user's credentials, if authorized.
   *
   * @param delegatorName delegator name
   * @throws DrillRuntimeException if credentials cannot be replaced
   */
  public void replaceUserCredentials(final String delegatorName) {
    assert enableDelegation;
    final String delegateName = properties.get(USER);
    final boolean authorized;
    try {
      authorized = UserDelegationUtil.hasDelegationPrivileges(delegateName, delegatorName,
          sessionOptions.getOption(ExecConstants.DELEGATES_VALIDATOR),
          sessionOptions.getOption(ExecConstants.USER_DELEGATION_DEFINITIONS_VALIDATOR),
          sessionOptions.getOption(ExecConstants.GROUP_DELEGATION_DEFINITIONS_VALIDATOR));
    } catch (Exception e) {
      throw new DrillRuntimeException(String.format("Failure while checking for delegation privileges." +
          "\nDetails: %s", e.getMessage())); // invalid user names, etc.
    }
    if (!authorized) {
      throw UserException.permissionError()
          .message("Delegate '%s' is not authorized to delegate for '%s'.", delegateName, delegatorName)
          .build(logger);
    }
    // replace this session's user credentials
    credentials = UserCredentials.newBuilder()
        .setUserName(delegatorName)
        .build();
  }

  public String getDefaultSchemaName() {
    return getProp(SCHEMA);
  }

  public void incrementQueryCount(final QueryCountIncrementer incrementer) {
    assert incrementer != null;
    queryCount.incrementAndGet();
  }

  public int getQueryCount() {
    return queryCount.get();
  }

  /**
   * Update the schema path for the session.
   * @param newDefaultSchemaPath New default schema path to set. It could be relative to the current default schema or
   *                             absolute schema.
   * @param currentDefaultSchema Current default schema.
   * @throws ValidationException If the given default schema path is invalid in current schema tree.
   */
  public void setDefaultSchemaPath(String newDefaultSchemaPath, SchemaPlus currentDefaultSchema)
      throws ValidationException {
    final List<String> newDefaultPathAsList = Lists.newArrayList(newDefaultSchemaPath.split("\\."));
    SchemaPlus newDefault;

    // First try to find the given schema relative to the current default schema.
    newDefault = SchemaUtilites.findSchema(currentDefaultSchema, newDefaultPathAsList);

    if (newDefault == null) {
      // If we fail to find the schema relative to current default schema, consider the given new default schema path as
      // absolute schema path.
      newDefault = SchemaUtilites.findSchema(currentDefaultSchema, newDefaultPathAsList);
    }

    if (newDefault == null) {
      SchemaUtilites.throwSchemaNotFoundException(currentDefaultSchema, newDefaultSchemaPath);
    }

    setProp(SCHEMA, SchemaUtilites.getSchemaPath(newDefault));
  }

  /**
   * @return Get current default schema path.
   */
  public String getDefaultSchemaPath() {
    return getProp(SCHEMA);
  }

  /**
   * Get default schema from current default schema path and given schema tree.
   * @param rootSchema
   * @return A {@link org.apache.calcite.schema.SchemaPlus} object.
   */
  public SchemaPlus getDefaultSchema(SchemaPlus rootSchema) {
    final String defaultSchemaPath = getProp(SCHEMA);

    if (Strings.isNullOrEmpty(defaultSchemaPath)) {
      return null;
    }

    final SchemaPlus defaultSchema = SchemaUtilites.findSchema(rootSchema, defaultSchemaPath);

    if (defaultSchema == null) {
      // If the current schema resolves to null, return root schema as the current default schema.
      return defaultSchema;
    }

    return defaultSchema;
  }

  public boolean setSessionOption(String name, String value) {
    return true;
  }

  private String getProp(String key) {
    return properties.get(key) != null ? properties.get(key) : "";
  }

  private void setProp(String key, String value) {
    properties.put(key, value);
  }
}
