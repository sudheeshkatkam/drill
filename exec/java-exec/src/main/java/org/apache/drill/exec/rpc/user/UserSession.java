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
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import org.apache.calcite.schema.SchemaPlus;
import org.apache.calcite.tools.ValidationException;
import org.apache.drill.common.config.ConnectionParameters;
import org.apache.drill.exec.planner.sql.SchemaUtilites;
import org.apache.drill.exec.proto.UserBitShared.UserCredentials;
import org.apache.drill.exec.proto.UserProtos.UserProperties;
import org.apache.drill.exec.server.options.OptionManager;
import org.apache.drill.exec.server.options.SessionOptionManager;

public class UserSession {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserSession.class);

  public static final String SCHEMA = "schema";
  public static final String USER = "user";
  public static final String PASSWORD = "password";
  public static final String IMPERSONATION_TARGET = "impersonation_target";

  // known property names in lower case
  private static final Set<String> knownProperties = ImmutableSet.of(SCHEMA, USER, PASSWORD, IMPERSONATION_TARGET);

  private boolean supportComplexTypes = false;
  private UserCredentials credentials;
  private ConnectionParameters params;
  private OptionManager sessionOptions;
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
      userSession.params = ConnectionParameters.createParamsFromProperties(properties);
      return this;
    }

    public Builder setSupportComplexTypes(boolean supportComplexTypes) {
      userSession.supportComplexTypes = supportComplexTypes;
      return this;
    }

    public UserSession build() {
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
   * Replace current user credentials with the given user's credentials. Meant to be called only by a
   * {@link InboundImpersonationManager impersonation manager}.
   *
   * @param impersonationManager impersonation manager making this call
   * @param newCredentials user credentials to change to
   */
  public void replaceUserCredentials(final InboundImpersonationManager impersonationManager,
                                     final UserCredentials newCredentials) {
    Preconditions.checkNotNull(impersonationManager, "User credentials can only be replaced by an" +
        " impersonation manager.");
    credentials = newCredentials;
  }

  public String getTargetUserName() {
    return params.getParameter(ConnectionParameters.IMPERSONATION_TARGET);
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

    params.setParameter(ConnectionParameters.SCHEMA, SchemaUtilites.getSchemaPath(newDefault));
  }

  /**
   * @return Get current default schema path.
   */
  public String getDefaultSchemaPath() {
    return params.getParameter(ConnectionParameters.SCHEMA, "");
  }

  /**
   * Get default schema from current default schema path and given schema tree.
   * @param rootSchema
   * @return A {@link org.apache.calcite.schema.SchemaPlus} object.
   */
  public SchemaPlus getDefaultSchema(SchemaPlus rootSchema) {
    final String defaultSchemaPath = getDefaultSchemaPath();

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

}
