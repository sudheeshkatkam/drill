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
package org.apache.drill.exec.util;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.drill.common.exceptions.UserException;
import org.apache.drill.exec.server.options.OptionValue;
import org.apache.drill.exec.server.options.TypeValidators;
import org.apache.hadoop.security.UserGroupInformation;

import java.util.List;
import java.util.Set;

/**
 * Utilities for user delegation purpose.
 */
public class UserDelegationUtil {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserDelegationUtil.class);

  // splitters used for delegation definitions (e.g. "a=b,c;d=e;f=g,h,i")
  private static final Splitter COMMA_SPLITTER = Splitter.on(',').trimResults().omitEmptyStrings();
  private static final Splitter SEMICOLON_SPLITTER = Splitter.on(';').trimResults().omitEmptyStrings();
  private static final Splitter EQUALS_SPLITTER = Splitter.on('=').trimResults().omitEmptyStrings();

  private static final String STAR = "*";

  public static class DelegationDefinitionsValidator extends TypeValidators.AdminOptionValidator {

    public DelegationDefinitionsValidator(String name, String def) {
      super(name, def);
    }

    @Override
    public void validate(OptionValue v) {
      super.validate(v);

      final Set<String> definitionsSet = Sets.newHashSet(SEMICOLON_SPLITTER.split(v.string_val));
      for (final String definitionString : definitionsSet) {
        final List<String> definition = Lists.newArrayList(EQUALS_SPLITTER.split(definitionString));
        checkOrThrow(definition.size() == 2, "cannot parse " + definitionString);
        checkOrThrow(!Strings.isNullOrEmpty(definition.get(0)), "null or empty delegate");

        final String delegators = definition.get(1);
        checkOrThrow(!Strings.isNullOrEmpty(delegators), "null or empty delegators");
        if (delegators.equals(STAR)) {
          continue;
        }

        final Set<String> delegatorsSet = Sets.newHashSet(COMMA_SPLITTER.split(delegators));
        for (final String delegator : delegatorsSet) {
          checkOrThrow(!Strings.isNullOrEmpty(delegator), "null or empty delegator");
          checkOrThrow(!delegator.equals(STAR), "specified users and wildcard");
          // no specific checks for existence of users or groups
        }
      }
    }

    private static void checkOrThrow(final boolean condition, final String message) {
      if (!condition) {
        throw UserException.validationError()
            .message("Invalid delegation definition (%s).", message)
            .build(logger);
      }
    }
  }

  /**
   * Given authorized delegate names, valid group delegation definitions and valid user delegation definitions,
   * check if the given delegate is authorized to delegate for the delegator.
   *
   * @param delegateName delegate name
   * @param delegatorName delegator name
   * @param delegates authorized delegates
   * @param userDefinitions valid user delegation definitions
   * @param groupDefinitions valid group delegation definitions
   * @return true iff delegate is authorized to delegate for the delegator
   */
  public static boolean hasDelegationPrivileges(final String delegateName, final String delegatorName,
                                                final String delegates, final String userDefinitions,
                                                final String groupDefinitions) {
    // check if the delegate is authorized
    final Set<String> delegatesSet = Sets.newHashSet(COMMA_SPLITTER.split(delegates));
    if (!delegatesSet.contains(delegateName)) {
      return false;
    }

    // check if the delegate is authorized to delegate for the user
    final Set<String> userDefinitionsSet = Sets.newHashSet(SEMICOLON_SPLITTER.split(userDefinitions));
    for (final String userDefinition : userDefinitionsSet) {
      final List<String> definition = Lists.newArrayList(EQUALS_SPLITTER.split(userDefinition));
      if (!delegateName.equals(definition.get(0))) {
        continue;
      }
      final String authorizedDelegators = definition.get(1);
      if (authorizedDelegators.equals(STAR)) {
        return true;
      }
      final Set<String> authorizedDelegatorsSet = Sets.newHashSet(COMMA_SPLITTER.split(authorizedDelegators));
      if (authorizedDelegatorsSet.contains(delegatorName)) {
        return true;
      }
    }

    final UserGroupInformation delegatorUgi = ImpersonationUtil.createProxyUgi(delegatorName);
    final String[] delegatorGroups = delegatorUgi.getGroupNames();
    if (delegatorGroups == null || delegatorGroups.length == 0) {
      return false;
    }

    // among the groups that the delegator belongs to, check if the delegate is authorized to delegate
    // for one of those groups
    final Set<String> groupDefinitionsSet = Sets.newHashSet(SEMICOLON_SPLITTER.split(groupDefinitions));
    for (final String groupDefinition : groupDefinitionsSet) {
      final List<String> definition = Lists.newArrayList(EQUALS_SPLITTER.split(groupDefinition));
      if (!delegateName.equals(definition.get(0))) {
        continue;
      }
      final String authorizedDelegatorGroups = definition.get(1);
      if (authorizedDelegatorGroups.equals(STAR)) {
        return true;
      }
      final Set<String> authorizedDelegatorGroupsSet =
          Sets.newHashSet(COMMA_SPLITTER.split(authorizedDelegatorGroups));
      for (final String delegatorGroup : delegatorGroups) {
        if (authorizedDelegatorGroupsSet.contains(delegatorGroup)) {
          return true;
        }
      }
    }
    return false;
  }

  // avoid instantiation
  private UserDelegationUtil() {
  }
}
