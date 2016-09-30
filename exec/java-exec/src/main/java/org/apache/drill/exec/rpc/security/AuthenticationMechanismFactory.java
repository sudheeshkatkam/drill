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

import com.google.common.base.Function;
import com.google.common.base.Strings;
import com.google.common.collect.Iterators;
import com.google.common.collect.Sets;
import org.apache.drill.common.AutoCloseables;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.common.map.CaseInsensitiveMap;
import org.apache.drill.common.scanner.persistence.ScanResult;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.rpc.security.plain.PlainMechanism;
import org.apache.drill.exec.rpc.user.security.UserAuthenticator;
import org.apache.drill.exec.rpc.user.security.UserAuthenticatorFactory;
import org.apache.drill.exec.security.LoginManager;
import org.apache.drill.exec.server.BootStrapContext;

import javax.annotation.Nullable;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AuthenticationMechanismFactory implements AutoCloseable {
  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(AuthenticationMechanismFactory.class);

  public static final String AUTHENTICATION_MECHANISMS = "drill.exec.security.auth.mechanisms";

  // Mapping: SASL name -> mechanism
  // See AuthenticationMechanism#getMechanismName
  private final Map<String, AuthenticationMechanism> mechanisms = CaseInsensitiveMap.newHashMapWithExpectedSize(5);

  @SuppressWarnings("unchecked")
  public AuthenticationMechanismFactory(final DrillConfig config, final ScanResult scan,
                                        final LoginManager loginManager) throws DrillbitStartupException {
    if (!config.hasPath(AUTHENTICATION_MECHANISMS)) {
      return;
    }

    final List<String> configuredMechanisms = config.getStringList(AUTHENTICATION_MECHANISMS);
    logger.debug("Configuring authentication mechanisms: {}", configuredMechanisms);
    // transform all names to uppercase
    final Set<String> configuredMechanismsSet = Sets.newHashSet(Iterators.transform(configuredMechanisms.iterator(),
        new Function<String, String>() {
          @Nullable
          @Override
          public String apply(@Nullable String input) {
            return input == null ? null : input.toUpperCase();
          }
        }));

    // PLAIN mechanism need special handling due to UserAuthenticator
    if (configuredMechanismsSet.contains(PlainMechanism.MECHANISM_NAME)) {
      // instantiated here, but closed in PlainMechanism#close
      final UserAuthenticator userAuthenticator = UserAuthenticatorFactory.createAuthenticator(config, scan);
      final PlainMechanism mechanism = new PlainMechanism(userAuthenticator);
      mechanisms.put(mechanism.getMechanismName(), mechanism);
      configuredMechanismsSet.remove(PlainMechanism.MECHANISM_NAME);
      logger.trace("Plain mechanism enabled.");
    }

    // Then, load other mechanisms, if any
    if (!configuredMechanismsSet.isEmpty()) {
      final Collection<Class<? extends AuthenticationMechanism>> mechanismImpls =
          scan.getImplementations(AuthenticationMechanism.class);
      logger.debug("Found AuthenticationMechanism implementations: {}", mechanismImpls);

      for (Class<? extends AuthenticationMechanism> clazz : mechanismImpls) {
        final SaslMechanism annotation = clazz.getAnnotation(SaslMechanism.class);
        if (annotation == null) {
          logger.warn("{} doesn't have {} annotation. Skipping.", clazz.getCanonicalName(), SaslMechanism.class);
          continue;
        }

        final String annotatedName = annotation.name();
        if (Strings.isNullOrEmpty(annotatedName)) {
          logger.warn("Authentication mechanism {} does not have a proper {} annotation. Skipping.",
              clazz.getCanonicalName(), SaslMechanism.class);
          continue;
        }

        if (!configuredMechanismsSet.contains(annotatedName.toUpperCase())) {
          logger.debug("Authentication mechanism {} found, but it is not configured to be used. Skipping.",
              clazz.getCanonicalName());
          continue;
        }

        Constructor<? extends AuthenticationMechanism> validConstructor = null;
        for (final Constructor<?> c : clazz.getConstructors()) {
          final Class<?>[] params = c.getParameterTypes();
          if (params.length == 2 &&
              params[0] == LoginManager.class &&
              params[1] == DrillConfig.class) {
            validConstructor = (Constructor<? extends AuthenticationMechanism>) c; // unchecked
            break;
          }
        }

        if (validConstructor == null) {
          logger.warn("Skipping authentication mechanism class {}. It must implement at least one constructor " +
              "with signature [{}(LoginManager, DrillConfig)]", clazz.getCanonicalName(), clazz.getName());
          continue;
        }

        try {
          final AuthenticationMechanism instance = validConstructor.newInstance(loginManager, config);
          mechanisms.put(instance.getMechanismName(), instance);
          logger.trace("{} mechanism enabled.", annotatedName);
        } catch (IllegalArgumentException | IllegalAccessException |
            InstantiationException | InvocationTargetException e) {
          throw new DrillbitStartupException(
              String.format("Failed to create authentication mechanism of type '%s'",
                  clazz.getCanonicalName()), e);
        }
      }
    }

    if (mechanisms.size() == 0) {
      throw new DrillbitStartupException("Authentication enabled, but no mechanism was configured correctly. " +
          "Please check authentication configuration(s).");
    }
    logger.info("Configured authentication mechanisms: {}", configuredMechanisms);
  }

  @Deprecated // used for user clients <= 1.8
  public PlainMechanism getPlainMechanism() {
    return (PlainMechanism) mechanisms.get(PlainMechanism.MECHANISM_NAME);
  }

  public AuthenticationMechanism getMechanism(final String mechanismName) throws IllegalArgumentException {
    final AuthenticationMechanism mechanism = mechanisms.get(mechanismName);
    if (mechanism == null) {
      throw new IllegalArgumentException(String.format("Unknown mechanism: '%s' Configured mechanisms: %s",
          mechanismName, mechanisms.keySet()));
    }
    return mechanism;
  }

  public Set<String> getSupportedMechanisms() {
    return mechanisms.keySet();
  }

  @Override
  public void close() throws Exception {
    AutoCloseables.close(mechanisms.values());
    mechanisms.clear();
  }

}
