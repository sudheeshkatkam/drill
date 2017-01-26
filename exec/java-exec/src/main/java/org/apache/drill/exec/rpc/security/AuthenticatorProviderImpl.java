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
import com.google.common.collect.Iterators;
import com.google.common.collect.Sets;
import org.apache.drill.common.AutoCloseables;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.common.map.CaseInsensitiveMap;
import org.apache.drill.common.scanner.persistence.ScanResult;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.rpc.security.plain.PlainFactory;
import org.apache.drill.exec.rpc.user.security.UserAuthenticator;
import org.apache.drill.exec.rpc.user.security.UserAuthenticatorFactory;

import javax.annotation.Nullable;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AuthenticatorProviderImpl implements AuthenticatorProvider {
  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(AuthenticatorProviderImpl.class);

  public static final String AUTHENTICATION_MECHANISMS = "drill.exec.security.auth.mechanisms";

  // Mapping: simple name -> authenticator factory
  private final Map<String, AuthenticatorFactory> authFactories = CaseInsensitiveMap.newHashMapWithExpectedSize(5);

  @SuppressWarnings("unchecked")
  public AuthenticatorProviderImpl(final DrillConfig config, final ScanResult scan) throws DrillbitStartupException {
    if (!config.hasPath(ExecConstants.AUTHENTICATION_MECHANISMS)) {
      return;
    }

    final List<String> configuredFactories = config.getStringList(ExecConstants.AUTHENTICATION_MECHANISMS);
    logger.debug("Configuring authenticator factories: {}", configuredFactories);
    // transform all names to uppercase
    final Set<String> configuredFactoriesSet = Sets.newHashSet(Iterators.transform(configuredFactories.iterator(),
        new Function<String, String>() {
          @Nullable
          @Override
          public String apply(@Nullable String input) {
            return input == null ? null : input.toUpperCase();
          }
        }));

    // PLAIN mechanism need special handling due to UserAuthenticator
    if (configuredFactoriesSet.remove(PlainFactory.SIMPLE_NAME)) {
      // instantiated here, but closed in PlainFactory#close
      final UserAuthenticator userAuthenticator = UserAuthenticatorFactory.createAuthenticator(config, scan);
      final PlainFactory factory = new PlainFactory(userAuthenticator);
      authFactories.put(PlainFactory.SIMPLE_NAME, factory);
      logger.trace("Plain mechanism enabled.");
    }

    // Then, load other authentication factories, if any
    if (!configuredFactoriesSet.isEmpty()) {
      final Collection<Class<? extends AuthenticatorFactory>> factoryImpls =
          scan.getImplementations(AuthenticatorFactory.class);
      logger.debug("Found AuthenticatorFactory implementations: {}", factoryImpls);

      for (final Class<? extends AuthenticatorFactory> clazz : factoryImpls) {
        Constructor<? extends AuthenticatorFactory> validConstructor = null;
        for (final Constructor<?> c : clazz.getConstructors()) {
          final Class<?>[] params = c.getParameterTypes();
          if (params.length == 0) {
            validConstructor = (Constructor<? extends AuthenticatorFactory>) c; // unchecked
            break;
          }
        }

        if (validConstructor == null) {
          logger.warn("Skipping authentication factory class {}. It must implement at least one constructor " +
              "with signature [{}()]", clazz.getCanonicalName(), clazz.getName());
          continue;
        }

        try {
          final AuthenticatorFactory instance = validConstructor.newInstance();
          if (configuredFactoriesSet.remove(instance.getSimpleName().toUpperCase())) {
            authFactories.put(instance.getSimpleName(), instance);
          }
        } catch (IllegalArgumentException | IllegalAccessException |
            InstantiationException | InvocationTargetException e) {
          throw new DrillbitStartupException(
              String.format("Failed to create authentication factory of type '%s'",
                  clazz.getCanonicalName()), e);
        }
      }
    }

    if (authFactories.size() == 0) {
      throw new DrillbitStartupException("Authentication enabled, but no mechanism was configured correctly. " +
          "Please check authentication configuration.");
    }
    logger.info("Configured authentication mechanisms: {}", authFactories.keySet());
  }

  @Override
  @Deprecated
  public PlainFactory getPlainFactory() {
    return (PlainFactory) authFactories.get(PlainFactory.SIMPLE_NAME);
  }

  @Override
  public AuthenticatorFactory getAuthenticatorFactory(final String name) throws IllegalArgumentException {
    final AuthenticatorFactory mechanism = authFactories.get(name);
    if (mechanism == null) {
      throw new IllegalArgumentException(String.format("Unknown mechanism: '%s' Configured mechanisms: %s",
          name, authFactories.keySet()));
    }
    return mechanism;
  }

  @Override
  public Set<String> getAllFactoryNames() {
    return authFactories.keySet();
  }

  @Override
  public boolean containsFactory(final String name) {
    return authFactories.containsKey(name);
  }

  @Override
  public void close() throws Exception {
    AutoCloseables.close(authFactories.values());
    authFactories.clear();
  }

}
