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
package org.apache.drill.exec.server.options;

import org.apache.drill.common.exceptions.UserException;

import java.util.Map;

/**
 * {@link OptionManager} that hold options in memory rather than in a persistent store. Option stored in
 * {@link SessionOptionManager}, {@link QueryOptionManager}, and {@link FragmentOptionManager} are held in memory
 * (see {@link #options}) whereas {@link SystemOptionManager} stores options in a persistent store.
 */
public abstract class InMemoryOptionManager extends FallbackOptionManager {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InMemoryOptionManager.class);

  protected final Map<String, OptionValue> options;

  InMemoryOptionManager(final OptionManager fallback, final Map<String, OptionValue> options) {
    super(fallback);
    this.options = options;
  }

  @Override
  public void deleteOption(final String name, final OptionValue.OptionType type) {
    throw UserException.unsupportedError()
      .message("This manager does not support deleting an option.")
      .build(logger);
  }

  @Override
  public void deleteAllOptions(final OptionValue.OptionType type) {
    throw UserException.unsupportedError()
      .message("This manager does not support deleting options.")
      .build(logger);
  }

  @Override
  OptionValue getLocalOption(final String name) {
    return options.get(name);
  }

  @Override
  boolean setLocalOption(final OptionValue value) {
    if (supportsOption(value)) {
      options.put(value.name, value);
      return true;
    } else {
      return false;
    }
  }

  @Override
  Iterable<OptionValue> getLocalOptions() {
    return options.values();
  }

  /**
   * Check to see if implementations of this manager support the given option value (e.g. check for option type).
   *
   * @param value the option value
   * @return true iff the option value is supported
   */
  abstract boolean supportsOption(OptionValue value);

}
