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
package org.apache.drill.exec.security;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

public interface LoginManager extends AutoCloseable {

  /**
   * Name of the service.
   *
   * @return service name
   */
  String getServiceName();

  /**
   * Hostname of the service.
   *
   * @return service hostname
   */
  String getServiceHostName();

  /**
   * Run the given action as the user.
   *
   * @param <T> the return type of the run method
   * @param action the method to execute
   * @return the value from the run method
   */
  <T> T doAsLoginUser(PrivilegedAction<T> action) throws IOException;

  /**
   * Run the given action as the user, potentially throwing an exception.
   *
   * @param <T> the return type of the run method
   * @param action the method to execute
   * @return the value from the run method
   * @throws IOException if the action throws an IOException
   * @throws Error if the action throws an Error
   * @throws RuntimeException if the action throws a RuntimeException
   * @throws InterruptedException if the action throws an InterruptedException
   * @throws UndeclaredThrowableException if the action throws something else
   */
  <T> T doAsLoginUser(PrivilegedExceptionAction<T> action) throws IOException, InterruptedException;

  /**
   * Get the translation of the principal name into an operating system
   * user name.
   *
   * @return the short name
   */
  String translateToLocalName(String name) throws IOException;

}
