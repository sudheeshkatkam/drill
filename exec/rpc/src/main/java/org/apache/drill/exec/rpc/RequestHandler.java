/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.rpc;

import io.netty.buffer.ByteBuf;

/**
 * Handlers should not maintain any internal state.
 *
 * @param <C>
 */
public interface RequestHandler<C extends ServerConnection> {

  /**
   * Handle request of given type (rpcType) with message (pBody) and optional data (dBody)
   * from the connection, and return the appropriate response. There may be side effects on
   * the connection object, but not on the parameters.
   *
   * @param connection remote connection
   * @param rpcType    rpc type
   * @param pBody      message
   * @param dBody      data, maybe null
   * @param sender     used to {@link ResponseSender#send send} the response
   * @return response to the request
   * @throws RpcException
   */
  void handle(C connection, int rpcType, ByteBuf pBody, ByteBuf dBody, ResponseSender sender)
      throws RpcException;

}
