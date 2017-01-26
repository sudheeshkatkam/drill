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
package org.apache.drill.exec.rpc.security;

import io.netty.buffer.ByteBuf;
import org.apache.drill.exec.rpc.RequestHandler;
import org.apache.drill.exec.rpc.ResponseSender;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.rpc.ServerConnection;

public class FailingRequestHandler<C extends ServerConnection> implements RequestHandler<C> {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(FailingRequestHandler.class);

  @Override
  public void handle(C connection, int rpcType, ByteBuf pBody, ByteBuf dBody, ResponseSender sender)
      throws RpcException {

    // drop connection
    connection.close();

    // Remote should not be making any requests before authenticating.
    throw new RpcException(String.format("Request of type %d is not allowed without authentication. " +
                "Remote on %s must authenticate before making requests. Connection dropped.",
            rpcType, connection.getRemoteAddress()));
  }
}
