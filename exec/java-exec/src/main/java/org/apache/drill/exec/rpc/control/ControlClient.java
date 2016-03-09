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
package org.apache.drill.exec.rpc.control;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.socket.SocketChannel;
import io.netty.util.concurrent.GenericFutureListener;

import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.proto.BitControl.BitControlHandshake;
import org.apache.drill.exec.proto.BitControl.RpcType;
import org.apache.drill.exec.rpc.BasicClient;
import org.apache.drill.exec.rpc.OutOfMemoryHandler;
import org.apache.drill.exec.rpc.ProtobufLengthDecoder;
import org.apache.drill.exec.rpc.Response;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.server.BootStrapContext;

import com.google.protobuf.MessageLite;

public class ControlClient extends BasicClient<RpcType, ControlConnection, BitControlHandshake, BitControlHandshake> {
  // private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ControlClient.class);

  private final ControlConnectionManager.CloseHandlerCreator closeHandlerFactory;
  private final BufferAllocator allocator;

  public ControlClient(BufferAllocator allocator, BootStrapContext context,
                       ControlConnectionManager.CloseHandlerCreator closeHandlerFactory) {
    super(ControlRpcConfig.getMapping(context.getConfig(), context.getExecutor()),
        allocator.getAsByteBufAllocator(),
        context.getBitClientLoopGroup(),
        RpcType.HANDSHAKE,
        BitControlHandshake.class,
        BitControlHandshake.PARSER);
    this.closeHandlerFactory = closeHandlerFactory;
    this.allocator = context.getAllocator();
  }

  @SuppressWarnings("unchecked")
  @Override
  public ControlConnection initRemoteConnection(SocketChannel channel) {
    super.initRemoteConnection(channel);
    return new ControlConnection("control client", channel, this, allocator);
  }

  @Override
  protected GenericFutureListener<ChannelFuture> getCloseHandler(SocketChannel ch,
                                                                 ControlConnection clientConnection) {
    return closeHandlerFactory.getHandler(clientConnection, super.getCloseHandler(ch, clientConnection));
  }

  @Override
  public MessageLite getResponseDefaultInstance(int rpcType) throws RpcException {
    return DefaultInstanceHandler.getResponseDefaultInstance(rpcType);
  }

  @Override
  protected Response handle(ControlConnection connection, int rpcType, ByteBuf pBody, ByteBuf dBody)
      throws RpcException {
    throw new UnsupportedOperationException("ControlClient is unidirectional by design.");
  }

  @Override
  protected void validateHandshake(BitControlHandshake handshake) throws RpcException {
    if (handshake.getRpcVersion() != ControlRpcConfig.RPC_VERSION) {
      throw new RpcException(String.format("Invalid rpc version.  Expected %d, actual %d.",
          handshake.getRpcVersion(),
          ControlRpcConfig.RPC_VERSION));
    }
  }

  @Override
  protected void finalizeConnection(BitControlHandshake handshake, ControlConnection connection) {
    connection.setEndpoint(handshake.getEndpoint());
  }

  @Override
  public ProtobufLengthDecoder getDecoder(BufferAllocator allocator) {
    return new ControlProtobufLengthDecoder(allocator, OutOfMemoryHandler.DEFAULT_INSTANCE);
  }

}
