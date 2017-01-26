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
import org.apache.drill.exec.proto.CoordinationProtos.DrillbitEndpoint;
import org.apache.drill.exec.rpc.BasicClient;
import org.apache.drill.exec.rpc.security.AuthenticationOutcomeListener;
import org.apache.drill.exec.rpc.OutOfMemoryHandler;
import org.apache.drill.exec.rpc.ProtobufLengthDecoder;
import org.apache.drill.exec.rpc.ResponseSender;
import org.apache.drill.exec.rpc.RpcCommand;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.rpc.RpcOutcomeListener;
import org.apache.drill.exec.rpc.security.FailingRequestHandler;

import com.google.protobuf.MessageLite;
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;

public class ControlClient extends BasicClient<RpcType, ControlConnection, BitControlHandshake, BitControlHandshake>{

  // private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ControlClient.class);

  private final DrillbitEndpoint remoteEndpoint;
  private volatile ControlConnection connection;
  private final ControlConnectionManager.CloseHandlerCreator closeHandlerFactory;
  private final BitConnectionConfigImpl config;

  public ControlClient(BitConnectionConfigImpl config, DrillbitEndpoint remoteEndpoint,
                       ControlConnectionManager.CloseHandlerCreator closeHandlerFactory) {
    super(ControlRpcConfig.getMapping(config.getBootstrapContext().getConfig(),
        config.getBootstrapContext().getExecutor()),
        config.getAllocator().getAsByteBufAllocator(),
        config.getBootstrapContext().getBitLoopGroup(),
        RpcType.HANDSHAKE,
        BitControlHandshake.class,
        BitControlHandshake.PARSER);
    this.config = config;
    this.remoteEndpoint = remoteEndpoint;
    this.closeHandlerFactory = closeHandlerFactory;
  }

  @SuppressWarnings("unchecked")
  @Override
  public ControlConnection initRemoteConnection(SocketChannel channel) {
    super.initRemoteConnection(channel);
    connection = new ControlConnection(channel, "control client", config,
        config.getAuthProvider() == null
            ? config.getMessageHandler()
            : new FailingRequestHandler<ControlConnection>(),
        this);
    return connection;
  }

  @Override
  protected GenericFutureListener<ChannelFuture> getCloseHandler(SocketChannel ch, ControlConnection clientConnection) {
    return closeHandlerFactory.getHandler(clientConnection, super.getCloseHandler(ch, clientConnection));
  }

  @Override
  public MessageLite getResponseDefaultInstance(int rpcType) throws RpcException {
    return DefaultInstanceHandler.getResponseDefaultInstance(rpcType);
  }

  @Override
  protected void handle(ControlConnection connection, int rpcType, ByteBuf pBody, ByteBuf dBody,
                        ResponseSender sender) throws RpcException {
    connection.getCurrentHandler().handle(connection, rpcType, pBody, dBody, sender);
  }

  @Override
  protected void validateHandshake(BitControlHandshake handshake) throws RpcException {
    if (handshake.getRpcVersion() != ControlRpcConfig.RPC_VERSION) {
      throw new RpcException(String.format("Invalid rpc version.  Expected %d, actual %d.",
          handshake.getRpcVersion(), ControlRpcConfig.RPC_VERSION));
    }

    if (handshake.getAuthenticationMechanismsCount() != 0) { // remote requires authentication
      if (config.getAuthProvider() == null) {
        throw new RpcException(
            String.format("Drillbit running on %s requires authentication, but authentication is not configured.",
            remoteEndpoint.getAddress()));
      }
      if (!handshake.getAuthenticationMechanismsList().contains(config.getAuthMechanismToUse())) {
        throw new RpcException(String.format("Drillbit running on %s does not support %s",
            remoteEndpoint.getAddress(), config.getAuthMechanismToUse()));
      }

      final SaslClient saslClient;
      try {
        saslClient = config.getAuthProvider()
            .getAuthenticatorFactory(config.getAuthMechanismToUse())
            .createSaslClient(UserGroupInformation.getLoginUser(),
                config.getSaslClientProperties(remoteEndpoint));
      } catch (final IOException e) {
        throw new RpcException("Unexpected failure trying to login.", e);
      }
      if (saslClient == null) {
        throw new RpcException("Unexpected failure. Could not initiate authentication.");
      }
      connection.setSaslClient(saslClient);
    }
  }

  @Override
  protected void finalizeConnection(BitControlHandshake handshake, ControlConnection connection) {
    connection.setEndpoint(handshake.getEndpoint());
  }

  @Override
  protected <M extends MessageLite> RpcCommand<M, ControlConnection>
  getInitialCommand(final RpcCommand<M, ControlConnection> command) {
    if (config.getAuthProvider() == null) {
      return super.getInitialCommand(command);
    } else {
      return new AuthenticationCommand<>(command);
    }
  }

  private class AuthenticationCommand<M extends MessageLite> implements RpcCommand<M, ControlConnection> {

    private final RpcCommand<M, ControlConnection> command;

    public AuthenticationCommand(RpcCommand<M, ControlConnection> command) {
      this.command = command;
    }

    @Override
    public void connectionAvailable(ControlConnection connection) {
      command.connectionFailed(FailureType.AUTHENTICATION, new SaslException("Should not reach here."));
    }

    @Override
    public void connectionSucceeded(final ControlConnection connection) {
      try {
        new AuthenticationOutcomeListener<>(ControlClient.this, connection, RpcType.SASL_MESSAGE,
            UserGroupInformation.getLoginUser(),
            new RpcOutcomeListener<Void>() {
              @Override
              public void failed(RpcException ex) {
                command.connectionFailed(FailureType.AUTHENTICATION, ex);
              }

              @Override
              public void success(Void value, ByteBuf buffer) {
                connection.changeHandlerTo(config.getMessageHandler());
                command.connectionSucceeded(connection);
              }

              @Override
              public void interrupted(InterruptedException e) {
                command.connectionFailed(FailureType.AUTHENTICATION, e);
              }
            }).initiate(config.getAuthMechanismToUse());
      } catch (IOException e) {
        command.connectionFailed(FailureType.AUTHENTICATION, e);
      }
    }

    @Override
    public void connectionFailed(FailureType type, Throwable t) {
      command.connectionFailed(FailureType.AUTHENTICATION, t);
    }
  }

  @Override
  public ProtobufLengthDecoder getDecoder(BufferAllocator allocator) {
    return new ControlProtobufLengthDecoder(allocator, OutOfMemoryHandler.DEFAULT_INSTANCE);
  }

}
