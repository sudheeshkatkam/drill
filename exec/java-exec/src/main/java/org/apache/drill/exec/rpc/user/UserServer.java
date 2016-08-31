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

import com.google.common.collect.ImmutableSet;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.SocketChannel;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.Map;
import java.util.UUID;

import org.apache.drill.common.config.ConnectionParams;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.physical.impl.materialize.QueryWritableBatch;
import org.apache.drill.exec.proto.GeneralRPCProtos.Ack;
import org.apache.drill.exec.proto.GeneralRPCProtos.RpcMode;
import org.apache.drill.exec.proto.UserBitShared.QueryResult;
import org.apache.drill.exec.proto.UserBitShared.UserCredentials;
import org.apache.drill.exec.proto.UserProtos.BitToUserHandshake;
import org.apache.drill.exec.proto.UserProtos.HandshakeStatus;
import org.apache.drill.exec.proto.UserProtos.Property;
import org.apache.drill.exec.proto.UserProtos.RpcType;
import org.apache.drill.exec.proto.UserProtos.UserProperties;
import org.apache.drill.exec.proto.UserProtos.UserToBitHandshake;
import org.apache.drill.exec.rpc.BasicServer;
import org.apache.drill.exec.rpc.OutOfMemoryHandler;
import org.apache.drill.exec.rpc.OutboundRpcMessage;
import org.apache.drill.exec.rpc.ProtobufLengthDecoder;
import org.apache.drill.exec.rpc.RemoteConnection;
import org.apache.drill.exec.rpc.ResponseSender;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.rpc.RpcOutcomeListener;
import org.apache.drill.exec.rpc.user.UserServer.UserClientConnectionImpl;
import org.apache.drill.exec.rpc.RequestHandler;
import org.apache.drill.exec.rpc.security.AuthenticationMechanismFactory;
import org.apache.drill.exec.rpc.security.plain.PlainMechanism;
import org.apache.drill.exec.rpc.user.security.UserAuthenticationException;
import org.apache.drill.exec.server.BootStrapContext;
import org.apache.drill.exec.work.user.UserWorker;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import com.google.protobuf.MessageLite;
import org.apache.hadoop.security.UserGroupInformation;

public class UserServer extends BasicServer<RpcType, UserClientConnectionImpl> {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserServer.class);

  private static final ImmutableSet<Integer> SUPPORTED_RPC_VERSIONS = ImmutableSet.of(5, 6);

  // for backward compatibility (<= 1.8) during authentication
  private static final int NON_SASL_RPC_VERSION_SUPPORTED = 5;

  final UserWorker worker;
  final BufferAllocator alloc;
  final AuthenticationMechanismFactory authFactory; // null iff user auth is disabled
  final InboundImpersonationManager impersonationManager;
  final UserServerRequestHandler handler;

  public UserServer(BootStrapContext context, BufferAllocator alloc, EventLoopGroup eventLoopGroup,
                    UserWorker worker) throws DrillbitStartupException {
    super(UserRpcConfig.getMapping(context.getConfig(), context.getExecutor()),
        alloc.getAsByteBufAllocator(),
        eventLoopGroup);
    this.worker = worker;
    this.alloc = alloc;
    // TODO: move this up
    final DrillConfig config = context.getConfig();
    authFactory = !config.getBoolean(ExecConstants.USER_AUTHENTICATION_ENABLED) ? null :
        new AuthenticationMechanismFactory(context.getClasspathScan(), config,
            config.getStringList("drill.exec.security.user.auth.mechanisms"));
    impersonationManager = !config.getBoolean(ExecConstants.IMPERSONATION_ENABLED) ? null :
        new InboundImpersonationManager();
    handler = new UserServerRequestHandler(worker);
  }

  @Override
  protected MessageLite getResponseDefaultInstance(int rpcType) throws RpcException {
    // a user server only expects acknowledgments on messages it creates.
    switch (rpcType) {
    case RpcType.ACK_VALUE:
      return Ack.getDefaultInstance();
    default:
      throw new UnsupportedOperationException();
    }
  }

  @Override
  protected void handle(UserClientConnectionImpl connection, int rpcType, ByteBuf pBody, ByteBuf dBody,
      ResponseSender responseSender) throws RpcException {
    connection.currentHandler.handle(connection, rpcType, pBody, dBody, responseSender);
  }

  /**
   * Interface for getting user session properties and interacting with user connection. Separating this interface from
   * {@link RemoteConnection} implementation for user connection:
   * <p><ul>
   *   <li> Connection is passed to Foreman and Screen operators. Instead passing this interface exposes few details.
   *   <li> Makes it easy to have wrappers around user connection which can be helpful to tap the messages and data
   *        going to the actual client.
   * </ul>
   */
  public interface UserClientConnection {
    /**
     * @return User session object.
     */
    UserSession getSession();

    /**
     * Send query result outcome to client. Outcome is returned through <code>listener</code>
     * @param listener
     * @param result
     */
    void sendResult(RpcOutcomeListener<Ack> listener, QueryResult result);

    /**
     * Send query data to client. Outcome is returned through <code>listener</code>
     * @param listener
     * @param result
     */
    void sendData(RpcOutcomeListener<Ack> listener, QueryWritableBatch result);

    /**
     * Returns the {@link ChannelFuture} which will be notified when this
     * channel is closed.  This method always returns the same future instance.
     */
    ChannelFuture getChannelClosureFuture();

    /**
     * @return Return the client node address.
     */
    SocketAddress getRemoteAddress();
  }

  /**
   * {@link RemoteConnection} implementation for user connection. Also implements {@link UserClientConnection}.
   */
  public class UserClientConnectionImpl extends RemoteConnection implements UserClientConnection {

    private UserSession session;
    private SaslServer saslServer;
    private RequestHandler<UserClientConnectionImpl> currentHandler;
    private UserToBitHandshake inbound;

    public UserClientConnectionImpl(SocketChannel channel) {
      super(channel, "user client");
      currentHandler = authFactory == null ? handler : new UserServerAuthenticationHandler(handler);
    }

    void disableReadTimeout() {
      getChannel().pipeline().remove(BasicServer.TIMEOUT_HANDLER);
    }

    void setHandshake(final UserToBitHandshake inbound) {
      this.inbound = inbound;
    }

    void initSaslServer(final String mechanismName, final Map<String, ?> properties)
        throws IllegalStateException, IllegalArgumentException, SaslException {
      if (saslServer != null) {
        throw new IllegalStateException("SASL server already initialized.");
      }

      this.saslServer = authFactory.getMechanism(mechanismName)
          .createSaslServer(properties);
      if (saslServer == null) {
        throw new SaslException("Server could not initiate authentication. Insufficient parameters?");
      }
    }

    SaslServer getSaslServer() {
      return saslServer;
    }

    void finalizeSession() {
      // Since user authentication completed at this point, assume authMethod is SIMPLE
      // because for now, the authMethod is not needed in the future
      final String userName = UserGroupInformation
          .createRemoteUser(saslServer.getAuthorizationID() /**, AuthMethod.SIMPLE */)
          .getShortUserName();
      finalizeSession(userName);
    }

    void disposeSaslServer() throws SaslException {
      if (saslServer != null) {
        saslServer.dispose();
        saslServer = null;
      }
    }

    /**
     * Sets the user on the session, and finalizes the session.
     *
     * @param userName user name to set on the session
     *
     */
    void finalizeSession(String userName) {
      // create a session
      session = UserSession.Builder.newBuilder()
          .withCredentials(UserCredentials.newBuilder()
              .setUserName(userName)
              .build())
          .withOptionManager(worker.getSystemOptions())
          .withUserProperties(inbound.getProperties())
          .setSupportComplexTypes(inbound.getSupportComplexTypes())
          .build();

      // if inbound impersonation is enabled and a target is mentioned
      final String targetName = session.getTargetUserName();
      if (impersonationManager != null && targetName != null) {
        impersonationManager.replaceUserOnSession(targetName, session);
      }
    }

    void changeHandlerTo(RequestHandler<UserClientConnectionImpl> handler) {
      this.currentHandler = handler;
    }

    @Override
    public UserSession getSession(){
      return session;
    }

    @Override
    public void sendResult(final RpcOutcomeListener<Ack> listener, final QueryResult result) {
      logger.trace("Sending result to client with {}", result);
      send(listener, this, RpcType.QUERY_RESULT, result, Ack.class, true);
    }

    @Override
    public void sendData(final RpcOutcomeListener<Ack> listener, final QueryWritableBatch result) {
      logger.trace("Sending data to client with {}", result);
      send(listener, this, RpcType.QUERY_DATA, result.getHeader(), Ack.class, false, result.getBuffers());
    }

    @Override
    public BufferAllocator getAllocator() {
      return alloc;
    }

    @Override
    public ChannelFuture getChannelClosureFuture() {
      return getChannel().closeFuture();
    }

    @Override
    public SocketAddress getRemoteAddress() {
      return getChannel().remoteAddress();
    }

    @Override
    public void close() {
      super.close();
      try {
        disposeSaslServer();
      } catch (final SaslException e) {
        logger.warn("Unclean disposal.", e);
      }
    }

  }

  @Override
  public UserClientConnectionImpl initRemoteConnection(SocketChannel channel) {
    super.initRemoteConnection(channel);
    return new UserClientConnectionImpl(channel);
  }

  @Override
  protected ServerHandshakeHandler<UserToBitHandshake> getHandshakeHandler(final UserClientConnectionImpl connection) {

    return new ServerHandshakeHandler<UserToBitHandshake>(RpcType.HANDSHAKE, UserToBitHandshake.PARSER){

      @Override
      protected void consumeHandshake(ChannelHandlerContext ctx, UserToBitHandshake inbound) throws Exception {
        BitToUserHandshake handshakeResp = getHandshakeResponse(inbound);
        OutboundRpcMessage msg = new OutboundRpcMessage(RpcMode.RESPONSE, this.handshakeType, coordinationId, handshakeResp);
        ctx.writeAndFlush(msg);

        if (handshakeResp.getStatus() != HandshakeStatus.SUCCESS &&
            handshakeResp.getStatus() != HandshakeStatus.AUTH_REQUIRED) {
          // If handling handshake results in an error, throw an exception to terminate the connection.
          throw new RpcException("Handshake request failed: " + handshakeResp.getErrorMessage());
        }
      }

      @Override
      public BitToUserHandshake getHandshakeResponse(UserToBitHandshake inbound) throws Exception {
        logger.trace("Handling handshake from user to bit. {}", inbound);

        // if timeout is unsupported or is set to false, disable timeout.
        if (!inbound.hasSupportTimeout() || !inbound.getSupportTimeout()) {
          connection.disableReadTimeout();
          logger.warn("Timeout Disabled as client doesn't support it.", connection.getName());
        }

        final BitToUserHandshake.Builder respBuilder = BitToUserHandshake.newBuilder()
            .setRpcVersion(UserRpcConfig.RPC_VERSION);

        try {
          if (!SUPPORTED_RPC_VERSIONS.contains(inbound.getRpcVersion())) {
            final String errMsg = String.format("Invalid rpc version. Expected %s, actual %d.",
                SUPPORTED_RPC_VERSIONS, inbound.getRpcVersion());

            return handleFailure(respBuilder, HandshakeStatus.RPC_VERSION_MISMATCH, errMsg, null);
          }

          connection.setHandshake(inbound);

          if (authFactory == null) { // authentication is disabled
            connection.finalizeSession(inbound.getCredentials().getUserName());
            respBuilder.setStatus(HandshakeStatus.SUCCESS);
            return respBuilder.build();
          }

          if (inbound.getRpcVersion() == NON_SASL_RPC_VERSION_SUPPORTED) { // for backward compatibility
            final String userName = inbound.getCredentials().getUserName();
            if (logger.isTraceEnabled()) {
              logger.trace("User {} on connection {} is using an older client (Drill version <= 1.8).",
                  userName, connection.getRemoteAddress());
            }
            try {
              String password = "";
              final UserProperties props = inbound.getProperties();
              for (int i = 0; i < props.getPropertiesCount(); i++) {
                Property prop = props.getProperties(i);
                if (ConnectionParams.PASSWORD.equalsIgnoreCase(prop.getKey())) {
                  password = prop.getValue();
                  break;
                }
              }
              final PlainMechanism plainMechanism = authFactory.getPlainMechanism();
              if (plainMechanism == null) {
                throw new UserAuthenticationException("The server no longer supports username/password" +
                    " based authentication. Please talk to your system administrator.");
              }
              plainMechanism.getAuthenticator()
                  .authenticate(userName, password);
              connection.changeHandlerTo(handler);
              connection.finalizeSession(userName);
              respBuilder.setStatus(HandshakeStatus.SUCCESS);
              if (logger.isTraceEnabled()) {
                logger.trace("Authenticated {} successfully using PLAIN from {}", userName,
                    connection.getRemoteAddress());
              }
              return respBuilder.build();
            } catch (UserAuthenticationException ex) {
              return handleFailure(respBuilder, HandshakeStatus.AUTH_FAILED, ex.getMessage(), ex);
            }
          }

          // mention server's authentication capabilities
          respBuilder.addAllAuthenticationMechanisms(authFactory.getSupportedMechanisms());

          respBuilder.setStatus(HandshakeStatus.AUTH_REQUIRED);
          return respBuilder.build();

        } catch (Exception e) {
          return handleFailure(respBuilder, HandshakeStatus.UNKNOWN_FAILURE, e.getMessage(), e);
        }
      }
    };
  }

  /**
   * Complete building the given builder for <i>BitToUserHandshake</i> message with given status and error details.
   *
   * @param respBuilder Instance of {@link org.apache.drill.exec.proto.UserProtos.BitToUserHandshake} builder which
   *                    has RPC version field already set.
   * @param status  Status of handling handshake request.
   * @param errMsg  Error message.
   * @param exception Optional exception.
   * @return
   */
  private static BitToUserHandshake handleFailure(BitToUserHandshake.Builder respBuilder, HandshakeStatus status,
      String errMsg, Exception exception) {
    final String errorId = UUID.randomUUID().toString();

    if (exception != null) {
      logger.error("Error {} in Handling handshake request: {}, {}", errorId, status, errMsg, exception);
    } else {
      logger.error("Error {} in Handling handshake request: {}, {}", errorId, status, errMsg);
    }

    return respBuilder
        .setStatus(status)
        .setErrorId(errorId)
        .setErrorMessage(errMsg)
        .build();
  }

  @Override
  public ProtobufLengthDecoder getDecoder(BufferAllocator allocator, OutOfMemoryHandler outOfMemoryHandler) {
    return new UserProtobufLengthDecoder(allocator, outOfMemoryHandler);
  }

  @Override
  public void close() throws IOException {
    if (authFactory != null) {
      try {
        authFactory.close();
      } catch (Exception e) {
        logger.warn("Failure closing authentication factory.", e);
      }
    }
    super.close();
  }
}
