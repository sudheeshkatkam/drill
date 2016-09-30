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

import com.google.common.collect.ImmutableMap;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import org.apache.drill.exec.proto.UserProtos.RpcType;
import org.apache.drill.exec.proto.UserProtos.SaslMessage;
import org.apache.drill.exec.proto.UserProtos.SaslStatus;
import org.apache.drill.exec.rpc.Response;
import org.apache.drill.exec.rpc.ResponseSender;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.rpc.RequestHandler;
import org.apache.drill.exec.security.LoginManager;

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedExceptionAction;

import static com.google.common.base.Preconditions.checkNotNull;

// package private
class UserServerAuthenticationHandler implements RequestHandler<UserServer.UserClientConnectionImpl> {
  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(UserServerAuthenticationHandler.class);

  private static final ImmutableMap<SaslStatus, SaslResponseProcessor> RESPONSE_PROCESSORS =
      ImmutableMap.<SaslStatus, SaslResponseProcessor>builder()
          .put(SaslStatus.SASL_START, new SaslStartProcessor())
          .put(SaslStatus.SASL_IN_PROGRESS, new SaslInProgressProcessor())
          .put(SaslStatus.SASL_SUCCESS, new SaslSuccessProcessor())
          .put(SaslStatus.SASL_FAILED, new SaslFailedProcessor())
          .build();

  private final UserServerRequestHandler requestHandler;
  private final LoginManager loginManager;

  public UserServerAuthenticationHandler(final UserServerRequestHandler requestHandler,
                                         final LoginManager loginManager) {
    this.requestHandler = requestHandler;
    this.loginManager = loginManager;
  }

  @Override
  public void handle(UserServer.UserClientConnectionImpl connection, int rpcType, ByteBuf pBody, ByteBuf dBody,
                     ResponseSender sender) throws RpcException {
    final String remoteAddress = connection.getRemoteAddress().toString();

    switch (rpcType) {

    // exchange involves server "challenges" and client "responses" (initiated by client)
    case RpcType.SASL_MESSAGE_VALUE: {
      final SaslMessage saslResponse;
      try {
        saslResponse = SaslMessage.PARSER.parseFrom(new ByteBufInputStream(pBody));
      } catch (final InvalidProtocolBufferException e) {
        handleAuthFailure(connection, remoteAddress, sender, e);
        break;
      }

      logger.trace("Received SASL message {} from {}", saslResponse.getStatus(), remoteAddress);
      final SaslResponseProcessor processor = RESPONSE_PROCESSORS.get(saslResponse.getStatus());
      if (processor == null) {
        logger.info("Unknown message type from client from {}. Will stop authentication.", remoteAddress);
        handleAuthFailure(connection, remoteAddress, sender, new SaslException("Received unexpected message"));
        break;
      }

      final SaslResponseContext context =
          new SaslResponseContext(saslResponse, connection, remoteAddress, sender, loginManager, requestHandler);
      try {
        final SaslMessage saslChallenge = processor.process(context);
        sender.send(new Response(RpcType.SASL_MESSAGE, saslChallenge));
        break;
      } catch (final Exception e) {
        handleAuthFailure(connection, remoteAddress, sender, e);
        break;
      }
    }

    // this handler only handles messages of SASL_MESSAGE_VALUE type
    default:

      // drop connection
      connection.close();

      // the response type for this request type is likely known from UserRpcConfig,
      // but the client should not be making any requests before authenticating.
      throw new UnsupportedOperationException(
          String.format("Request of type %d is not allowed without authentication. " +
              "Client on %s must authenticate before making requests. Connection dropped.",
              rpcType, remoteAddress));
    }
  }

  private static class SaslResponseContext {

    final SaslMessage saslResponse;
    final UserServer.UserClientConnectionImpl connection;
    final String remoteAddress;
    final LoginManager loginManager;
    final UserServerRequestHandler requestHandler;

    SaslResponseContext(SaslMessage saslResponse, UserServer.UserClientConnectionImpl connection,
                        String remoteAddress, ResponseSender sender, LoginManager loginManager,
                        UserServerRequestHandler requestHandler) {
      this.saslResponse = checkNotNull(saslResponse);
      this.connection = checkNotNull(connection);
      this.remoteAddress = checkNotNull(remoteAddress);
      this.loginManager = checkNotNull(loginManager);
      this.requestHandler = checkNotNull(requestHandler);
    }
  }

  private interface SaslResponseProcessor {

    /**
     * Process response from client, and return a challenge.
     *
     * @param context response context
     * @return challenge
     * @throws Exception
     */
    SaslMessage process(SaslResponseContext context) throws Exception;

  }

  private static class SaslStartProcessor implements SaslResponseProcessor {

    @Override
    public SaslMessage process(final SaslResponseContext context) throws Exception {
      context.connection.initSaslServer(context.saslResponse.getMechanism(),
          null /** properties; default QOP is auth */);

      // assume #evaluateResponse must be called at least once
      return RESPONSE_PROCESSORS.get(SaslStatus.SASL_IN_PROGRESS).process(context);
    }
  }

  private static class SaslInProgressProcessor implements SaslResponseProcessor {

    @Override
    public SaslMessage process(final SaslResponseContext context) throws Exception {
      final SaslMessage.Builder challenge = SaslMessage.newBuilder();
      final SaslServer saslServer = context.connection.getSaslServer();

      final byte[] challengeBytes = evaluateResponse(context.loginManager, saslServer,
          context.saslResponse.getData().toByteArray());

      if (saslServer.isComplete()) {
        challenge.setStatus(SaslStatus.SASL_SUCCESS);
        if (challengeBytes != null) {
          challenge.setData(ByteString.copyFrom(challengeBytes));
        }

        context.connection.changeHandlerTo(context.requestHandler);
        context.connection.finalizeSession();
        logger.trace("Authenticated {} successfully using {} from {}", saslServer.getAuthorizationID(),
            saslServer.getMechanismName(), context.remoteAddress);
      } else {
        challenge.setStatus(SaslStatus.SASL_IN_PROGRESS)
            .setData(ByteString.copyFrom(challengeBytes));
      }

      return challenge.build();
    }
  }

  // only when client succeeds first
  private static class SaslSuccessProcessor implements SaslResponseProcessor {

    @Override
    public SaslMessage process(final SaslResponseContext context) throws Exception {
      // at this point, #isComplete must be false; so try once, fail otherwise
      final SaslServer saslServer = context.connection.getSaslServer();

      evaluateResponse(context.loginManager, saslServer,
          context.saslResponse.getData().toByteArray()); // discard challenge

      if (saslServer.isComplete()) {
        final SaslMessage.Builder challenge = SaslMessage.newBuilder();
        challenge.setStatus(SaslStatus.SASL_SUCCESS);

        context.connection.changeHandlerTo(context.requestHandler);
        context.connection.finalizeSession();
        logger.trace("Authenticated {} successfully using {} from {}", saslServer.getAuthorizationID(),
            saslServer.getMechanismName(), context.remoteAddress);
        return challenge.build();
      } else {
        logger.info("Failed to authenticate client from {}", context.remoteAddress);
        throw new SaslException("Client allegedly succeeded authentication, but server did not. Suspicious?");
      }
    }
  }

  private static class SaslFailedProcessor implements SaslResponseProcessor {

    @Override
    public SaslMessage process(final SaslResponseContext context) throws Exception {
      logger.info("Client from {} failed authentication graciously, and does not want to continue.",
          context.remoteAddress);
      throw new SaslException("Client graciously failed authentication");
    }
  }

  private static byte[] evaluateResponse(final LoginManager loginManager, final SaslServer saslServer,
                                         final byte[] responseBytes) throws SaslException {
    try {
      return loginManager.doAsLoginUser(new PrivilegedExceptionAction<byte[]>() {
        @Override
        public byte[] run() throws Exception {
          return saslServer.evaluateResponse(responseBytes);
        }
      });
    } catch (final UndeclaredThrowableException e) {
      throw new SaslException(String.format("Unexpected failure trying to authenticate using %s",
          saslServer.getMechanismName()), e.getCause());
    } catch (final IOException | InterruptedException e) {
      if (e instanceof SaslException) {
        throw (SaslException) e;
      } else {
        throw new SaslException(String.format("Unexpected failure trying to authenticate using %s",
            saslServer.getMechanismName()), e);
      }
    }
  }

  private static void handleAuthFailure(UserServer.UserClientConnectionImpl connection, String remoteAddress,
                                        ResponseSender sender, Exception e) {
    logger.debug("Authentication failed from client {} due to {}", remoteAddress, e);

    // inform the client that authentication failed, and no more
    sender.send(new Response(RpcType.SASL_MESSAGE,
        SaslMessage.newBuilder()
            .setStatus(SaslStatus.SASL_FAILED)
            .build()));

    // drop connection
    connection.close();
  }
}
