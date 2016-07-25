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

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

// package private
class UserServerAuthenticationHandler implements RequestHandler<UserServer.UserClientConnectionImpl> {
  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(UserServerAuthenticationHandler.class);

  private final UserServerRequestHandler requestHandler;

  public UserServerAuthenticationHandler(final UserServerRequestHandler requestHandler) {
    this.requestHandler = requestHandler;
  }

  @Override
  public void handle(UserServer.UserClientConnectionImpl connection, int rpcType, ByteBuf pBody, ByteBuf dBody,
                     ResponseSender sender) throws RpcException {
    final String remoteAddress = connection.getRemoteAddress().toString();
    switch (rpcType) {

    case RpcType.SASL_MESSAGE_VALUE:
      try {
        final SaslMessage message = SaslMessage.PARSER.parseFrom(new ByteBufInputStream(pBody));
        logger.trace("Received SASL message {} from {}", message.getStatus(), remoteAddress);

        switch (message.getStatus()) {

        case SASL_START: {
          try {
            // TODO(SUDHEESH): MUST FIX NULL
            connection.initSaslServer(message.getMechanism(), null);
          } catch (final Exception e) {
            handleAuthFailure(connection, sender, e);
          }
        }

        // assume #evaluateResponse must be called at least once
        // $FALL-THROUGH$

        case SASL_AUTH_IN_PROGRESS: {
          try {
            final SaslMessage.Builder challenge = SaslMessage.newBuilder();
            final SaslServer saslServer = connection.getSaslServer();
            final byte[] challengeBytes = saslServer.evaluateResponse(message.getData().toByteArray());
            if (saslServer.isComplete()) {
              logger.trace("Authenticated {} successfully using {} from {}", saslServer.getAuthorizationID(),
                  saslServer.getMechanismName(), remoteAddress);
              challenge.setStatus(SaslStatus.SASL_AUTH_SUCCESS);
              if (challengeBytes != null) {
                challenge.setData(ByteString.copyFrom(challengeBytes));
              }

              connection.changeHandlerTo(requestHandler);
              connection.finalizeSession();
              connection.disposeSaslServer();
            } else {
              challenge.setStatus(SaslStatus.SASL_AUTH_IN_PROGRESS)
                  .setData(ByteString.copyFrom(challengeBytes));
            }

            sender.send(new Response(RpcType.SASL_MESSAGE, challenge.build()));
          } catch (final Exception e) {
            handleAuthFailure(connection, sender, e);
          }
        }

        case SASL_AUTH_SUCCESS: { // client succeeded first
          // at this point, #isComplete must be false; so try once, fail otherwise
          try {
            final SaslServer saslServer = connection.getSaslServer();
            saslServer.evaluateResponse(message.getData().toByteArray()); // discard challenge
            if (saslServer.isComplete()) {
              final SaslMessage.Builder challenge = SaslMessage.newBuilder();
              logger.trace("Authenticated {} successfully using {} from {}", saslServer.getAuthorizationID(),
                  saslServer.getMechanismName(), remoteAddress);
              challenge.setStatus(SaslStatus.SASL_AUTH_SUCCESS);

              connection.changeHandlerTo(requestHandler);
              connection.finalizeSession();
              connection.disposeSaslServer();
              sender.send(new Response(RpcType.SASL_MESSAGE, challenge.build()));
            } else {
              logger.info("Failed to authenticate client from {}", remoteAddress);
              throw new SaslException("Client allegedly succeeded authentication, but server did not. Suspicious?");
            }
          } catch (final Exception e) {
            handleAuthFailure(connection, sender, e);
          }
        }

        case SASL_AUTH_FAILED: {
          logger.info("Client from {} failed authentication graciously, and does not want to continue.",
              remoteAddress);
          handleAuthFailure(connection, sender, new SaslException("Client graciously failed authentication"));
        }

        default: {
          logger.info("Unknown message type from client from {}. Will stop authentication.", remoteAddress);
          handleAuthFailure(connection, sender, new SaslException("Received unexpected message"));
        }
        }

      } catch (final InvalidProtocolBufferException e) {
        handleAuthFailure(connection, sender, e);
      }

    default:
      // drop the connection; the response type is likely known from UserRpcConfig,
      // but the client should not be making any requests before authenticating
      throw new UnsupportedOperationException(
          String.format("Request of type %d is not allowed without authentication. " +
              "Client on %s must authenticate before making requests.", rpcType, remoteAddress));
    }
  }

  private static void handleAuthFailure(UserServer.UserClientConnectionImpl connection,
                                        ResponseSender sender, Exception e) throws RpcException {
    // cleanup
    try {
      connection.disposeSaslServer();
    } catch (final SaslException ignored) {
      logger.warn("Unexpected failure while disposing SaslServer", ignored);
    }
    // inform the client
    sender.send(new Response(RpcType.SASL_MESSAGE,
        SaslMessage.newBuilder()
            .setStatus(SaslStatus.SASL_AUTH_FAILED)
            .build()));
    // throw an exception (terminates the connection); see RpcExceptionHandler
    throw new RpcException("Authentication failed", e);
  }
}
