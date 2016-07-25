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

import com.google.common.util.concurrent.AbstractCheckedFuture;
import com.google.common.util.concurrent.CheckedFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.DrillBuf;
import io.netty.channel.EventLoopGroup;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;

import org.apache.drill.common.config.ConnectionParams;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.client.AuthenticationUtil;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.proto.CoordinationProtos.DrillbitEndpoint;
import org.apache.drill.exec.proto.GeneralRPCProtos.Ack;
import org.apache.drill.exec.proto.UserBitShared.QueryData;
import org.apache.drill.exec.proto.UserBitShared.QueryId;
import org.apache.drill.exec.proto.UserBitShared.QueryResult;
import org.apache.drill.exec.proto.UserBitShared.UserCredentials;
import org.apache.drill.exec.proto.UserProtos.BitToUserHandshake;
import org.apache.drill.exec.proto.UserProtos.CreatePreparedStatementResp;
import org.apache.drill.exec.proto.UserProtos.GetCatalogsResp;
import org.apache.drill.exec.proto.UserProtos.GetColumnsResp;
import org.apache.drill.exec.proto.UserProtos.GetQueryPlanFragments;
import org.apache.drill.exec.proto.UserProtos.GetSchemasResp;
import org.apache.drill.exec.proto.UserProtos.GetTablesResp;
import org.apache.drill.exec.proto.UserProtos.QueryPlanFragments;
import org.apache.drill.exec.proto.UserProtos.RpcType;
import org.apache.drill.exec.proto.UserProtos.RunQuery;
import org.apache.drill.exec.proto.UserProtos.SaslMessage;
import org.apache.drill.exec.proto.UserProtos.SaslStatus;
import org.apache.drill.exec.proto.UserProtos.UserToBitHandshake;
import org.apache.drill.exec.rpc.Acks;
import org.apache.drill.exec.rpc.BasicClientWithConnection;
import org.apache.drill.exec.rpc.ConnectionThrottle;
import org.apache.drill.exec.rpc.DrillRpcFuture;
import org.apache.drill.exec.rpc.OutOfMemoryHandler;
import org.apache.drill.exec.rpc.ProtobufLengthDecoder;
import org.apache.drill.exec.rpc.Response;
import org.apache.drill.exec.rpc.RpcConnectionHandler;
import org.apache.drill.exec.rpc.RpcException;

import com.google.protobuf.MessageLite;
import org.apache.drill.exec.rpc.RpcOutcomeListener;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class UserClient extends BasicClientWithConnection<RpcType, UserToBitHandshake, BitToUserHandshake> {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserClient.class);

  private final QueryResultHandler queryResultHandler = new QueryResultHandler();
  private boolean supportComplexTypes = true;
  private ConnectionParams connectionParams;
  private SaslClient saslClient;

  public UserClient(DrillConfig config, boolean supportComplexTypes, BufferAllocator alloc,
                    EventLoopGroup eventLoopGroup, Executor eventExecutor) {
    super(
        UserRpcConfig.getMapping(config, eventExecutor),
        alloc,
        eventLoopGroup,
        RpcType.HANDSHAKE,
        BitToUserHandshake.class,
        BitToUserHandshake.PARSER,
        "user client");
    this.supportComplexTypes = supportComplexTypes;
  }

  public void submitQuery(UserResultsListener resultsListener, RunQuery query) {
    send(queryResultHandler.getWrappedListener(resultsListener), RpcType.RUN_QUERY, query, QueryId.class);
  }

  public CheckedFuture<Void, RpcException> connect(DrillbitEndpoint endpoint, ConnectionParams connectionParams,
                                                   UserCredentials credentials) {
    final FutureHandler handler = new FutureHandler();
    UserToBitHandshake.Builder hsBuilder = UserToBitHandshake.newBuilder()
        .setRpcVersion(UserRpcConfig.RPC_VERSION)
        .setSupportListening(true)
        .setSupportComplexTypes(supportComplexTypes)
        .setSupportTimeout(true)
        .setCredentials(credentials)
        .setProperties(connectionParams.serializeForServer());
    this.connectionParams = connectionParams;

    connectAsClient(queryResultHandler.getWrappedConnectionHandler(handler),
        hsBuilder.build(), endpoint.getAddress(), endpoint.getUserPort());
    return handler;
  }

  public CheckedFuture<Void, SaslException> authenticate() {
    final SettableFuture<Void> settableFuture = SettableFuture.create(); // future used in exchange
    final CheckedFuture<Void, SaslException> future =
        new AbstractCheckedFuture<Void, SaslException>(settableFuture) {
          @Override
          protected SaslException mapException(Exception e) {
            connection.close(); // to ensure connection is dropped
            if (e instanceof ExecutionException) {
              final Throwable cause = e.getCause();
              if (cause instanceof SaslException) {
                return new SaslException("Authentication failed: " + cause.getMessage(), cause);
              }
            }
            return new SaslException("Authentication failed unexpectedly.", e);
          }
        };

    if (saslClient == null) {
      settableFuture.setException(new SaslException("Server does not require authentication, " +
          "or something went wrong during authentication setup?"));
    } else {
      try {
        send(new SaslClientListener(settableFuture),
            RpcType.SASL_MESSAGE,
            SaslMessage.newBuilder()
                .setMechanism(saslClient.getMechanismName())
                .setStatus(SaslStatus.SASL_START)
                .setData(saslClient.hasInitialResponse() ?
                    ByteString.copyFrom(saslClient.evaluateChallenge(new byte[0])) : ByteString.EMPTY)
                .build(),
            SaslMessage.class);
        logger.trace("Initiated SASL exchange.");
      } catch (Exception e) {
        logger.trace("Failed to initiate SASL exchange.");
        settableFuture.setException(e);
      }
    }
    return future;
  }

  // handles SASL message exchange
  private class SaslClientListener implements RpcOutcomeListener<SaslMessage> {

    private final SettableFuture<Void> future;

    public SaslClientListener(SettableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void failed(RpcException ex) {
      future.setException(ex);
    }

    @Override
    public void success(SaslMessage value, ByteBuf buffer) {
      logger.trace("Server responded with message of type: " + value.getStatus());
      switch (value.getStatus()) {
      case SASL_AUTH_IN_PROGRESS: {
        try {
          final SaslMessage.Builder response = SaslMessage.newBuilder();
          final byte[] responseBytes = saslClient.evaluateChallenge(value.getData().toByteArray());
          logger.trace("Evaluated challenge. Completed? {}. Sending response to server..", saslClient.isComplete());
          if (saslClient.isComplete()) {
            response.setStatus(SaslStatus.SASL_AUTH_SUCCESS);
            if (responseBytes != null) {
              response.setData(ByteString.copyFrom(responseBytes));
            }
            // client finished; will get one more response from server
          } else {
            response.setStatus(SaslStatus.SASL_AUTH_IN_PROGRESS)
                .setData(ByteString.copyFrom(responseBytes));
          }
          send(new SaslClientListener(future),
              connection,
              RpcType.SASL_MESSAGE,
              response.build(),
              SaslMessage.class,
              true);
        } catch (Exception e) {
          future.setException(e);
        }
        break;
      }
      case SASL_AUTH_SUCCESS: {
        try {
          if (saslClient.isComplete()) {
            logger.trace("Successfully authenticated to server using {}", saslClient.getMechanismName());
            saslClient.dispose();
            saslClient = null;
            future.set(null); // success
          } else {
            // server completed before client; so try once, fail otherwise
            saslClient.evaluateChallenge(value.getData().toByteArray()); // discard response
            if (saslClient.isComplete()) {
              logger.trace("Successfully authenticated to server using {}", saslClient.getMechanismName());
              saslClient.dispose();
              saslClient = null;
              future.set(null); // success
            } else {
              future.setException(
                  new SaslException("Server allegedly succeeded authentication, but client did not. Suspicious?"));
            }
          }
        } catch (Exception e) {
          future.setException(e);
        }
        break;
      }
      case SASL_AUTH_FAILED: {
        future.setException(new SaslException("Insufficient or incorrect credentials?"));
        try {
          saslClient.dispose();
        } catch (final SaslException ignored) {
          logger.warn("Auth failed; cleanup also failed.", ignored);
        }
        saslClient = null;
        break;
      }
      default:
        future.setException(new SaslException("Server sent a corrupt message."));
      }
    }

    @Override
    public void interrupted(InterruptedException e) {
      future.setException(e);
    }
  }

  @Override
  protected MessageLite getResponseDefaultInstance(int rpcType) throws RpcException {
    switch (rpcType) {
    case RpcType.ACK_VALUE:
      return Ack.getDefaultInstance();
    case RpcType.HANDSHAKE_VALUE:
      return BitToUserHandshake.getDefaultInstance();
    case RpcType.QUERY_HANDLE_VALUE:
      return QueryId.getDefaultInstance();
    case RpcType.QUERY_RESULT_VALUE:
      return QueryResult.getDefaultInstance();
    case RpcType.QUERY_DATA_VALUE:
      return QueryData.getDefaultInstance();
    case RpcType.QUERY_PLAN_FRAGMENTS_VALUE:
      return QueryPlanFragments.getDefaultInstance();
    case RpcType.CATALOGS_VALUE:
      return GetCatalogsResp.getDefaultInstance();
    case RpcType.SCHEMAS_VALUE:
      return GetSchemasResp.getDefaultInstance();
    case RpcType.TABLES_VALUE:
      return GetTablesResp.getDefaultInstance();
    case RpcType.COLUMNS_VALUE:
      return GetColumnsResp.getDefaultInstance();
    case RpcType.PREPARED_STATEMENT_VALUE:
      return CreatePreparedStatementResp.getDefaultInstance();
    case RpcType.SASL_MESSAGE_VALUE:
      return SaslMessage.getDefaultInstance();
    }
    throw new RpcException(String.format("Unable to deal with RpcType of %d", rpcType));
  }

  @Override
  protected Response handleResponse(ConnectionThrottle throttle, int rpcType, ByteBuf pBody, ByteBuf dBody) throws RpcException {
    switch (rpcType) {
    case RpcType.QUERY_DATA_VALUE:
      queryResultHandler.batchArrived(throttle, pBody, dBody);
      return new Response(RpcType.ACK, Acks.OK);
    case RpcType.QUERY_RESULT_VALUE:
      queryResultHandler.resultArrived(pBody);
      return new Response(RpcType.ACK, Acks.OK);
    default:
      throw new RpcException(String.format("Unknown Rpc Type %d. ", rpcType));
    }
  }

  @Override
  protected void validateHandshake(BitToUserHandshake inbound) throws RpcException {
    switch (inbound.getStatus()) {
    case SUCCESS:
      break;
    case AUTH_REQUIRED: {
      logger.trace("Server requires authentication before proceeding.");
      final String authMechanismToUse = AuthenticationUtil.getMechanismFromParams(connectionParams);
      if (authMechanismToUse == null) {
        throw new RpcException("Server requires authentication. But the client library could not deduce which " +
            "mechanism to use from the given connection parameters.");
      }

      boolean isChosenMechanismSupported = false;
      for (final String mechanism : inbound.getAuthenticationMechanismsList()) {
        if (mechanism.equalsIgnoreCase(authMechanismToUse)) {
          isChosenMechanismSupported = true;
          break;
        }
      }
      if (!isChosenMechanismSupported) {
        throw new RpcException(
            String.format("Server does not support the chosen mechanism: '%s' supported mechanisms: %s",
                authMechanismToUse, inbound.getAuthenticationMechanismsList()));
      }
      logger.trace("Will try to authenticate using {} mechanism.", authMechanismToUse);

      try {
        switch (authMechanismToUse.toUpperCase()) {

        case "PLAIN": {
          final String name = connectionParams.getUserName();
          final String password = connectionParams.getParam(ConnectionParams.PASSWORD);
          saslClient = AuthenticationUtil.getPlainSaslClient(name, password);
          break;
        }

        case "GSSAPI": {
          final String principal = AuthenticationUtil.deriveKerberosName(connectionParams);
          final String[] names = AuthenticationUtil.splitKerberosName(principal); // ignore names[2]
          saslClient = AuthenticationUtil.getKerberosSaslClient(names[0], names[1], connectionParams);
          break;
        }

        default: // not possible
          throw new RpcException("Client chose a mechanism that is not available. Cannot authenticate to server.");
        }
      } catch (Exception e) {
        throw new RpcException("Unable to start authenticating to server.", e);
      }
      break;
    }
    case AUTH_FAILED:
    case RPC_VERSION_MISMATCH:
    case UNKNOWN_FAILURE:
      final String errMsg = String.format("Status: %s, Error Id: %s, Error message: %s",
          inbound.getStatus(), inbound.getErrorId(), inbound.getErrorMessage());
      logger.error(errMsg);
      throw new RpcException(errMsg);
    }
  }

  @Override
  protected void finalizeConnection(BitToUserHandshake handshake, BasicClientWithConnection.ServerConnection connection) {
  }

  @Override
  public ProtobufLengthDecoder getDecoder(BufferAllocator allocator) {
    return new UserProtobufLengthDecoder(allocator, OutOfMemoryHandler.DEFAULT_INSTANCE);
  }

  /**
   * planQuery is an API to plan a query without query execution
   * @param req - data necessary to plan query
   * @return list of PlanFragments that can later on be submitted for execution
   */
  public DrillRpcFuture<QueryPlanFragments> planQuery(
      GetQueryPlanFragments req) {
    return send(RpcType.GET_QUERY_PLAN_FRAGMENTS, req, QueryPlanFragments.class);
  }

  private class FutureHandler extends AbstractCheckedFuture<Void, RpcException>
      implements RpcConnectionHandler<ServerConnection>, DrillRpcFuture<Void> {

    protected FutureHandler() {
      super(SettableFuture.<Void>create());
    }

    @Override
    public void connectionSucceeded(ServerConnection connection) {
      getInner().set(null);
    }

    @Override
    public void connectionFailed(FailureType type, Throwable t) {
      getInner().setException(new RpcException(String.format("%s : %s", type.name(), t.getMessage()), t));
    }

    private SettableFuture<Void> getInner() {
      return (SettableFuture<Void>) delegate();
    }

    @Override
    protected RpcException mapException(Exception e) {
      return RpcException.mapException(e);
    }

    @Override
    public DrillBuf getBuffer() {
      return null;
    }
  }
}
