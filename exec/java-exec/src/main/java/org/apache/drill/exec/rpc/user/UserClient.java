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

import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.AbstractCheckedFuture;
import com.google.common.util.concurrent.CheckedFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.DrillBuf;
import io.netty.channel.EventLoopGroup;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;

import org.apache.drill.common.config.ConnectionParameters;
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
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class UserClient extends BasicClientWithConnection<RpcType, UserToBitHandshake, BitToUserHandshake> {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserClient.class);

  private final QueryResultHandler queryResultHandler = new QueryResultHandler();
  private boolean supportComplexTypes = true;
  private ConnectionParameters parameters;

  // these are used for authentication
  private volatile List<String> supportedMechs = null;
  private SaslClient saslClient = null;

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

  public CheckedFuture<Void, RpcException> connect(DrillbitEndpoint endpoint, ConnectionParameters parameters,
                                                   UserCredentials credentials) {
    final FutureHandler handler = new FutureHandler();
    UserToBitHandshake.Builder hsBuilder = UserToBitHandshake.newBuilder()
        .setRpcVersion(UserRpcConfig.RPC_VERSION)
        .setSupportListening(true)
        .setSupportComplexTypes(supportComplexTypes)
        .setSupportTimeout(true)
        .setCredentials(credentials)
        .setProperties(parameters.serializeForServer());
    this.parameters = parameters;

    connectAsClient(queryResultHandler.getWrappedConnectionHandler(handler),
        hsBuilder.build(), endpoint.getAddress(), endpoint.getUserPort());
    return handler;
  }

  /**
   * Check (after {@link #connect connecting}) if server requires authentication.
   *
   * @return true if server requires authentication
   */
  public boolean serverRequiresAuthentication() {
    return supportedMechs != null;
  }

  /**
   * Returns a list of supported authentication mechanism. If called before {@link #connect connecting},
   * returns null. If called after {@link #connect connecting}, returns a list of supported mechanisms
   * iff authentication is required.
   *
   * @return list of supported authentication mechanisms
   */
  public List<String> getSupportedAuthenticationMechanisms() {
    return supportedMechs;
  }

  /**
   * Authenticate to the server asynchronously. Returns a future that {@link CheckedFuture#checkedGet results}
   * in null if authentication succeeds, or throws a {@link SaslException} with relevant message if
   * authentication fails.
   *
   * This method uses parameters provided at {@link #connect connection time} and override them with the
   * given parameters, if any.
   *
   * @param overrides parameter overrides
   * @return result of authentication request
   */
  public CheckedFuture<Void, SaslException> authenticate(final ConnectionParameters overrides) {
    parameters.merge(overrides);
    assert supportedMechs != null;
    final SettableFuture<Void> settableFuture = SettableFuture.create(); // future used in SASL exchange
    final CheckedFuture<Void, SaslException> future =
        new AbstractCheckedFuture<Void, SaslException>(settableFuture) {

          @Override
          protected SaslException mapException(Exception e) {
            if (connection != null) {
              connection.close(); // to ensure connection is dropped
            }
            if (e instanceof ExecutionException) {
              final Throwable cause = e.getCause();
              if (cause instanceof SaslException) {
                return new SaslException("Authentication failed: " + cause.getMessage(), cause);
              }
            }
            return new SaslException("Authentication failed unexpectedly.", e);
          }
        };

    final String authMechanismToUse = AuthenticationUtil.getMechanismFromParameters(parameters);
    if (authMechanismToUse == null) {
      settableFuture.setException(new SaslException("Cannot derive mechanism. Insufficient credentials?"));
      return future;
    }

    boolean isChosenMechanismSupported = false;
    for (final String mechanism : supportedMechs) {
      if (mechanism.equalsIgnoreCase(authMechanismToUse)) {
        isChosenMechanismSupported = true;
        break;
      }
    }
    if (!isChosenMechanismSupported) {
      settableFuture.setException(new SaslException(
          String.format("Server does not support authentication using '%s', supported mechanisms: %s",
              authMechanismToUse, supportedMechs)));
      return future;
    }

    logger.trace("Will try to login for {} mechanism.", authMechanismToUse);
    final UserGroupInformation ugi;
    try {
      ugi = AuthenticationUtil.login(authMechanismToUse, parameters);
    } catch (SaslException e) {
      settableFuture.setException(e);
      return future;
    }

    logger.trace("Will try to authenticate to server using {} mechanism.", authMechanismToUse);
    try {
      saslClient = AuthenticationUtil.createSaslClient(ugi, authMechanismToUse, parameters);
    } catch (SaslException e) {
      settableFuture.setException(e);
      return future;
    }

    if (saslClient == null) {
      settableFuture.setException(new SaslException("Cannot initiate. Insufficient credentials?"));
      return future;
    }
    logger.trace("Initiating SASL exchange.");

    try {
      final ByteString responseData;
      if (saslClient.hasInitialResponse()) {
        responseData = ByteString.copyFrom(evaluateChallenge(ugi, saslClient, new byte[0]));
      } else {
        responseData = ByteString.EMPTY;
      }
      send(new SaslClientListener(ugi, settableFuture),
          RpcType.SASL_MESSAGE,
          SaslMessage.newBuilder()
              .setMechanism(saslClient.getMechanismName())
              .setStatus(SaslStatus.SASL_START)
              .setData(responseData)
              .build(),
          SaslMessage.class);
      logger.trace("Initiated SASL exchange.");
    } catch (SaslException e) {
      settableFuture.setException(e);
    }
    return future;
  }

  private static byte[] evaluateChallenge(final UserGroupInformation ugi, final SaslClient saslClient,
                                          final byte[] challenge) throws SaslException {
    try {
      return ugi.doAs(new PrivilegedExceptionAction<byte[]>() {
        @Override
        public byte[] run() throws Exception {
          return saslClient.evaluateChallenge(challenge);
        }
      });
    } catch (final UndeclaredThrowableException e) {
      if (e.getCause() instanceof SaslException) {
        throw (SaslException) e.getCause();
      } else {
        throw new SaslException(
            String.format("Unexpected failure (%s)", saslClient.getMechanismName()), e.getCause());
      }
    } catch (final IOException | InterruptedException e) {
      throw new SaslException(String.format("Unexpected failure (%s)", saslClient.getMechanismName()), e);
    }
  }

  // handles SASL message exchange
  private class SaslClientListener implements RpcOutcomeListener<SaslMessage> {

    private final UserGroupInformation ugi;
    private final SettableFuture<Void> future;

    public SaslClientListener(UserGroupInformation ugi, SettableFuture<Void> future) {
      this.ugi = ugi;
      this.future = future;
    }

    @Override
    public void failed(RpcException ex) {
      future.setException(new SaslException("Unexpected failure", ex));
    }

    @Override
    public void success(SaslMessage value, ByteBuf buffer) {
      logger.trace("Server responded with message of type: {}", value.getStatus());
      switch (value.getStatus()) {
      case SASL_AUTH_IN_PROGRESS: {
        try {
          final SaslMessage.Builder response = SaslMessage.newBuilder();
          final byte[] responseBytes = evaluateChallenge(ugi, saslClient, value.getData().toByteArray());
          final boolean isComplete = saslClient.isComplete();
          logger.trace("Evaluated challenge. Completed? {}. Sending response to server.", isComplete);
          if (isComplete) {
            response.setStatus(SaslStatus.SASL_AUTH_SUCCESS);
            if (responseBytes != null) {
              response.setData(ByteString.copyFrom(responseBytes));
            }
            // client finished; will get one more response from server
          } else {
            response.setStatus(SaslStatus.SASL_AUTH_IN_PROGRESS)
                .setData(ByteString.copyFrom(responseBytes));
          }
          send(new SaslClientListener(ugi, future),
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
            evaluateChallenge(ugi, saslClient, value.getData().toByteArray()); // discard response
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
        future.setException(new SaslException("Incorrect credentials?"));
        try {
          saslClient.dispose();
        } catch (final SaslException ignored) {
          // ignored
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
      supportedMechs = ImmutableList.copyOf(inbound.getAuthenticationMechanismsList());
      break;
    }
    case AUTH_FAILED: // no longer a status returned by server
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
