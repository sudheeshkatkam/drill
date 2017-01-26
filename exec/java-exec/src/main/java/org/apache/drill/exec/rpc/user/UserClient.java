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

import com.google.common.base.Function;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterators;
import com.google.common.util.concurrent.AbstractCheckedFuture;
import com.google.common.util.concurrent.CheckedFuture;
import com.google.common.util.concurrent.SettableFuture;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.DrillBuf;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;

import io.netty.channel.socket.SocketChannel;
import org.apache.drill.common.KerberosUtil;
import org.apache.drill.common.config.DrillProperties;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.proto.CoordinationProtos.DrillbitEndpoint;
import org.apache.drill.exec.proto.GeneralRPCProtos.Ack;
import org.apache.drill.exec.proto.UserBitShared.QueryData;
import org.apache.drill.exec.proto.UserBitShared.QueryId;
import org.apache.drill.exec.proto.UserBitShared.QueryResult;
import org.apache.drill.exec.proto.UserBitShared.SaslMessage;
import org.apache.drill.exec.proto.UserBitShared.UserCredentials;
import org.apache.drill.exec.proto.UserProtos.BitToUserHandshake;
import org.apache.drill.exec.proto.UserProtos.CreatePreparedStatementResp;
import org.apache.drill.exec.proto.UserProtos.GetCatalogsResp;
import org.apache.drill.exec.proto.UserProtos.GetColumnsResp;
import org.apache.drill.exec.proto.UserProtos.GetQueryPlanFragments;
import org.apache.drill.exec.proto.UserProtos.GetSchemasResp;
import org.apache.drill.exec.proto.UserProtos.GetTablesResp;
import org.apache.drill.exec.proto.UserProtos.QueryPlanFragments;
import org.apache.drill.exec.proto.UserProtos.RpcEndpointInfos;
import org.apache.drill.exec.proto.UserProtos.RpcType;
import org.apache.drill.exec.proto.UserProtos.RunQuery;
import org.apache.drill.exec.proto.UserProtos.SaslSupport;
import org.apache.drill.exec.proto.UserProtos.UserToBitHandshake;
import org.apache.drill.exec.rpc.AbstractClientConnection;
import org.apache.drill.exec.rpc.Acks;
import org.apache.drill.exec.rpc.BasicClient;
import org.apache.drill.exec.rpc.security.AuthenticationOutcomeListener;
import org.apache.drill.exec.rpc.DrillRpcFuture;
import org.apache.drill.exec.rpc.OutOfMemoryHandler;
import org.apache.drill.exec.rpc.ProtobufLengthDecoder;
import org.apache.drill.exec.rpc.Response;
import org.apache.drill.exec.rpc.ResponseSender;
import org.apache.drill.exec.rpc.RpcConnectionHandler;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.rpc.InvalidConnectionInfoException;

import com.google.protobuf.MessageLite;
import org.apache.drill.exec.rpc.RpcOutcomeListener;
import org.apache.drill.exec.rpc.security.AuthenticatorFactory;
import org.apache.drill.exec.rpc.security.AuthenticatorProvider;
import org.apache.drill.exec.rpc.security.plain.PlainFactory;
import org.apache.drill.exec.rpc.security.ClientAuthenticatorProvider;
import org.apache.hadoop.security.UserGroupInformation;

import javax.annotation.Nullable;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import io.netty.channel.EventLoopGroup;
import org.slf4j.Logger;

public class UserClient extends BasicClient<RpcType, UserClient.UserToBitConnection,
    UserToBitHandshake, BitToUserHandshake> {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserClient.class);

  // resource is not closed for now
  private static final AuthenticatorProvider authProvider = new ClientAuthenticatorProvider();

  private final BufferAllocator allocator;

  private final QueryResultHandler queryResultHandler = new QueryResultHandler();
  private final String clientName;
  private RpcEndpointInfos serverInfos = null;

  private boolean supportComplexTypes = true;
  private DrillProperties properties;

  // these are used for authentication
  private volatile List<String> serverAuthMechanisms = null;
  private volatile boolean authComplete = true;

  public UserClient(String clientName, DrillConfig config, boolean supportComplexTypes,
      BufferAllocator allocator, EventLoopGroup eventLoopGroup, Executor eventExecutor) {
    super(
        UserRpcConfig.getMapping(config, eventExecutor),
        allocator.getAsByteBufAllocator(),
        eventLoopGroup,
        RpcType.HANDSHAKE,
        BitToUserHandshake.class,
        BitToUserHandshake.PARSER);
    this.clientName = clientName;
    this.allocator = allocator;
    this.supportComplexTypes = supportComplexTypes;
  }

  public RpcEndpointInfos getServerInfos() {
    return serverInfos;
  }

  public void submitQuery(UserResultsListener resultsListener, RunQuery query) {
    send(queryResultHandler.getWrappedListener(resultsListener), RpcType.RUN_QUERY, query, QueryId.class);
  }

  public CheckedFuture<Void, RpcException> connect(DrillbitEndpoint endpoint, DrillProperties parameters,
                                                   UserCredentials credentials) {
    final FutureHandler handler = new FutureHandler();
    UserToBitHandshake.Builder hsBuilder = UserToBitHandshake.newBuilder()
        .setRpcVersion(UserRpcConfig.RPC_VERSION)
        .setSupportListening(true)
        .setSupportComplexTypes(supportComplexTypes)
        .setSupportTimeout(true)
        .setCredentials(credentials)
        .setClientInfos(UserRpcUtils.getRpcEndpointInfos(clientName))
        .setSaslSupport(SaslSupport.SASL_AUTH)
        .setProperties(parameters.serializeForServer());
    this.properties = parameters;

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
    return serverAuthMechanisms != null;
  }

  /**
   * Returns a list of supported authentication mechanism. If called before {@link #connect connecting},
   * returns null. If called after {@link #connect connecting}, returns a list of supported mechanisms
   * iff authentication is required.
   *
   * @return list of supported authentication mechanisms
   */
  public List<String> getSupportedAuthenticationMechanisms() {
    return serverAuthMechanisms;
  }

  /**
   * Authenticate to the server asynchronously. Returns a future that {@link CheckedFuture#checkedGet results}
   * in null if authentication succeeds, or throws a {@link SaslException} with relevant message if
   * authentication fails.
   *
   * This method uses properties provided at {@link #connect connection time} and override them with the
   * given properties, if any.
   *
   * @param overrides parameter overrides
   * @return result of authentication request
   */
  public CheckedFuture<Void, SaslException> authenticate(final DrillProperties overrides) {
    if (serverAuthMechanisms == null) {
      throw new IllegalStateException("Server does not require authentication.");
    }
    properties.merge(overrides);
    final Map<String, String> propertiesMap = properties.stringPropertiesAsMap();

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

    final AuthenticatorFactory factory;
    try {
      factory = getAuthenticatorFactory();
    } catch (final SaslException e) {
      settableFuture.setException(e);
      return future;
    }

    final String mechanismName = factory.getSimpleName();
    logger.trace("Will try to login for {} mechanism.", mechanismName);
    final UserGroupInformation ugi;
    try {
      ugi = factory.createAndLoginUser(propertiesMap);
    } catch (final IOException e) {
      settableFuture.setException(e);
      return future;
    }

    logger.trace("Will try to authenticate to server using {} mechanism.", mechanismName);
    final SaslClient saslClient;
    try {
      saslClient = factory.createSaslClient(ugi, propertiesMap);
      connection.setSaslClient(saslClient);
    } catch (final SaslException e) {
      settableFuture.setException(e);
      return future;
    }

    if (saslClient == null) {
      settableFuture.setException(new SaslException("Cannot initiate authentication. Insufficient credentials?"));
      return future;
    }

    logger.trace("Initiating SASL exchange.");
    new AuthenticationOutcomeListener<>(this, connection, RpcType.SASL_MESSAGE, ugi, new RpcOutcomeListener<Void>(){

      @Override
      public void failed(RpcException ex) {
        settableFuture.setException(ex);
      }

      @Override
      public void success(Void value, ByteBuf buffer) {
        authComplete = true;
        settableFuture.set(null);
      }

      @Override
      public void interrupted(InterruptedException e) {
        settableFuture.setException(e);
      }
    }).initiate(mechanismName);
    return future;
  }

  private AuthenticatorFactory getAuthenticatorFactory() throws SaslException {
    // canonicalization
    final Set<String> supportedAuthMechanismSet = ImmutableSet.copyOf(
        Iterators.transform(serverAuthMechanisms.iterator(), new Function<String, String>() {
          @Nullable
          @Override
          public String apply(@Nullable String input) {
            return input == null ? null : input.toUpperCase();
          }
        }));

    // first, check if a certain mechanism must be used
    String authMechanism = properties.getProperty(DrillProperties.AUTH_MECHANISM);
    if (authMechanism != null) {
      if (!authProvider.containsFactory(authMechanism)) {
        throw new SaslException(String.format("Unknown mechanism: %s", authMechanism));
      }
      if (!supportedAuthMechanismSet.contains(authMechanism.toUpperCase())) {
        throw new SaslException(String.format("Server does not support authentication using: %s",
            authMechanism));
      }
      return authProvider.getAuthenticatorFactory(authMechanism);
    }

    // check if Kerberos is supported, and the service principal is provided
    if (supportedAuthMechanismSet.contains(KerberosUtil.KERBEROS_SIMPLE_NAME) &&
        properties.getProperty(DrillProperties.SERVICE_PRINCIPAL) != null) {
      return authProvider.getAuthenticatorFactory(KerberosUtil.KERBEROS_SIMPLE_NAME);
    }

    // check if username/password is supported, and username/password are provided
    if (supportedAuthMechanismSet.contains(PlainFactory.SIMPLE_NAME) &&
        properties.getProperty(DrillProperties.USER) != null &&
        !Strings.isNullOrEmpty(properties.getProperty(DrillProperties.PASSWORD))) {
      return authProvider.getAuthenticatorFactory(PlainFactory.SIMPLE_NAME);
    }

    throw new SaslException(String.format("Server requires authentication using %s. Insufficient credentials?",
        serverAuthMechanisms));
  }

  protected <SEND extends MessageLite, RECEIVE extends MessageLite>
  void send(RpcOutcomeListener<RECEIVE> listener, RpcType rpcType, SEND protobufBody, Class<RECEIVE> clazz,
            boolean allowInEventLoop, ByteBuf... dataBodies) {
    super.send(listener, connection, rpcType, protobufBody, clazz, allowInEventLoop, dataBodies);
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
  protected void handle(UserToBitConnection connection, int rpcType, ByteBuf pBody, ByteBuf dBody,
                        ResponseSender sender) throws RpcException {
    if (!authComplete) {
      // drop connection
      connection.close();

      // Remote should not be making any requests before authenticating.
      throw new RpcException(String.format("Request of type %d is not allowed without authentication. " +
                  "Remote on %s must authenticate before making requests. Connection dropped.",
              rpcType, connection.getRemoteAddress()));
    }
    switch (rpcType) {
    case RpcType.QUERY_DATA_VALUE:
      queryResultHandler.batchArrived(connection, pBody, dBody);
      sender.send(new Response(RpcType.ACK, Acks.OK));
      break;
    case RpcType.QUERY_RESULT_VALUE:
      queryResultHandler.resultArrived(pBody);
      sender.send(new Response(RpcType.ACK, Acks.OK));
      break;
    default:
      throw new RpcException(String.format("Unknown Rpc Type %d. ", rpcType));
    }
  }

  @Override
  protected void validateHandshake(BitToUserHandshake inbound) throws RpcException {
//    logger.debug("Handling handshake from bit to user. {}", inbound);
    if (inbound.hasServerInfos()) {
      serverInfos = inbound.getServerInfos();
    }
    switch (inbound.getStatus()) {
    case SUCCESS:
      break;
    case AUTH_REQUIRED: {
      authComplete = false;
      logger.trace("Server requires authentication before proceeding.");
      serverAuthMechanisms = ImmutableList.copyOf(inbound.getAuthenticationMechanismsList());
      break;
    }
    case AUTH_FAILED: // no longer a status returned by server
    case RPC_VERSION_MISMATCH:
    case UNKNOWN_FAILURE:
      final String errMsg = String.format("Status: %s, Error Id: %s, Error message: %s",
          inbound.getStatus(), inbound.getErrorId(), inbound.getErrorMessage());
      logger.error(errMsg);
      throw new InvalidConnectionInfoException(errMsg);
    }
  }

  @Override
  public UserToBitConnection initRemoteConnection(SocketChannel channel) {
    super.initRemoteConnection(channel);
    return new UserToBitConnection(channel);
  }

  public class UserToBitConnection extends AbstractClientConnection {

    UserToBitConnection(SocketChannel channel) {
      super(channel, "user client");
    }

    @Override
    public BufferAllocator getAllocator() {
      return allocator;
    }

    @Override
    protected Logger getLogger() {
      return logger;
    }
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
      implements RpcConnectionHandler<UserToBitConnection>, DrillRpcFuture<Void> {

    protected FutureHandler() {
      super(SettableFuture.<Void>create());
    }

    @Override
    public void connectionSucceeded(UserToBitConnection connection) {
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
