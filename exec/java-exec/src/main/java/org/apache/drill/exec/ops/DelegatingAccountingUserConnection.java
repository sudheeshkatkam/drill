/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.ops;

import com.google.common.base.Preconditions;
import org.apache.drill.exec.physical.impl.materialize.QueryWritableBatch;
import org.apache.drill.exec.proto.GeneralRPCProtos;
import org.apache.drill.exec.rpc.CompositeRpcOutcomeListener;
import org.apache.drill.exec.rpc.RpcOutcomeListener;

public class DelegatingAccountingUserConnection implements AccountingUserConnection {
  private final AccountingUserConnection delegate;
  private final RpcOutcomeListener<GeneralRPCProtos.Ack> listener;

  public DelegatingAccountingUserConnection(final AccountingUserConnection delegate, final RpcOutcomeListener<GeneralRPCProtos.Ack> listener) {
    this.delegate = Preconditions.checkNotNull(delegate, "delegate is required");
    this.listener = CompositeRpcOutcomeListener.of(delegate.getStatusHandler(), listener);
  }

  @Override
  public boolean isSendingBufferAvailable() {
    return delegate.isSendingBufferAvailable();
  }

  @Override
  public RpcOutcomeListener<GeneralRPCProtos.Ack> getStatusHandler() {
    return listener;
  }

  @Override
  public void sendData(final QueryWritableBatch batch) {
    sendData(getStatusHandler(), batch);
  }

  @Override
  public void sendData(final RpcOutcomeListener<GeneralRPCProtos.Ack> listener, final QueryWritableBatch batch) {
    delegate.sendData(listener, batch);
  }


  public static DelegatingAccountingUserConnection of(final AccountingUserConnection delegate,
                                                  final RpcOutcomeListener<GeneralRPCProtos.Ack> listener) {
    return new DelegatingAccountingUserConnection(delegate, listener);
  }
}
