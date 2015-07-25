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
package org.apache.drill.exec.rpc.data;

import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.proto.GeneralRPCProtos.Ack;
import org.apache.drill.exec.record.FragmentWritableBatch;
import org.apache.drill.exec.rpc.DrillRpcFuture;
import org.apache.drill.exec.rpc.RpcOutcomeListener;
import org.apache.drill.exec.testing.ControlsInjector;
import org.apache.drill.exec.testing.ExecutionControls;
import org.slf4j.Logger;

public interface DataTunnel {
  static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DataTunnel.class);

  public void sendRecordBatch(RpcOutcomeListener<Ack> outcomeListener, FragmentWritableBatch batch);

  public DrillRpcFuture<Ack> sendRecordBatch(FragmentContext context, FragmentWritableBatch batch);

  /**
   * Once a DataTunnel is created, clients of DataTunnel can pass injection controls to enable setting injections at
   * pre-defined places. Currently following injection sites are available.
   *
   * 1. In method {@link #sendRecordBatch(RpcOutcomeListener, FragmentWritableBatch)}, an interruptible pause injection
   * is available before acquiring the sending slot. Site name is: "data-tunnel-send-batch-wait-for-interrupt"
   *
   * @param testInjector
   * @param testControls
   * @param testLogger
   */
  public void setTestInjectionControls(
      final ControlsInjector testInjector,
      final ExecutionControls testControls,
      final Logger testLogger);
}
