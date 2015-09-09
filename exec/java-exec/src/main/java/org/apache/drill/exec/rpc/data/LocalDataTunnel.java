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

import io.netty.buffer.DrillBuf;
import io.netty.channel.EventLoop;

import java.util.concurrent.Semaphore;

import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.proto.BitData.FragmentRecordBatch;
import org.apache.drill.exec.proto.GeneralRPCProtos.Ack;
import org.apache.drill.exec.record.FragmentWritableBatch;
import org.apache.drill.exec.rpc.DrillRpcFuture;
import org.apache.drill.exec.rpc.DrillRpcFutureImpl;
import org.apache.drill.exec.rpc.Response;
import org.apache.drill.exec.rpc.ResponseSender;
import org.apache.drill.exec.rpc.RpcException;
import org.apache.drill.exec.rpc.RpcOutcomeListener;
import org.apache.drill.exec.testing.ControlsInjector;
import org.apache.drill.exec.testing.ExecutionControls;
import org.slf4j.Logger;

public class LocalDataTunnel implements DataTunnel {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LocalDataTunnel.class);

  private final DataServer dataServer;
  private final EventLoop eventLoop;
  private final Semaphore sendingSemaphore = new Semaphore(8);

  private boolean isInjectionControlSet;
  private ControlsInjector testInjector;
  private ExecutionControls testControls;
  private Logger testLogger;

  public LocalDataTunnel(DataServer dataServer, EventLoop eventLoop) {
    super();
    this.dataServer = dataServer;
    this.eventLoop = eventLoop;
  }

  @Override
  public void setTestInjectionControls(final ControlsInjector testInjector,
      final ExecutionControls testControls, final Logger testLogger) {
    isInjectionControlSet = true;
    this.testInjector = testInjector;
    this.testControls = testControls;
    this.testLogger = testLogger;
  }

  @Override
  public void sendRecordBatch(RpcOutcomeListener<Ack> outcomeListener, FragmentWritableBatch batch) {

    final DrillBuf buf;
    if(batch.getBuffers().length == 0){
      buf = null;
    }else{
      int len = 0;
      for (DrillBuf b : batch.getBuffers()) {
        len += b.readableBytes();
      }

      buf = dataServer.getAllocator().buffer(len);

      // TODO: Avoid this extra copy. Unfortunately, the DrillBuf abstraction doesn't currently support composite
      // buffers so we have to consolidate to traverse that path.
      for(DrillBuf b : batch.getBuffers()){
        buf.writeBytes(b);
        b.release();
      }

    }
    try {

      if (isInjectionControlSet) {
        // Wait for interruption if set. Used to simulate the fragment interruption while the fragment is waiting for
        // semaphore acquire. We expect the
        testInjector.injectInterruptiblePause(testControls, "data-tunnel-send-batch-wait-for-interrupt", testLogger);
      }

      sendingSemaphore.acquire();
      eventLoop.submit(new SendBatchRunnable(batch.getHeader(), buf == null ? null : buf.slice(), outcomeListener));
    } catch (final InterruptedException e) {
      outcomeListener.failed(new RpcException("Interrupted while trying to get sending semaphore.", e));

      // Preserve evidence that the interruption occurred so that code higher up on the call stack can learn of the
      // interruption and respond to it if it wants to.
      Thread.currentThread().interrupt();
    }
  }

  @Override
  public DrillRpcFuture<Ack> sendRecordBatch(FragmentContext context, FragmentWritableBatch batch) {
    DrillRpcFutureImpl<Ack> future = new DrillRpcFutureImpl<>();
    sendRecordBatch(future, batch);
    return future;
  }

  static enum State {
    SENDING, RELEASED, ACKD
  };

  private class SendBatchRunnable implements Runnable, ResponseSender {

    private State state = State.SENDING;
    private final FragmentRecordBatch fragRecordBatch;
    private final DrillBuf body;
    private final RpcOutcomeListener<Ack> outcomeListener;
    private Ack ack;;

    public SendBatchRunnable(FragmentRecordBatch fragRecordBatch, DrillBuf body, RpcOutcomeListener<Ack> outcomeListener) {
      super();
      this.fragRecordBatch = fragRecordBatch;
      this.body = body;
      this.outcomeListener = outcomeListener;
    }

    @Override
    public void run() {
      try {
        dataServer.receiveBatch(fragRecordBatch, body, this);
      } catch (Exception e) {
        logger.error("Failure while sending local batch.", e);
      } finally {
        if (body != null) {
          body.release();
        }
        sendingSemaphore.release();
      }

      synchronized (this) {

        if (state == State.ACKD) {
          // if ack arrived, send success.
          outcomeListener.success(ack, null);
        } else {
          // otherwise, wait for ack.
          state = State.RELEASED;
        }
      }
    }

    @Override
    public void send(Response r) {
      synchronized (this) {

        // if release happened, send info.
        if (state == State.RELEASED) {
          outcomeListener.success((Ack) r.pBody, null);

          // if not, wait until release happened
        } else {
          this.ack = (Ack) r.pBody;
          state = State.ACKD;
        }
      }
    }


  }


}
