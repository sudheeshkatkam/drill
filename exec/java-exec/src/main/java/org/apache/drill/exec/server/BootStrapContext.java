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
package org.apache.drill.exec.server;

import io.netty.channel.EventLoopGroup;

import java.io.Closeable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.memory.BufferAllocator;
import org.apache.drill.exec.memory.TopLevelAllocator;
import org.apache.drill.exec.metrics.DrillMetrics;
import org.apache.drill.exec.rpc.NamedThreadFactory;
import org.apache.drill.exec.rpc.TransportCheck;

import com.codahale.metrics.MetricRegistry;

// TODO:  Doc.  What kind of context?  (For what aspects, RPC?  What kind of data?)
public class BootStrapContext implements Closeable{
  static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BootStrapContext.class);

  private final DrillConfig config;
  private final EventLoopGroup loop;
  private final EventLoopGroup loop2;
  private final MetricRegistry metrics;
  private final BufferAllocator allocator;
  private final ExecutorService executor;


  public BootStrapContext(DrillConfig config) {
    super();
    this.config = config;
    this.loop = TransportCheck.createEventLoopGroup(config.getInt(ExecConstants.BIT_SERVER_RPC_THREADS), "BitServer-");
    this.loop2 = TransportCheck.createEventLoopGroup(config.getInt(ExecConstants.BIT_SERVER_RPC_THREADS), "BitClient-");
    this.metrics = DrillMetrics.getInstance();
    this.allocator = new TopLevelAllocator(config);
    /*
     * TODO (Chris comments) This executor isn't bounded in any way and could create an arbitrarily large number of
     * threads, possibly choking the machine. We should really put an upper bound on the number of threads that can be
     * created. Ideally, this might be computed based on the number of cores or some similar metric; ThreadPoolExecutor
     * can impose an upper bound, and might be a better choice.
     *
     * (Jacques feedback) However, this should be really be bounded elsewhere. If bounded here, we run a high likelihood
     * of creating distributed deadlocks across the machines.
     */
    this.executor = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 60L, TimeUnit.SECONDS,
        new SynchronousQueue<Runnable>(),
        new NamedThreadFactory("drill-executor-")) {
      @Override
      protected void afterExecute(final Runnable r, final Throwable t) {
        if (t != null) {
          logger.error("{}.run() leaked an exception.", r.getClass().getName(), t);
        }
        super.afterExecute(r, t);
      }
    };
  }

  public ExecutorService getExecutor() {
    return executor;
  }

  public DrillConfig getConfig() {
    return config;
  }

  public EventLoopGroup getBitLoopGroup() {
    return loop;
  }

  public EventLoopGroup getBitClientLoopGroup() {
    return loop2;
  }

  public MetricRegistry getMetrics() {
    return metrics;
  }

  public BufferAllocator getAllocator() {
    return allocator;
  }

  public void close() {
    DrillMetrics.resetMetrics();
    loop.shutdownGracefully();
    allocator.close();

    try {
      executor.awaitTermination(1, TimeUnit.SECONDS);
    } catch (final InterruptedException e) {
      logger.warn("Executor interrupted while awaiting termination");

      // Preserve evidence that the interruption occurred so that code higher up on the call stack can learn of the
      // interruption and respond to it if it wants to.
      Thread.currentThread().interrupt();
    }

  }

}
