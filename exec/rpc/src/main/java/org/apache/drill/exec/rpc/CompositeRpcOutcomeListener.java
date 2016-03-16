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
package org.apache.drill.exec.rpc;

import java.util.Arrays;
import java.util.Collection;

import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CompositeRpcOutcomeListener<T> implements RpcOutcomeListener<T> {
  private static final Logger logger = LoggerFactory.getLogger(CompositeRpcOutcomeListener.class);

  private final Collection<RpcOutcomeListener<T>> delegates;

  public CompositeRpcOutcomeListener(final Collection<RpcOutcomeListener<T>> delegates) {
    this.delegates = Preconditions.checkNotNull(delegates, "delegate listeners cannot be null.");
  }

  @Override
  public void failed(final RpcException cause) {
    for (final RpcOutcomeListener<T> listener:delegates) {
      try {
        listener.failed(cause);
      } catch (final Exception ex) {
        logger.warn("delegate listener error", ex);
      }
    }
  }

  @Override
  public void success(final T value, final ByteBuf buffer) {
    for (final RpcOutcomeListener<T> listener:delegates) {
      try {
        listener.success(value, buffer);
      } catch (final Exception ex) {
        logger.warn("delegate listener error", ex);
      }
    }
  }

  @Override
  public void interrupted(final InterruptedException cause) {
    for (final RpcOutcomeListener<T> listener:delegates) {
      try {
        listener.interrupted(cause);
      } catch (final Exception ex) {
        logger.warn("delegate listener error", ex);
      }
    }
  }

  public static <T> CompositeRpcOutcomeListener<T> of(final RpcOutcomeListener<T>... listeners) {
    for (final RpcOutcomeListener listener:listeners) {
      Preconditions.checkNotNull(listener, "listener cannot be null");
    }

    return new CompositeRpcOutcomeListener<>(Arrays.asList(listeners));
  }
}
