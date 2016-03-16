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
package org.apache.drill.exec.record;

import io.netty.buffer.DrillBuf;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.drill.exec.proto.BitData.FragmentRecordBatch;
import org.apache.drill.exec.rpc.data.AckSender;

public class RawFragmentBatch {
  //private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RawFragmentBatch.class);
  public static final RawFragmentBatch NONE;

  static {
    final FragmentRecordBatch header = FragmentRecordBatch.newBuilder()
        .setReceivingMajorFragmentId(-1)
        .setSendingMajorFragmentId(-1)
        .build();
    NONE = new RawFragmentBatch(header, null, null);
  }

  private final FragmentRecordBatch header;
  private final DrillBuf body;
  private final AckSender sender;
  private final AtomicBoolean ackSent = new AtomicBoolean(false);

  public RawFragmentBatch(FragmentRecordBatch header, DrillBuf body, AckSender sender) {
    this.header = header;
    this.sender = sender;
    this.body = body;
    if (body != null) {
      body.retain(1);
    }
  }

  public boolean isNone() {
    return equals(NONE);
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj instanceof RawFragmentBatch) {
      final RawFragmentBatch other = RawFragmentBatch.class.cast(obj);
      return Objects.equals(header, other.header) && Objects.equals(body, other.body)
          && Objects.equals(sender, other.sender) && Objects.equals(ackSent, other.ackSent);
    }
    return false;
  }

  public FragmentRecordBatch getHeader() {
    return header;
  }

  public DrillBuf getBody() {
    return body;
  }

  @Override
  public String toString() {
    return "RawFragmentBatch [header=" + header + ", body=" + body + "]";
  }

  public void release() {
    if (body != null) {
      body.release(1);
    }
  }

  public AckSender getSender() {
    return sender;
  }

  public synchronized void sendOk() {
    if (sender != null && ackSent.compareAndSet(false, true)) {
      sender.sendOk();
    }
  }

  public long getByteCount() {
    return body == null ? 0 : body.readableBytes();
  }

  public boolean isAckSent() {
    return ackSent.get();
  }
}
