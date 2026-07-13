// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdlib>
#include <sys/signalfd.h>
#include <sys/socket.h>

#include <networking/includes.h>
#include <networking/time.h>

struct io_uring_recvmsg_out;

class RingLifecycle {
public:

  virtual void beforeRing(void) {}
  virtual void afterRing(void) {}
  virtual bool signalHandler(const struct signalfd_siginfo& sigInfo)
  {
    return true;
  }
};

class RingInterface {
public:

  virtual void acceptMultishotHandler(void *socket, int fslot, bool mustRearm) {}
  virtual void acceptHandler(void *socket, int fslot) {}

  virtual void closeHandler(void *socket) {}

  virtual void ringMessageHandler(int ringFD, String *container) {}

  virtual void connectHandler(void *socket, int result) {}

  virtual void tcpFastOpenHandler(void *socket, int result) {}
  virtual void recvHandler(void *socket, int result) {}
  virtual void recvmsgHandler(void *socket, struct msghdr *msg, int result) {}
  virtual void recvmsgMultishotHandler(void *socket, struct io_uring_recvmsg_out *message, int result, bool mustRearm) {}
  virtual void sendHandler(void *socket, int result) {}
  virtual void sendmsgHandler(void *socket, struct msghdr *msg, int result) {}

  virtual void shutdownHandler(void *socket) {}

  virtual void pollHandler(void *socket, int result) {}
  // This is the terminal lifetime acknowledgement for a raw-fd poll. The
  // owner may release the watcher before returning from this callback.
  virtual void rawFDPollHandler(void *owner, uint64_t generation, uint64_t ticket, int result) {}

  virtual void waitidHandler(void *waiter) {}
  virtual void waitidResultHandler(void *waiter, int result)
  {
    if (result < 0)
    {
      std::abort();
    }
    waitidHandler(waiter);
  }

  virtual void restartMultishotRecvMsgOn(void *socket) {}
  virtual void timeoutHandler(TimeoutPacket *packet, int result) {}
  virtual void timeoutMultishotHandler(TimeoutPacket *packet, int result) {}

  virtual void fileWriteHandler(int fslot, int result) {}
  virtual void fsyncHandler(int fslot, int result) {}
  virtual void completionBatchHandler(uint32_t count) { (void)count; }
};

inline thread_local RingInterface *ringInterfacer = nullptr;
inline thread_local RingLifecycle *ringLifecycler = nullptr;
