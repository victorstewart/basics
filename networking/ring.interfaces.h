// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/includes.h>
#include <networking/time.h>
#include <sys/signalfd.h>
#include <sys/socket.h>

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

  virtual void waitidHandler(void *waiter) {}

  virtual void restartMultishotRecvMsgOn(void *socket) {}
  virtual void timeoutHandler(TimeoutPacket *packet, int result) {}
  virtual void timeoutMultishotHandler(TimeoutPacket *packet, int result) {}

  virtual void fileWriteHandler(int fslot, int result) {}
  virtual void fsyncHandler(int fslot, int result) {}
};

inline thread_local RingInterface *ringInterfacer = nullptr;
inline thread_local RingLifecycle *ringLifecycler = nullptr;
