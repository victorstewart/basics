// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

class RingMultiplexer : virtual public RingInterface, virtual public RingLifecycle {
public:
};

class RingDispatcher : public RingMultiplexer { // allows us to build trees
private:

  bytell_hash_map<void *, RingInterface *> multiplexees; // this is a top level direct mapping of objects to end consumers
  bytell_hash_set<RingMultiplexer *> multiplexers;

  template <typename Lambda>
  void distributeContains(void *object, Lambda&& lambda)
  {
    if (auto it = multiplexees.find(object); it != multiplexees.end())
    {
      lambda(it->second);
    }
    else
    {
      (void)object;
    }
  }

public:

  static inline RingDispatcher *dispatcher = nullptr; // auto initialzes itself

  static void installMultiplexer(RingMultiplexer *multiplexer)
  {
    if (dispatcher == nullptr)
    {
      (void)multiplexer;
      std::abort();
    }

    dispatcher->multiplexers.insert(multiplexer);
  }

  static void installMultiplexee(void *object, RingInterface *target)
  {
    if (dispatcher == nullptr)
    {
      (void)object;
      (void)target;
      std::abort();
    }

    dispatcher->multiplexees.insert_or_assign(object, target);
  }

  static void eraseMultiplexee(void *object)
  {
    if (dispatcher == nullptr)
    {
      (void)object;
      std::abort();
    }

    dispatcher->multiplexees.erase(object);
  }

  void beforeRing(void)
  {
    for (RingLifecycle *multiplexer : multiplexers)
    {
      multiplexer->beforeRing();
    }
  }

  void afterRing(void)
  {
    for (RingLifecycle *multiplexer : multiplexers)
    {
      multiplexer->afterRing();
    }
  }

  bool signalHandler(const struct signalfd_siginfo& sigInfo)
  {
    bool returnFalse = false;

    for (RingLifecycle *multiplexer : multiplexers)
    {
      if (multiplexer->signalHandler(sigInfo) == false)
      {
        returnFalse = true;
      }
    }

    return (returnFalse ? false : true);
  }

  void waitidHandler(void *waiter)
  {
    distributeContains(waiter, [&](RingInterface *interface) {
      interface->waitidHandler(waiter);
    });
  }

  void timeoutHandler(TimeoutPacket *packet, int result)
  {
    if (packet && packet->dispatcher)
    {
      packet->dispatcher->dispatchTimeout(packet);
      return;
    }

    if (packet == nullptr)
    {
      return;
    }

    distributeContains(packet->originator, [&](RingInterface *interface) {
      interface->timeoutHandler(packet, result);
    });
  }

  void acceptHandler(void *socket, int fslot)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->acceptHandler(socket, fslot);
    });
  }

  void acceptMultishotHandler(void *socket, int fslot, bool mustRearm)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->acceptMultishotHandler(socket, fslot, mustRearm);
    });
  }

  void closeHandler(void *socket)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->closeHandler(socket);
    });
  }

  void connectHandler(void *socket, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->connectHandler(socket, result);
    });
  }

  void tcpFastOpenHandler(void *socket, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->tcpFastOpenHandler(socket, result);
    });
  }

  void recvHandler(void *socket, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->recvHandler(socket, result);
    });
  }

  void recvmsgHandler(void *socket, struct msghdr *msg, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->recvmsgHandler(socket, msg, result);
    });
  }

  void recvmsgMultishotHandler(void *socket, struct io_uring_recvmsg_out *message, int result, bool mustRefresh)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->recvmsgMultishotHandler(socket, message, result, mustRefresh);
    });
  }

  void sendHandler(void *socket, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->sendHandler(socket, result);
    });
  }

  void sendmsgHandler(void *socket, struct msghdr *msg, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->sendmsgHandler(socket, msg, result);
    });
  }

  void shutdownHandler(void *socket)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->shutdownHandler(socket);
    });
  }

  void pollHandler(void *socket, int result)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->pollHandler(socket, result);
    });
  }

  void restartMultishotRecvMsgOn(void *socket)
  {
    distributeContains(socket, [&](RingInterface *interface) {
      interface->restartMultishotRecvMsgOn(socket);
    });
  }

  RingDispatcher()
  {
    dispatcher = this;
    Ring::interfacer = this;
    Ring::lifecycler = this;
  }
};

inline RingDispatcher globalRingDispatcher;
