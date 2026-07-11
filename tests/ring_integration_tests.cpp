// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include "macros/bytes.h"
#include "services/filesystem.h"
#include "services/numbers.h"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "services/crypto.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/msg.h"
#include "networking/message.h"
#include "networking/pool.h"
#include "networking/stream.h"
#include "networking/ring.h"
#include "networking/ringlet.h"

namespace {

static constexpr int kDynamicFixedSlotBegin = 5;

struct WaitableSigChldScope {
  struct sigaction previous = {};
  bool restore = false;

  WaitableSigChldScope()
  {
    if (sigaction(SIGCHLD, nullptr, &previous) != 0)
    {
      return;
    }

    if (previous.sa_handler == SIG_IGN)
    {
      struct sigaction waitable = {};
      sigemptyset(&waitable.sa_mask);
      waitable.sa_handler = SIG_DFL;
      sigaction(SIGCHLD, &waitable, nullptr);
      restore = true;
    }
  }

  ~WaitableSigChldScope()
  {
    if (restore)
    {
      sigaction(SIGCHLD, &previous, nullptr);
    }
  }
};

static String makeQueuedServiceLookupMessage(uint64_t requestID, float lat, float lon)
{
  String message;
  uint32_t headerOffset = Message::appendHeader(message, uint16_t(2));
  Message::append(message, requestID);
  Message::append(message, lat);
  Message::append(message, lon);
  Message::finish(message, headerOffset);
  return message;
}

static uint16_t boundPortForFD(int fd)
{
  sockaddr_in address = {};
  socklen_t addressLength = sizeof(address);
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&address), &addressLength) != 0)
  {
    return 0;
  }

  return ntohs(address.sin_port);
}

static void configureLoopbackListener(TCPSocket& socket)
{
  socket.setIPVersion(AF_INET);
  socket.setSaddr("127.0.0.1"_ctv, 0);
  socket.bindThenListen();
}

static bool ringAndRingletSupported()
{
  pid_t child = fork();
  if (child == 0)
  {
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;

    Ring::createRing(32, 32, 8, 2, -1, -1, 8);
    Ring::shutdownForExec();

    Ringlet ringlet(8, 8);
    (void)ringlet;

    _exit(0);
  }

  if (child < 0)
  {
    return false;
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0)
  {
    return false;
  }

  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void isolatedWorkerSignalHandler(int)
{}

static void testIsolatedWorkerRingPreservesProcessIntegration(TestSuite& suite)
{
  WaitableSigChldScope waitableSigChld;
  pid_t child = fork();
  if (child == 0)
  {
    struct Lifecycle final : RingLifecycle
    {
      bool before = false;
      bool after = false;
      void beforeRing(void) override { before = true; }
      void afterRing(void) override { after = true; }
    } lifecycle;

    struct sigaction action = {};
    sigemptyset(&action.sa_mask);
    action.sa_handler = isolatedWorkerSignalHandler;
    if (sigaction(SIGTERM, &action, nullptr) != 0)
    {
      _exit(2);
    }

    sigset_t beforeMask = {};
    sigprocmask(SIG_SETMASK, nullptr, &beforeMask);
    Ring::interfacer = nullptr;
    Ring::lifecycler = &lifecycle;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(32, 32, 8, 2, -1, -1, 8, false,
                     RingProcessIntegration::isolatedWorker);

    struct sigaction afterAction = {};
    sigset_t afterMask = {};
    sigaction(SIGTERM, nullptr, &afterAction);
    sigprocmask(SIG_SETMASK, nullptr, &afterMask);
    bool preserved = afterAction.sa_handler == isolatedWorkerSignalHandler &&
                     sigismember(&beforeMask, SIGTERM) == sigismember(&afterMask, SIGTERM) &&
                     lifecycle.before == false && lifecycle.after == false;
    Ring::shutdownForExec();
    _exit(preserved ? 0 : 3);
  }

  EXPECT_TRUE(suite, child >= 0);
  if (child < 0)
  {
    return;
  }
  int status = 0;
  EXPECT_EQ(suite, waitpid(child, &status, 0), child);
  EXPECT_TRUE(suite, WIFEXITED(status));
  EXPECT_EQ(suite, WEXITSTATUS(status), 0);
}

static void testRingControlStateIsThreadLocal(TestSuite& suite)
{
  Ring::exit = false;
  Ring::shuttingDown = false;
  bool firstThreadIsolated = false;
  bool secondThreadIsolated = false;
  std::thread first([&](void) -> void {
    Ring::exit = true;
    firstThreadIsolated = Ring::shuttingDown == false;
  });
  std::thread second([&](void) -> void {
    Ring::shuttingDown = true;
    secondThreadIsolated = Ring::exit == false;
  });
  first.join();
  second.join();
  EXPECT_TRUE(suite, firstThreadIsolated && secondThreadIsolated &&
                         Ring::exit == false && Ring::shuttingDown == false);
}

struct RingScenarioInterface : RingInterface {
  TestSuite *suite = nullptr;

  TCPSocket listener;
  TCPSocket multishotListener;
  TCPStream acceptedStream;
  TCPStream timedOutStream;

  TimeoutPacket deadline;

  bool accepted = false;
  bool received = false;
  bool sent = false;
  bool recvTimedOut = false;
  bool acceptMultishotReceived = false;
  bool acceptMultishotMustRearm = false;
  bool acceptedStreamClosed = false;
  bool listenerClosed = false;
  bool timedOutStreamClosed = false;
  bool multishotListenerClosed = false;
  bool deadlineFired = false;

  String receivedPayload;

  explicit RingScenarioInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(1000);
    configureLoopbackListener(listener);
    configureLoopbackListener(multishotListener);
  }

  bool complete() const
  {
    return accepted &&
           received &&
           sent &&
           recvTimedOut &&
           acceptMultishotReceived &&
           acceptedStreamClosed &&
           listenerClosed &&
           timedOutStreamClosed &&
           multishotListenerClosed;
  }

  void maybeStop()
  {
    if (complete())
    {
      Ring::exit = true;
    }
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket != &listener)
    {
      return;
    }

    accepted = true;
    suite->expectTrue(fslot >= 0, "accept fixed-file slot is valid", __FILE__, __LINE__);
    suite->expectTrue(fslot >= kDynamicFixedSlotBegin, "accept fixed-file slot stays out of reserved range", __FILE__, __LINE__);

    acceptedStream.fslot = fslot;
    acceptedStream.isFixedFile = true;
    suite->expectTrue(acceptedStream.rBuffer.reserve(64), "acceptedStream.rBuffer.reserve(64)", __FILE__, __LINE__);
    Ring::queueRecv(&acceptedStream);
  }

  void acceptMultishotHandler(void *socket, int fslot, bool mustRearm) override
  {
    if (socket != &multishotListener || acceptMultishotReceived)
    {
      return;
    }

    acceptMultishotReceived = true;
    acceptMultishotMustRearm = mustRearm;
    suite->expectTrue(fslot >= 0, "acceptMultishot fixed-file slot is valid", __FILE__, __LINE__);
    suite->expectTrue(fslot >= kDynamicFixedSlotBegin, "acceptMultishot fixed-file slot stays out of reserved range", __FILE__, __LINE__);

    timedOutStream.fslot = fslot;
    timedOutStream.isFixedFile = true;
    suite->expectTrue(timedOutStream.rBuffer.reserve(64), "timedOutStream.rBuffer.reserve(64)", __FILE__, __LINE__);
    Ring::queueRecv(&timedOutStream, 40);
  }

  void recvHandler(void *socket, int result) override
  {
    if (socket == &acceptedStream)
    {
      acceptedStream.pendingRecv = false;

      suite->expectEqual(result, 4, "result", "4", __FILE__, __LINE__);
      if (result > 0)
      {
        acceptedStream.rBuffer.advance(result);
        receivedPayload.assign(acceptedStream.rBuffer.pHead(), acceptedStream.rBuffer.outstandingBytes());
        received = true;
        acceptedStream.wBuffer.append("pong", 4);
        Ring::queueSend(&acceptedStream);
      }
      else
      {
        Ring::exit = true;
      }
      return;
    }

    if (socket == &timedOutStream)
    {
      timedOutStream.pendingRecv = false;
      suite->expectEqual(result, -ETIME, "result", "-ETIME", __FILE__, __LINE__);
      recvTimedOut = true;
      Ring::queueClose(&timedOutStream);
      Ring::queueClose(&multishotListener);
    }
  }

  void sendHandler(void *socket, int result) override
  {
    if (socket != &acceptedStream)
    {
      return;
    }

    acceptedStream.pendingSend = false;
    acceptedStream.pendingSendBytes = 0;
    acceptedStream.wBuffer.noteSendCompleted();

    suite->expectEqual(result, 4, "result", "4", __FILE__, __LINE__);
    if (result > 0)
    {
      acceptedStream.wBuffer.consume(result, true);
      sent = true;
      Ring::queueClose(&acceptedStream);
      Ring::queueClose(&listener);
    }
    else
    {
      Ring::exit = true;
    }
  }

  void closeHandler(void *socket) override
  {
    if (socket == &acceptedStream)
    {
      acceptedStreamClosed = true;
    }
    else if (socket == &listener)
    {
      listenerClosed = true;
    }
    else if (socket == &timedOutStream)
    {
      timedOutStreamClosed = true;
    }
    else if (socket == &multishotListener)
    {
      multishotListenerClosed = true;
    }

    maybeStop();
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    deadlineFired = true;
    suite->expectTrue(false, "ring scenario completed before deadline timeout", __FILE__, __LINE__);
    Ring::exit = true;
  }
};

struct DuplicateCloseInterface : RingInterface {
  TestSuite *suite = nullptr;
  UnixSocket socket;
  TimeoutPacket deadline;
  int closeCalls = 0;
  bool deadlineFired = false;

  explicit DuplicateCloseInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(1000);
  }

  void closeHandler(void *closedSocket) override
  {
    if (closedSocket != &socket)
    {
      return;
    }

    closeCalls += 1;
    Ring::exit = true;
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    deadlineFired = true;
    suite->expectEqual(result, -ETIME, "result", "-ETIME", __FILE__, __LINE__);
    Ring::exit = true;
  }
};

struct AcceptCloseRawInterface : RingInterface {
  TestSuite *suite = nullptr;
  TCPSocket listener;
  TimeoutPacket deadline;
  int acceptCalls = 0;
  int firstSlot = -1;
  int secondSlot = -1;
  bool listenerClosed = false;
  bool deadlineFired = false;

  explicit AcceptCloseRawInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(1000);
    configureLoopbackListener(listener);
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket != &listener)
    {
      return;
    }

    suite->expectTrue(fslot >= 0, "raw-close accept fixed-file slot is valid", __FILE__, __LINE__);
    suite->expectTrue(fslot >= kDynamicFixedSlotBegin, "raw-close accept fixed-file slot stays out of reserved range", __FILE__, __LINE__);

    if (acceptCalls == 0)
    {
      firstSlot = fslot;
      acceptCalls += 1;
      Ring::queueCloseRaw(fslot);
      Ring::queueAccept(&listener);
      return;
    }

    secondSlot = fslot;
    acceptCalls += 1;
    Ring::queueCloseRaw(fslot);
    Ring::queueClose(&listener);
  }

  void closeHandler(void *closedSocket) override
  {
    if (closedSocket != &listener)
    {
      return;
    }

    listenerClosed = true;
    Ring::exit = true;
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    deadlineFired = true;
    suite->expectEqual(result, -ETIME, "result", "-ETIME", __FILE__, __LINE__);
    Ring::exit = true;
  }
};

struct QueuedSendDrainInterface : RingInterface {
  TestSuite *suite = nullptr;
  TCPSocket listener;
  AegisStream acceptedStream;
  TimeoutPacket deadline;

  uint128_t secret = (uint128_t(0x13579bdf2468ace0ULL) << 64) | uint128_t(0x0fedcba987654321ULL);
  uint64_t service = 0x0123456789abcdefULL;
  uint64_t pairingHash = 0;
  uint64_t expectedBytes = 0;
  Vector<int> sendResults;
  std::vector<String> plaintexts;

  bool accepted = false;
  bool streamClosed = false;
  bool listenerClosed = false;
  bool deadlineFired = false;

  explicit QueuedSendDrainInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(1000);
    configureLoopbackListener(listener);
    pairingHash = AegisStream::generateSecretServiceHash(secret, service);
  }

  void maybeStop()
  {
    if (streamClosed && listenerClosed)
    {
      Ring::exit = true;
    }
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket != &listener)
    {
      return;
    }

    accepted = true;
    suite->expectTrue(fslot >= 0, "queued-send accept fixed-file slot is valid", __FILE__, __LINE__);
    suite->expectTrue(fslot >= kDynamicFixedSlotBegin, "queued-send accept fixed-file slot stays out of reserved range", __FILE__, __LINE__);

    acceptedStream.secret = secret;
    acceptedStream.service = service;
    acceptedStream.fslot = fslot;
    acceptedStream.isFixedFile = true;
    acceptedStream.wBuffer.append(pairingHash);
    expectedBytes = sizeof(pairingHash);
    Ring::queueSend(&acceptedStream);

    for (uint64_t requestID = 1; requestID <= 32; ++requestID)
    {
      String plaintext = makeQueuedServiceLookupMessage(requestID, 40.718266f, -74.00782f);
      plaintexts.push_back(plaintext);
      const uint32_t encryptedFrameBytes = uint32_t(((40u + uint32_t(plaintext.size()) + 15u) / 16u) * 16u);
      expectedBytes += encryptedFrameBytes;
      acceptedStream.encrypt(plaintext);
    }
  }

  void sendHandler(void *socket, int result) override
  {
    if (socket != &acceptedStream)
    {
      return;
    }

    acceptedStream.pendingSend = false;
    acceptedStream.pendingSendBytes = 0;
    acceptedStream.wBuffer.noteSendCompleted();

    suite->expectTrue(result > 0, "queued-send result positive", __FILE__, __LINE__);
    if (result <= 0)
    {
      Ring::exit = true;
      return;
    }

    sendResults.push_back(result);
    acceptedStream.wBuffer.consume(uint64_t(result), true);

    if (acceptedStream.wBuffer.outstandingBytes() > 0)
    {
      Ring::queueSend(&acceptedStream);
    }
    else
    {
      Ring::queueClose(&acceptedStream);
      Ring::queueClose(&listener);
    }
  }

  void closeHandler(void *socket) override
  {
    if (socket == &acceptedStream)
    {
      streamClosed = true;
    }
    else if (socket == &listener)
    {
      listenerClosed = true;
    }

    maybeStop();
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    deadlineFired = true;
    suite->expectEqual(result, -ETIME, "result", "-ETIME", __FILE__, __LINE__);
    Ring::exit = true;
  }
};

struct TimedRecvCloseReuseStressInterface : RingInterface {
  TestSuite *suite = nullptr;
  TCPSocket listener;
  TCPStream acceptedStream;
  TimeoutPacket deadline;

  int targetIterations = 512;
  int acceptedCount = 0;
  int closeCount = 0;
  int eofCount = 0;
  int timeoutCount = 0;
  bool listenerClosed = false;
  bool deadlineFired = false;

  explicit TimedRecvCloseReuseStressInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(5000);
    configureLoopbackListener(listener);
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket != &listener)
    {
      return;
    }

    suite->expectTrue(fslot >= 0, "timed-recv-stress accept fixed-file slot is valid", __FILE__, __LINE__);
    suite->expectTrue(fslot >= kDynamicFixedSlotBegin, "timed-recv-stress accept fixed-file slot stays out of reserved range", __FILE__, __LINE__);

    acceptedStream.reset();
    acceptedStream.fslot = fslot;
    acceptedStream.isFixedFile = true;
    suite->expectTrue(acceptedStream.rBuffer.reserve(64), "timed-recv-stress reserve acceptedStream", __FILE__, __LINE__);

    acceptedCount += 1;
    Ring::queueRecv(&acceptedStream, 2);
  }

  void recvHandler(void *socket, int result) override
  {
    if (socket != &acceptedStream)
    {
      return;
    }

    acceptedStream.pendingRecv = false;

    if (result == 0)
    {
      eofCount += 1;
    }
    else if (result == -ETIME)
    {
      timeoutCount += 1;
    }

    if (Ring::socketIsClosing(&acceptedStream) == false)
    {
      Ring::queueCancelAll(&acceptedStream);
      Ring::queueClose(&acceptedStream);
    }
  }

  void closeHandler(void *socket) override
  {
    if (socket == &acceptedStream)
    {
      closeCount += 1;
      if (closeCount >= targetIterations)
      {
        Ring::queueClose(&listener);
      }
      else
      {
        Ring::queueAccept(&listener);
      }
      return;
    }

    if (socket == &listener)
    {
      listenerClosed = true;
      Ring::exit = true;
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    deadlineFired = true;
    suite->expectEqual(result, -ETIME, "result", "-ETIME", __FILE__, __LINE__);
    Ring::exit = true;
  }
};

enum class RawPollExpectation : uint8_t {
  ready,
  canceled,
  readinessCancelRace
};

struct RawPollWatcher {
  RawPollExpectation expectation;
  uint64_t generation;
  Ring::RawPollTicket ticket = Ring::invalidRawPollTicket;
  int *destructionCount = nullptr;

  ~RawPollWatcher()
  {
    ++(*destructionCount);
  }
};

struct RawPollScenarioInterface : RingInterface {
  TestSuite *suite = nullptr;
  TimeoutPacket deadline;
  Vector<Ring::RawPollTicket> completedTickets;
  size_t expectedCompletions = 0;
  int destructionCount = 0;
  bool deadlineFired = false;

  explicit RawPollScenarioInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(2000);
  }

  void rawFDPollHandler(void *owner, uint64_t generation, uint64_t ticket, int result) override
  {
    if (std::find(completedTickets.begin(), completedTickets.end(), ticket) != completedTickets.end())
    {
      suite->expectTrue(false, "raw fd poll ticket completes exactly once", __FILE__, __LINE__);
      Ring::exit = true;
      return;
    }

    RawPollWatcher *watcher = static_cast<RawPollWatcher *>(owner);
    suite->expectTrue(watcher != nullptr, "raw fd poll returns its owner", __FILE__, __LINE__);
    if (watcher == nullptr)
    {
      Ring::exit = true;
      return;
    }

    suite->expectEqual(generation, watcher->generation, "generation", "watcher->generation", __FILE__, __LINE__);
    suite->expectEqual(ticket, watcher->ticket, "ticket", "watcher->ticket", __FILE__, __LINE__);
    suite->expectTrue(Ring::cancelRawFDPoll(ticket) == false, "terminal raw fd poll cannot be canceled again", __FILE__, __LINE__);

    switch (watcher->expectation)
    {
      case RawPollExpectation::ready:
        suite->expectTrue(result >= 0 && (result & POLLIN), "ready raw fd poll reports POLLIN", __FILE__, __LINE__);
        break;
      case RawPollExpectation::canceled:
        suite->expectEqual(result, -ECANCELED, "result", "-ECANCELED", __FILE__, __LINE__);
        break;
      case RawPollExpectation::readinessCancelRace:
        suite->expectTrue(result == -ECANCELED || (result >= 0 && (result & POLLIN)), "readiness/cancel race has one valid terminal result", __FILE__, __LINE__);
        break;
    }

    completedTickets.push_back(ticket);
    delete watcher;

    if (completedTickets.size() == expectedCompletions)
    {
      Ring::exit = true;
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    (void)result;
    if (packet == &deadline)
    {
      deadlineFired = true;
      Ring::exit = true;
    }
  }
};

struct CompletionBatchExitInterface : RingInterface {
  TimeoutPacket wakeup;
  bool timeoutHandled = false;
  bool batchHandled = false;

  CompletionBatchExitInterface()
  {
    wakeup.setTimeoutMs(1);
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet == &wakeup && result == -ETIME)
    {
      timeoutHandled = true;
    }
  }

  void completionBatchHandler(uint32_t count) override
  {
    if (count > 0 && timeoutHandled)
    {
      batchHandled = true;
      Ring::exit = true;
    }
  }
};

static void testCompletionBatchCanQuiesceRing(TestSuite& suite)
{
  CompletionBatchExitInterface interfacer;
  Ring::interfacer = &interfacer;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(32, 32, 4, 2, -1, -1, 4);
  Ring::queueTimeout(&interfacer.wakeup);
  Ring::start();
  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  EXPECT_TRUE(suite, interfacer.timeoutHandled);
  EXPECT_TRUE(suite, interfacer.batchHandled);
}

static void runRingScenario(TestSuite& suite)
{
  RingScenarioInterface interfacer(suite);

  const uint16_t listenerPort = boundPortForFD(interfacer.listener.fd);
  const uint16_t multishotPort = boundPortForFD(interfacer.multishotListener.fd);
  EXPECT_TRUE(suite, listenerPort != 0);
  EXPECT_TRUE(suite, multishotPort != 0);

  std::string reply;
  int passiveClientResult = 0;

  std::thread client([&]() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
      return;
    }

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(listenerPort);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0)
    {
      (void)::send(fd, "ping", 4, 0);

      char buffer[4] = {};
      ssize_t nread = recv(fd, buffer, sizeof(buffer), MSG_WAITALL);
      if (nread > 0)
      {
        reply.assign(buffer, size_t(nread));
      }
    }

    ::close(fd);
  });

  std::thread passiveClient([&]() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
      passiveClientResult = -1;
      return;
    }

    timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(multishotPort);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
    {
      passiveClientResult = -2;
      ::close(fd);
      return;
    }

    char buffer[8] = {};
    passiveClientResult = int(recv(fd, buffer, sizeof(buffer), 0));
    ::close(fd);
  });

  Ring::interfacer = &interfacer;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  Ring::createRing(128, 256, 16, 4, -1, -1, 16);
  Ring::installFDIntoFixedFileSlot(&interfacer.listener);
  Ring::installFDIntoFixedFileSlot(&interfacer.multishotListener);
  Ring::queueAccept(&interfacer.listener);
  Ring::queueAcceptMultishot(&interfacer.multishotListener);
  Ring::queueTimeout(&interfacer.deadline);
  Ring::start();
  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  client.join();
  passiveClient.join();

  EXPECT_FALSE(suite, interfacer.deadlineFired);
  EXPECT_TRUE(suite, interfacer.accepted);
  EXPECT_TRUE(suite, interfacer.received);
  EXPECT_TRUE(suite, interfacer.sent);
  EXPECT_TRUE(suite, interfacer.recvTimedOut);
  EXPECT_TRUE(suite, interfacer.acceptMultishotReceived);
  EXPECT_TRUE(suite, interfacer.acceptedStreamClosed);
  EXPECT_TRUE(suite, interfacer.listenerClosed);
  EXPECT_TRUE(suite, interfacer.timedOutStreamClosed);
  EXPECT_TRUE(suite, interfacer.multishotListenerClosed);
  EXPECT_STRING_EQ(suite, interfacer.receivedPayload, "ping"_ctv);
  EXPECT_EQ(suite, reply, std::string("pong"));
  EXPECT_TRUE(suite, passiveClientResult <= 0);
  (void)interfacer.acceptMultishotMustRearm;
}

static void testRawFDPollReadinessCancellationAndRace(TestSuite& suite)
{
  RawPollScenarioInterface interfacer(suite);
  Vector<std::array<int, 2>> pipes;

  Ring::interfacer = &interfacer;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(256, 512, 8, 2, -1, -1, 8);

  EXPECT_EQ(suite, Ring::queueRawFDPoll(nullptr, 1, STDIN_FILENO, POLLIN), Ring::invalidRawPollTicket);
  EXPECT_EQ(suite, Ring::queueRawFDPoll(&interfacer, 1, -1, POLLIN), Ring::invalidRawPollTicket);
  EXPECT_EQ(suite, Ring::queueRawFDPoll(&interfacer, 1, STDIN_FILENO, 0), Ring::invalidRawPollTicket);

  auto addWatcher = [&](RawPollExpectation expectation, bool makeReady, bool cancel) {
    std::array<int, 2> descriptors = {-1, -1};
    EXPECT_EQ(suite, pipe2(descriptors.data(), O_NONBLOCK | O_CLOEXEC), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0)
    {
      return;
    }

    RawPollWatcher *watcher = new RawPollWatcher {
      .expectation = expectation,
      .generation = UINT64_C(0xEEDDCCBBAA000000) + pipes.size(),
      .destructionCount = &interfacer.destructionCount
    };
    watcher->ticket = Ring::queueRawFDPoll(watcher, watcher->generation, descriptors[0], POLLIN);
    EXPECT_TRUE(suite, watcher->ticket != Ring::invalidRawPollTicket);

    if (makeReady)
    {
      const uint8_t value = 1;
      EXPECT_EQ(suite, write(descriptors[1], &value, sizeof(value)), ssize_t(sizeof(value)));
    }
    if (cancel)
    {
      EXPECT_TRUE(suite, Ring::cancelRawFDPoll(watcher->ticket));
      EXPECT_FALSE(suite, Ring::cancelRawFDPoll(watcher->ticket));
    }

    pipes.push_back(descriptors);
    ++interfacer.expectedCompletions;
  };

  addWatcher(RawPollExpectation::ready, true, false);
  addWatcher(RawPollExpectation::canceled, false, true);
  for (size_t index = 0; index < 64; ++index)
  {
    addWatcher(RawPollExpectation::readinessCancelRace, true, true);
  }

  Ring::queueTimeout(&interfacer.deadline);
  Ring::start();
  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  for (const auto& descriptors : pipes)
  {
    close(descriptors[0]);
    close(descriptors[1]);
  }

  EXPECT_FALSE(suite, interfacer.deadlineFired);
  EXPECT_EQ(suite, interfacer.completedTickets.size(), interfacer.expectedCompletions);
  EXPECT_EQ(suite, interfacer.destructionCount, int(interfacer.expectedCompletions));
}

static void testRingletSendRecvAndTimeout(TestSuite& suite)
{
  int fds[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

  UnixSocket sender;
  UnixSocket receiver;
  sender.fd = fds[0];
  receiver.fd = fds[1];

  uint8_t received[4] = {};
  const uint8_t payload[4] = {'p', 'o', 'n', 'g'};

  bool sendSeen = false;
  bool recvSeen = false;
  bool timeoutSeen = false;

  Ringlet ringlet(16, 16);
  ringlet.queueSend(&sender, const_cast<uint8_t *>(payload), sizeof(payload));
  ringlet.queueRecv(&receiver, received, sizeof(received));
  ringlet.queueTimeout(10'000);

  ringlet.events([&](RingletOp op, Ringlet::Event *, int result, uint32_t) -> bool {
    switch (op)
    {
      case RingletOp::send:
        EXPECT_EQ(suite, result, int(sizeof(payload)));
        sendSeen = true;
        break;
      case RingletOp::recv:
        EXPECT_EQ(suite, result, int(sizeof(payload)));
        EXPECT_TRUE(suite, std::memcmp(received, payload, sizeof(payload)) == 0);
        recvSeen = true;
        break;
      case RingletOp::timeout:
        EXPECT_EQ(suite, result, -ETIME);
        timeoutSeen = true;
        break;
      default:
        break;
    }

    return sendSeen && recvSeen && timeoutSeen;
  });

  EXPECT_TRUE(suite, sendSeen);
  EXPECT_TRUE(suite, recvSeen);
  EXPECT_TRUE(suite, timeoutSeen);

  ::close(fds[0]);
  ::close(fds[1]);
}

static void testDuplicateQueueCloseIsIdempotent(TestSuite& suite)
{
  int fds[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds), 0);

  DuplicateCloseInterface interfacer(suite);
  interfacer.socket.fd = fds[0];

  Ring::interfacer = &interfacer;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  Ring::createRing(64, 64, 8, 4, -1, -1, 8);
  Ring::installFDIntoFixedFileSlot(&interfacer.socket);
  Ring::queueTimeout(&interfacer.deadline);
  Ring::queueClose(&interfacer.socket);
  Ring::queueClose(&interfacer.socket);
  Ring::start();
  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  ::close(fds[1]);

  EXPECT_FALSE(suite, interfacer.deadlineFired);
  EXPECT_EQ(suite, interfacer.closeCalls, 1);
}

static void testAcceptedCloseRawReturnsDynamicSlot(TestSuite& suite)
{
  AcceptCloseRawInterface interfacer(suite);
  const uint16_t listenerPort = boundPortForFD(interfacer.listener.fd);
  EXPECT_TRUE(suite, listenerPort != 0);

  std::thread client([&]() {
    for (int attempt = 0; attempt < 2; attempt++)
    {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0)
      {
        return;
      }

      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_port = htons(listenerPort);
      inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

      (void)connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
      ::close(fd);
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  });

  Ring::interfacer = &interfacer;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  Ring::createRing(32, 32, 5, 4, -1, -1, 8);
  Ring::installFDIntoFixedFileSlot(&interfacer.listener);
  Ring::queueTimeout(&interfacer.deadline);
  Ring::queueAccept(&interfacer.listener);
  Ring::start();
  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  client.join();

  EXPECT_FALSE(suite, interfacer.deadlineFired);
  EXPECT_TRUE(suite, interfacer.listenerClosed);
  EXPECT_EQ(suite, interfacer.acceptCalls, 2);
  EXPECT_EQ(suite, interfacer.firstSlot, kDynamicFixedSlotBegin);
  EXPECT_EQ(suite, interfacer.secondSlot, kDynamicFixedSlotBegin);
}

static void testQueuedSendDrainsFramesBehindCompletedHandshake(TestSuite& suite)
{
  QueuedSendDrainInterface interfacer(suite);
  const uint16_t listenerPort = boundPortForFD(interfacer.listener.fd);
  EXPECT_TRUE(suite, listenerPort != 0);

  String received;
  std::thread client([&]() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
      return;
    }

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(listenerPort);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
    {
      ::close(fd);
      return;
    }

    char buffer[4096] = {};
    for (;;)
    {
      ssize_t nread = recv(fd, buffer, sizeof(buffer), 0);
      if (nread <= 0)
      {
        break;
      }

      received.append(reinterpret_cast<const uint8_t *>(buffer), uint64_t(nread));
    }

    ::close(fd);
  });

  Ring::interfacer = &interfacer;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  Ring::createRing(128, 256, 16, 4, -1, -1, 16);
  Ring::installFDIntoFixedFileSlot(&interfacer.listener);
  Ring::queueTimeout(&interfacer.deadline);
  Ring::queueAccept(&interfacer.listener);
  Ring::start();
  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  client.join();

  EXPECT_FALSE(suite, interfacer.deadlineFired);
  EXPECT_TRUE(suite, interfacer.accepted);
  EXPECT_TRUE(suite, interfacer.streamClosed);
  EXPECT_TRUE(suite, interfacer.listenerClosed);
  EXPECT_EQ(suite, received.size(), interfacer.expectedBytes);
  EXPECT_TRUE(suite, interfacer.sendResults.size() >= size_t(2));
  EXPECT_EQ(suite, interfacer.sendResults.front(), int(sizeof(uint64_t)));

  uint64_t receivedHash = 0;
  std::memcpy(&receivedHash, received.data(), sizeof(receivedHash));
  EXPECT_EQ(suite, receivedHash, interfacer.pairingHash);

  AegisStream receiver;
  receiver.secret = interfacer.secret;
  receiver.rBuffer.append(received.data() + sizeof(receivedHash), received.size() - sizeof(receivedHash));

  bool failed = true;
  size_t decryptedCount = 0;
  String decrypted;
  receiver.extractMessages<AegisMessage>([&](AegisMessage *message) -> void {
    EXPECT_TRUE(suite, receiver.decrypt(message, decrypted));
    EXPECT_STRING_EQ(suite, decrypted, interfacer.plaintexts[decryptedCount]);
    decrypted.clear();
    ++decryptedCount;
  },
                                       true, UINT32_MAX, AegisStream::minMessageSize, AegisStream::maxMessageSize, failed);

  EXPECT_FALSE(suite, failed);
  EXPECT_EQ(suite, decryptedCount, interfacer.plaintexts.size());
  EXPECT_EQ(suite, receiver.rBuffer.outstandingBytes(), uint64_t(0));
}

static void testTimedRecvCloseReuseStress(TestSuite& suite)
{
  WaitableSigChldScope waitableSigChld;
  pid_t child = fork();
  if (child == 0)
  {
    TimedRecvCloseReuseStressInterface interfacer(suite);
    const uint16_t listenerPort = boundPortForFD(interfacer.listener.fd);
    if (listenerPort == 0)
    {
      _exit(2);
    }

    std::thread client([&]() {
      for (int iteration = 0; iteration < interfacer.targetIterations; iteration++)
      {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
          continue;
        }

        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(listenerPort);
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

        if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0)
        {
          if ((iteration % 3) == 0)
          {
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
          }
        }

        ::close(fd);

        if ((iteration % 32) == 0)
        {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
      }
    });

    Ring::interfacer = &interfacer;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;

    Ring::createRing(128, 256, 16, 4, -1, -1, 16);
    Ring::installFDIntoFixedFileSlot(&interfacer.listener);
    Ring::queueTimeout(&interfacer.deadline);
    Ring::queueAccept(&interfacer.listener);
    Ring::start();
    Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;

    client.join();

    if (interfacer.deadlineFired)
    {
      _exit(3);
    }

    if (interfacer.listenerClosed == false)
    {
      _exit(4);
    }

    if (interfacer.acceptedCount != interfacer.targetIterations || interfacer.closeCount != interfacer.targetIterations)
    {
      _exit(5);
    }

    if (interfacer.eofCount == 0 || interfacer.timeoutCount == 0)
    {
      _exit(6);
    }

    _exit(0);
  }

  EXPECT_TRUE(suite, child >= 0);
  if (child < 0)
  {
    return;
  }

  int status = 0;
  EXPECT_EQ(suite, waitpid(child, &status, 0), child);
  EXPECT_TRUE(suite, WIFEXITED(status));
  EXPECT_EQ(suite, WEXITSTATUS(status), 0);
}

static void testRingMessageSenderErrorReportsInvalidTarget(TestSuite& suite)
{
  WaitableSigChldScope waitableSigChld;
  int stderrPipe[2] = {-1, -1};
  EXPECT_EQ(suite, pipe(stderrPipe), 0);
  if (stderrPipe[0] < 0 || stderrPipe[1] < 0)
  {
    return;
  }

  pid_t child = fork();
  if (child == 0)
  {
    close(stderrPipe[0]);
    dup2(stderrPipe[1], STDERR_FILENO);
    close(stderrPipe[1]);

    struct MsgRingSenderErrorInterface : RingInterface {
      TimeoutPacket deadline;
      bool timeoutFired = false;

      MsgRingSenderErrorInterface()
      {
        deadline.setTimeoutMs(50);
      }

      void timeoutHandler(TimeoutPacket *packet, int result) override
      {
        (void)result;

        if (packet != &deadline)
        {
          return;
        }

        timeoutFired = true;
        Ring::exit = true;
      }
    } interfacer;

    Ring::interfacer = &interfacer;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;

    Ring::createRing(32, 32, 8, 2, -1, -1, 8);

    String *message = new String();
    Message::construct(*message, uint16_t(7), uint64_t(11));

    Ring::queueTimeout(&interfacer.deadline);
    Ring::queueRingMessageToRingFD(123456, message);
    Ring::start();
    Ring::shutdownForExec();

    _exit(interfacer.timeoutFired ? 0 : 2);
  }

  close(stderrPipe[1]);

  std::string captured;
  char buffer[256] = {};
  ssize_t nread = 0;
  while ((nread = read(stderrPipe[0], buffer, sizeof(buffer))) > 0)
  {
    captured.append(buffer, size_t(nread));
  }
  close(stderrPipe[0]);

  EXPECT_TRUE(suite, child >= 0);
  if (child < 0)
  {
    return;
  }

  int status = 0;
  EXPECT_EQ(suite, waitpid(child, &status, 0), child);
  EXPECT_TRUE(suite, WIFEXITED(status));
  EXPECT_EQ(suite, WEXITSTATUS(status), 0);
  EXPECT_TRUE(suite, captured.find("Ring msg_ring sender-error") != std::string::npos);
}

} // namespace

int main()
{
  TestSuite suite;
  testRingControlStateIsThreadLocal(suite);
  if (!ringAndRingletSupported())
  {
    std::cout << "ring integration tests skipped: required io_uring features unavailable on this host.\n";
    return suite.finish("ring integration tests");
  }

  testIsolatedWorkerRingPreservesProcessIntegration(suite);
  runRingScenario(suite);
  testCompletionBatchCanQuiesceRing(suite);
  testRawFDPollReadinessCancellationAndRace(suite);
  testRingletSendRecvAndTimeout(suite);
  testDuplicateQueueCloseIsIdempotent(suite);
  testAcceptedCloseRawReturnsDynamicSlot(suite);
  testQueuedSendDrainsFramesBehindCompletedHandshake(suite);
  testTimedRecvCloseReuseStress(suite);
  testRingMessageSenderErrorReportsInvalidTarget(suite);
  return suite.finish("ring integration tests");
}
