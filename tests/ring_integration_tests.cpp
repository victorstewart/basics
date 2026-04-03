// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
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

} // namespace

int main()
{
  if (!ringAndRingletSupported())
  {
    std::cout << "ring integration tests skipped: required io_uring features unavailable on this host.\n";
    return 0;
  }

  TestSuite suite;
  runRingScenario(suite);
  testRingletSendRecvAndTimeout(suite);
  return suite.finish("ring integration tests");
}
