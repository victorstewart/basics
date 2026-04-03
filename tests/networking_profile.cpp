// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "services/filesystem.h"
#include "services/numbers.h"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "services/crypto.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/message.h"
#include "networking/stream.h"
#include "networking/pool.h"
#include "networking/ring.h"
#include "networking/tls.h"

namespace {

volatile uint64_t g_profile_sink = 0;

static void profileConsume(uint64_t value)
{
  g_profile_sink ^= value + 0x517cc1b727220a95ULL;
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

struct Options {

  std::string scenario = "ring-loopback";
  uint32_t iterations = 128;
  uint32_t payloadBytes = 64 * 1024;
};

static void printUsage(const char *argv0)
{
  std::cerr
      << "Usage:\n"
      << "  " << argv0 << " --list-scenarios\n"
      << "  " << argv0 << " [--scenario ring-loopback] [--iterations n] [--payload-bytes n]\n";
}

static uint64_t parseUnsigned(const char *flag, const char *value)
{
  if (value == nullptr || value[0] == '\0')
  {
    throw std::runtime_error(std::string(flag) + " requires a value");
  }

  char *terminal = nullptr;
  unsigned long long parsed = std::strtoull(value, &terminal, 10);
  if (terminal == value || terminal == nullptr || *terminal != '\0')
  {
    throw std::runtime_error(std::string(flag) + " requires an unsigned integer");
  }

  return static_cast<uint64_t>(parsed);
}

static Options parseOptions(int argc, char **argv)
{
  Options options;

  for (int index = 1; index < argc; ++index)
  {
    std::string_view argument(argv[index]);
    if (argument == "--scenario")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--scenario requires a value");
      }
      options.scenario = argv[++index];
    }
    else if (argument == "--iterations")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--iterations requires a value");
      }
      options.iterations = static_cast<uint32_t>(parseUnsigned("--iterations", argv[++index]));
      if (options.iterations == 0)
      {
        throw std::runtime_error("--iterations must be greater than 0");
      }
    }
    else if (argument == "--payload-bytes")
    {
      if (index + 1 >= argc)
      {
        throw std::runtime_error("--payload-bytes requires a value");
      }
      options.payloadBytes = static_cast<uint32_t>(parseUnsigned("--payload-bytes", argv[++index]));
      if (options.payloadBytes == 0)
      {
      throw std::runtime_error("--payload-bytes must be greater than 0");
      }
    }
    else if (argument == "--list-scenarios")
    {
      std::cout << "ring-loopback\tLoopback TCP accept/recv/send/close through Ring and TCPStream.\n";
      std::exit(0);
    }
    else if (argument == "-h" || argument == "--help")
    {
      printUsage(argv[0]);
      std::exit(0);
    }
    else
    {
      throw std::runtime_error("unknown argument: " + std::string(argument));
    }
  }

  return options;
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

static std::vector<uint8_t> makeDeterministicPayload(uint32_t payloadBytes)
{
  std::vector<uint8_t> payload(payloadBytes);
  for (uint32_t index = 0; index < payloadBytes; ++index)
  {
    payload[index] = static_cast<uint8_t>((index * 131u + 17u) & 0xffu);
  }
  return payload;
}

static bool ringSupported()
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

struct RingProfileInterface : RingInterface {

  TCPSocket listener;
  TCPStream acceptedStream;
  TimeoutPacket deadline;
  const std::vector<uint8_t>& responsePayload;
  const uint64_t expectedBytes;

  uint64_t totalReceived = 0;
  uint64_t totalSent = 0;
  bool accepted = false;
  bool failed = false;
  bool deadlineFired = false;
  bool streamClosed = false;
  bool listenerClosed = false;
  std::string failureReason;

  RingProfileInterface(const std::vector<uint8_t>& payload, int64_t timeoutMs)
      : responsePayload(payload),
        expectedBytes(payload.size())
  {
    deadline.setTimeoutMs(timeoutMs);
    configureLoopbackListener(listener);
  }

  void fail()
  {
    failed = true;
    Ring::exit = true;
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket != &listener || fslot < 0)
    {
      failureReason = "acceptHandler invalid socket or fslot";
      fail();
      return;
    }

    accepted = true;
    acceptedStream.fslot = fslot;
    acceptedStream.isFixedFile = true;
    if (acceptedStream.rBuffer.reserve(4096) == false || acceptedStream.wBuffer.reserve(4096) == false)
    {
      failureReason = "acceptHandler reserve failed";
      fail();
      return;
    }

    Ring::queueRecv(&acceptedStream);
  }

  void recvHandler(void *socket, int result) override
  {
    if (socket != &acceptedStream)
    {
      return;
    }

    acceptedStream.pendingRecv = false;
    if (result <= 0)
    {
      failureReason = "recvHandler result <= 0";
      fail();
      return;
    }

    acceptedStream.rBuffer.advance(result);
    totalReceived += static_cast<uint64_t>(result);

    if (totalReceived < expectedBytes)
    {
      Ring::queueRecv(&acceptedStream);
      return;
    }

    if (totalReceived > expectedBytes)
    {
      failureReason = "recvHandler received more bytes than expected";
      fail();
      return;
    }

    if (acceptedStream.wBuffer.outstandingBytes() == 0)
    {
      acceptedStream.wBuffer.append(responsePayload.data(), responsePayload.size());
    }

    Ring::queueSend(&acceptedStream);
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
    if (result <= 0)
    {
      failureReason = "sendHandler result <= 0";
      fail();
      return;
    }

    totalSent += static_cast<uint64_t>(result);
    acceptedStream.wBuffer.consume(static_cast<uint32_t>(result), true);

    if (acceptedStream.wBuffer.outstandingBytes() > 0)
    {
      Ring::queueSend(&acceptedStream);
      return;
    }

    if (totalSent != expectedBytes)
    {
      failureReason = "sendHandler totalSent mismatch";
      fail();
      return;
    }

    Ring::queueClose(&acceptedStream);
    Ring::queueClose(&listener);
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

    if (streamClosed && listenerClosed)
    {
      Ring::exit = true;
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline || result != -ETIME)
    {
      return;
    }

    deadlineFired = true;
    failureReason = "deadline fired";
    fail();
  }
};

static uint64_t runRingLoopbackProfile(uint32_t iterations, uint32_t payloadBytes)
{
  if (ringSupported() == false)
  {
    throw std::runtime_error("ring-loopback scenario unsupported on this host");
  }

  const std::vector<uint8_t> payload = makeDeterministicPayload(payloadBytes);
  uint64_t completedBytes = 0;

  for (uint32_t iteration = 0; iteration < iterations; ++iteration)
  {
    RingProfileInterface interfacer(payload, 5000);
    uint16_t listenerPort = boundPortForFD(interfacer.listener.fd);
    if (listenerPort == 0)
    {
      throw std::runtime_error("failed to determine loopback listener port");
    }

    std::string clientFailure;
    bool clientSucceeded = false;
    std::thread client([&]() {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0)
      {
        clientFailure = "client socket() failed";
        return;
      }

      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_port = htons(listenerPort);
      inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

      if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
      {
        clientFailure = "client connect() failed";
        ::close(fd);
        return;
      }

      size_t sent = 0;
      while (sent < payload.size())
      {
        ssize_t rc = ::send(fd, payload.data() + sent, payload.size() - sent, 0);
        if (rc <= 0)
        {
          clientFailure = "client send() failed";
          ::close(fd);
          return;
        }
        sent += size_t(rc);
      }

      std::vector<uint8_t> reply(payload.size());
      size_t recved = 0;
      while (recved < reply.size())
      {
        ssize_t rc = ::recv(fd, reply.data() + recved, reply.size() - recved, 0);
        if (rc <= 0)
        {
          clientFailure = "client recv() failed";
          ::close(fd);
          return;
        }
        recved += size_t(rc);
      }

      if (reply != payload)
      {
        clientFailure = "client reply payload mismatch";
        ::close(fd);
        return;
      }

      clientSucceeded = true;
      ::close(fd);
    });

    Ring::interfacer = &interfacer;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(128, 256, 16, 4, -1, -1, 16);
    Ring::installFDIntoFixedFileSlot(&interfacer.listener);
    Ring::queueAccept(&interfacer.listener);
    Ring::queueTimeout(&interfacer.deadline);
    Ring::start();
    Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;

    client.join();

    if (!clientSucceeded)
    {
      throw std::runtime_error("ring-loopback client failed: " + clientFailure);
    }

    if (!interfacer.accepted || interfacer.failed || interfacer.deadlineFired || !interfacer.streamClosed || !interfacer.listenerClosed || interfacer.totalReceived != payload.size() || interfacer.totalSent != payload.size())
    {
      throw std::runtime_error("ring-loopback scenario failed: " + interfacer.failureReason);
    }

    completedBytes += interfacer.totalReceived + interfacer.totalSent;
  }

  return completedBytes;
}

} // namespace

int main(int argc, char **argv)
{
  try
  {
    Options options = parseOptions(argc, argv);
    uint64_t processedBytes = 0;

    if (options.scenario == "ring-loopback")
    {
      processedBytes = runRingLoopbackProfile(options.iterations, options.payloadBytes);
    }
    else
    {
      throw std::runtime_error("unsupported scenario: " + options.scenario);
    }

    std::cout
        << "scenario=" << options.scenario
        << " iterations=" << options.iterations
        << " payload_bytes=" << options.payloadBytes
        << " processed_bytes=" << processedBytes
        << '\n';
    profileConsume(processedBytes);
  }
  catch (const std::exception& error)
  {
    std::cerr << "networking profile failed: " << error.what() << '\n';
    return 1;
  }

  return int(g_profile_sink == 0xffffffffffffffffULL);
}
