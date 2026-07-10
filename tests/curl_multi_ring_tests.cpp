// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/curl.multi.ring.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace
{

static bool ringSupported(void)
{
   const pid_t child = fork();
   if (child == 0)
   {
      Ring::interfacer = nullptr;
      Ring::lifecycler = nullptr;
      Ring::exit = false;
      Ring::shuttingDown = false;
      Ring::createRing(32, 64, 4, 2, -1, -1, 4);
      Ring::shutdownForExec();
      _exit(0);
   }
   if (child < 0)
   {
      return false;
   }
   int status = 0;
   return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void append16(Vector<uint8_t>& bytes, uint16_t value)
{
   bytes.push_back(uint8_t(value >> 8));
   bytes.push_back(uint8_t(value));
}

static void append32(Vector<uint8_t>& bytes, uint32_t value)
{
   bytes.push_back(uint8_t(value >> 24));
   bytes.push_back(uint8_t(value >> 16));
   bytes.push_back(uint8_t(value >> 8));
   bytes.push_back(uint8_t(value));
}

class DnsFixture
{
private:

   int fd = -1;
   uint16_t boundPort = 0;
   std::atomic<bool> stopping = false;
   std::atomic<uint32_t> queries = 0;
   uint32_t delayMilliseconds = 0;
   std::thread worker;

   void run(void)
   {
      while (!stopping.load(std::memory_order_relaxed))
      {
         pollfd descriptor {.fd = fd, .events = POLLIN, .revents = 0};
         if (poll(&descriptor, 1, 25) <= 0)
         {
            continue;
         }
         uint8_t query[512] = {};
         sockaddr_storage peer = {};
         socklen_t peerLength = sizeof(peer);
         const ssize_t size = recvfrom(fd,
                                       query,
                                       sizeof(query),
                                       0,
                                       reinterpret_cast<sockaddr *>(&peer),
                                       &peerLength);
         if (size < 17)
         {
            continue;
         }
         const size_t queryBytes = size_t(size);
         size_t offset = 12;
         while (offset < queryBytes && query[offset] != 0)
         {
            const size_t label = query[offset++];
            if (label > 63 || offset + label > queryBytes)
            {
               offset = queryBytes;
               break;
            }
            offset += label;
         }
         if (++offset + 4 > queryBytes)
         {
            continue;
         }
         const uint16_t type = uint16_t(query[offset] << 8 | query[offset + 1]);
         const size_t questionEnd = offset + 4;
         const bool ipv4 = type == 1;
         Vector<uint8_t> response;
         response.insert(response.end(), query, query + 2);
         append16(response, 0x8180);
         append16(response, 1);
         append16(response, ipv4 ? 1 : 0);
         append16(response, 0);
         append16(response, 0);
         response.insert(response.end(), query + 12, query + questionEnd);
         if (ipv4)
         {
            append16(response, 0xC00C);
            append16(response, 1);
            append16(response, 1);
            append32(response, 1);
            append16(response, 4);
            response.push_back(127);
            response.push_back(0);
            response.push_back(0);
            response.push_back(1);
         }
         if (delayMilliseconds != 0)
         {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMilliseconds));
         }
         (void)sendto(fd,
                      response.data(),
                      response.size(),
                      0,
                      reinterpret_cast<sockaddr *>(&peer),
                      peerLength);
         queries.fetch_add(1, std::memory_order_relaxed);
      }
   }

public:

   explicit DnsFixture(uint32_t delay = 0)
       : delayMilliseconds(delay)
   {
      fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0)
      {
         return;
      }
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
      {
         close(fd);
         fd = -1;
         return;
      }
      socklen_t length = sizeof(address);
      if (getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) != 0)
      {
         close(fd);
         fd = -1;
         return;
      }
      boundPort = ntohs(address.sin_port);
      worker = std::thread([this]
      {
         run();
      });
   }

   ~DnsFixture()
   {
      stopping.store(true, std::memory_order_relaxed);
      if (fd >= 0)
      {
         close(fd);
      }
      if (worker.joinable())
      {
         worker.join();
      }
   }

   bool ready(void) const
   {
      return fd >= 0 && boundPort != 0;
   }

   String servers(void) const
   {
      String value;
      value.snprintf<"127.0.0.1:{itoa}"_ctv>(uint64_t(boundPort));
      return value;
   }

   uint32_t queryCount(void) const
   {
      return queries.load(std::memory_order_relaxed);
   }
};

class HttpFixture
{
private:

   int listener = -1;
   uint16_t boundPort = 0;
   String body;
   uint32_t delayMilliseconds = 0;
   uint32_t expectedConnections = 1;
   std::atomic<bool> stopping = false;
   std::thread worker;

   void run(void)
   {
      uint32_t completed = 0;
      while (!stopping.load(std::memory_order_relaxed))
      {
         pollfd descriptor {.fd = listener, .events = POLLIN, .revents = 0};
         if (poll(&descriptor, 1, 25) <= 0)
         {
            continue;
         }
         const int connection = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
         if (connection < 0)
         {
            continue;
         }
         char request[4096] = {};
         (void)recv(connection, request, sizeof(request), 0);
         if (delayMilliseconds != 0 && completed == 0)
         {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMilliseconds));
         }
         String response;
         response.snprintf<"HTTP/1.1 200 OK\r\nContent-Length: {itoa}\r\nConnection: close\r\n\r\n"_ctv>(
             uint64_t(body.size()));
         response.append(body);
         size_t sent = 0;
         while (sent < response.size())
         {
            const ssize_t count = send(connection,
                                       response.data() + sent,
                                       response.size() - sent,
                                       MSG_NOSIGNAL);
            if (count <= 0)
            {
               break;
            }
            sent += size_t(count);
         }
         close(connection);
         if (++completed == expectedConnections)
         {
            return;
         }
      }
   }

public:

   HttpFixture(const String& responseBody, uint32_t delay, uint32_t connections = 1)
       : body(responseBody),
         delayMilliseconds(delay),
         expectedConnections(connections)
   {
      listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (listener < 0)
      {
         return;
      }
      const int enabled = 1;
      (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
          listen(listener, 8) != 0)
      {
         close(listener);
         listener = -1;
         return;
      }
      socklen_t length = sizeof(address);
      if (getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) != 0)
      {
         close(listener);
         listener = -1;
         return;
      }
      boundPort = ntohs(address.sin_port);
      worker = std::thread([this]
      {
         run();
      });
   }

   ~HttpFixture()
   {
      stopping.store(true, std::memory_order_relaxed);
      if (listener >= 0)
      {
         shutdown(listener, SHUT_RDWR);
         close(listener);
      }
      if (worker.joinable())
      {
         worker.join();
      }
   }

   bool ready(void) const
   {
      return listener >= 0 && boundPort != 0;
   }

   String url(void) const
   {
      String value;
      value.snprintf<"http://127.0.0.1:{itoa}/"_ctv>(uint64_t(boundPort));
      return value;
   }

   uint16_t port(void) const
   {
      return boundPort;
   }
};

struct Scenario final : RingMultiplexer
{
   TestSuite *suite = nullptr;
   CurlMultiRingClient *client = nullptr;
   TimeoutPacket guard;
   bool guardArmed = false;
   bool guardCancellationRequested = false;
   bool fastDone = false;
   bool slowDone = false;
   bool canceledDone = false;
   bool invalidHeaderDone = false;
   bool capDone = false;
   bool deadlineDone = false;
   bool timedOut = false;
   bool firstCompletedWhileSecondActive = false;
   uint32_t fastCalls = 0;
   uint32_t slowCalls = 0;
   uint32_t canceledCalls = 0;
   uint32_t invalidHeaderCalls = 0;
   uint32_t capCalls = 0;
   uint32_t deadlineCalls = 0;

   explicit Scenario(TestSuite& testSuite)
       : suite(&testSuite)
   {
      guard.originator = this;
   }

   static void fastCallback(void *context,
                            CurlMultiRingClient::Ticket,
                            CurlMultiRingClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.fastCalls;
      scenario.fastDone = result.succeeded() && result.statusCode == 200 && result.body == "fast"_ctv;
      scenario.firstCompletedWhileSecondActive = scenario.client->activeTransferCount() > 0;
      scenario.beginShutdownIfDone();
   }

   static void slowCallback(void *context,
                            CurlMultiRingClient::Ticket,
                            CurlMultiRingClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.slowCalls;
      scenario.slowDone = result.succeeded() && result.statusCode == 200 && result.body == "slow"_ctv;
      scenario.beginShutdownIfDone();
   }

   static void canceledCallback(void *context,
                                CurlMultiRingClient::Ticket,
                                CurlMultiRingClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.canceledCalls;
      scenario.canceledDone = result.status == CurlMultiRingClient::Status::canceled;
      scenario.beginShutdownIfDone();
   }

   static void invalidHeaderCallback(void *context,
                                     CurlMultiRingClient::Ticket,
                                     CurlMultiRingClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.invalidHeaderCalls;
      scenario.invalidHeaderDone = result.status == CurlMultiRingClient::Status::invalidRequest;
      scenario.beginShutdownIfDone();
   }

   static void capCallback(void *context,
                           CurlMultiRingClient::Ticket,
                           CurlMultiRingClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.capCalls;
      scenario.capDone = result.status == CurlMultiRingClient::Status::responseTooLarge;
      scenario.beginShutdownIfDone();
   }

   static void deadlineCallback(void *context,
                                CurlMultiRingClient::Ticket,
                                CurlMultiRingClient::Result&& result)
   {
      Scenario& scenario = *static_cast<Scenario *>(context);
      ++scenario.deadlineCalls;
      scenario.deadlineDone = result.status == CurlMultiRingClient::Status::deadlineExceeded;
      scenario.beginShutdownIfDone();
   }

   void beginShutdownIfDone(void)
   {
      if (!fastDone || !slowDone || !canceledDone || !invalidHeaderDone ||
          !capDone || !deadlineDone)
      {
         return;
      }
      (void)client->shutdown();
      if (guardArmed && !guardCancellationRequested)
      {
         guardCancellationRequested = true;
         Ring::queueCancelTimeout(&guard);
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guardCancellationRequested = false;
      guard.clear();
      if (result != -ECANCELED)
      {
         timedOut = true;
         (void)client->shutdown();
      }
      if (client->shutdownSafe())
      {
         Ring::exit = true;
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if (client && client->shutdownSafe() && !guardArmed)
      {
         Ring::exit = true;
      }
   }
};

static CurlMultiRingClient::Request requestFor(const HttpFixture& fixture)
{
   CurlMultiRingClient::Request request;
   request.url = fixture.url();
   request.requireTls = false;
   request.httpPolicy = CurlMultiRingClient::HttpPolicy::requireHttp1;
   request.responseBytes = 1024;
   request.overallDeadline = CurlMultiRingClient::Clock::now() + std::chrono::seconds(3);
   return request;
}

static void testConcurrentCompletionCancellationAndShutdown(TestSuite& suite)
{
   (void)setenv("HTTP_PROXY", "http://127.0.0.1:1", 1);
   (void)setenv("HTTPS_PROXY", "http://127.0.0.1:1", 1);
   (void)setenv("ALL_PROXY", "http://127.0.0.1:1", 1);
   HttpFixture fast("fast", 0);
   HttpFixture slow("slow", 150);
   HttpFixture cancelFixture("cancel", 1000);
   HttpFixture capFixture("response exceeds cap", 0);
   HttpFixture deadlineFixture("late", 400);
   EXPECT_TRUE(suite, fast.ready());
   EXPECT_TRUE(suite, slow.ready());
   EXPECT_TRUE(suite, cancelFixture.ready());
   EXPECT_TRUE(suite, capFixture.ready());
   EXPECT_TRUE(suite, deadlineFixture.ready());
   if (!fast.ready() || !slow.ready() || !cancelFixture.ready() ||
       !capFixture.ready() || !deadlineFixture.ready())
   {
      (void)unsetenv("HTTP_PROXY");
      (void)unsetenv("HTTPS_PROXY");
      (void)unsetenv("ALL_PROXY");
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(128, 256, 8, 2, -1, -1, 8);

   Scenario scenario(suite);
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   scenario.client = new CurlMultiRingClient();
   EXPECT_TRUE(suite, scenario.client->ready());

   CurlMultiRingClient::Request invalid = requestFor(fast);
   invalid.headers.push_back({"Host", "invalid.test"});
   scenario.client->submit(std::move(invalid), {&scenario, Scenario::invalidHeaderCallback});

   CurlMultiRingClient::Request canceled = requestFor(cancelFixture);
   const auto canceledTicket = scenario.client->submit(std::move(canceled),
                                                        {&scenario, Scenario::canceledCallback});
   EXPECT_TRUE(suite, scenario.client->cancel(canceledTicket));

   scenario.client->submit(requestFor(slow), {&scenario, Scenario::slowCallback});
   scenario.client->submit(requestFor(fast), {&scenario, Scenario::fastCallback});
   CurlMultiRingClient::Request capped = requestFor(capFixture);
   capped.responseBytes = 4;
   scenario.client->submit(std::move(capped), {&scenario, Scenario::capCallback});
   CurlMultiRingClient::Request deadline = requestFor(deadlineFixture);
   deadline.firstByteTimeout = std::chrono::milliseconds(50);
   scenario.client->submit(std::move(deadline), {&scenario, Scenario::deadlineCallback});
   scenario.guard.setTimeoutSeconds(5);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.fastDone);
   EXPECT_TRUE(suite, scenario.slowDone);
   EXPECT_TRUE(suite, scenario.canceledDone);
   EXPECT_TRUE(suite, scenario.invalidHeaderDone);
   EXPECT_TRUE(suite, scenario.capDone);
   EXPECT_TRUE(suite, scenario.deadlineDone);
   EXPECT_TRUE(suite, scenario.firstCompletedWhileSecondActive);
   EXPECT_EQ(suite, scenario.fastCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.slowCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.canceledCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.invalidHeaderCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.capCalls, uint32_t(1));
   EXPECT_EQ(suite, scenario.deadlineCalls, uint32_t(1));
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   scenario.client = nullptr;
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   (void)unsetenv("HTTP_PROXY");
   (void)unsetenv("HTTPS_PROXY");
   (void)unsetenv("ALL_PROXY");
}

struct ResetScenario final : RingMultiplexer
{
   CurlMultiRingClient *client = nullptr;
   TimeoutPacket guard;
   bool guardArmed = false;
   bool completionDone = false;
   bool stateCorrect = false;
   bool resetMode = true;
   bool timedOut = false;
   uint32_t calls = 0;

   ResetScenario()
   {
      guard.originator = this;
   }

   static void callback(void *context,
                        CurlMultiRingClient::Ticket,
                        CurlMultiRingClient::Result&& result)
   {
      ResetScenario& scenario = *static_cast<ResetScenario *>(context);
      ++scenario.calls;
      scenario.completionDone = result.status == (scenario.resetMode
                                                       ? CurlMultiRingClient::Status::reset
                                                       : CurlMultiRingClient::Status::shutdown);
      scenario.stateCorrect = scenario.resetMode ? scenario.client->ready()
                                                 : !scenario.client->ready();
      if (scenario.resetMode)
      {
         (void)scenario.client->shutdown();
      }
      if (scenario.guardArmed)
      {
         Ring::queueCancelTimeout(&scenario.guard);
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guard.clear();
      if (result != -ECANCELED)
      {
         timedOut = true;
         (void)client->shutdown();
      }
      if (client->shutdownSafe())
      {
         Ring::exit = true;
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if (client->shutdownSafe() && !guardArmed)
      {
         Ring::exit = true;
      }
   }
};

static void testResetAndActiveShutdownBarriers(TestSuite& suite, bool resetMode)
{
   HttpFixture delayed("unused", 500);
   EXPECT_TRUE(suite, delayed.ready());
   if (!delayed.ready())
   {
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(64, 128, 4, 2, -1, -1, 4);

   ResetScenario scenario;
   scenario.resetMode = resetMode;
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   scenario.client = new CurlMultiRingClient();
   EXPECT_TRUE(suite, scenario.client->ready());
   scenario.client->submit(requestFor(delayed), {&scenario, ResetScenario::callback});
   if (resetMode)
   {
      EXPECT_TRUE(suite, scenario.client->reset());
   }
   else
   {
      (void)scenario.client->shutdown();
   }
   scenario.guard.setTimeoutSeconds(5);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.completionDone);
   EXPECT_TRUE(suite, scenario.stateCorrect);
   EXPECT_EQ(suite, scenario.calls, uint32_t(1));
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
}

struct PinRefreshScenario final : RingMultiplexer
{
   CurlMultiRingClient *client = nullptr;
   TimeoutPacket guard;
   TimeoutPacket heartbeat;
   bool guardArmed = false;
   bool heartbeatArmed = false;
   bool timedOut = false;
   bool allSucceeded = true;
   uint32_t calls = 0;
   uint32_t heartbeats = 0;

   PinRefreshScenario()
   {
      guard.originator = this;
      heartbeat.originator = this;
   }

   static void callback(void *context,
                        CurlMultiRingClient::Ticket,
                        CurlMultiRingClient::Result&& result)
   {
      PinRefreshScenario& scenario = *static_cast<PinRefreshScenario *>(context);
      ++scenario.calls;
      scenario.allSucceeded = scenario.allSucceeded && result.succeeded() &&
                              result.statusCode == 200 && result.body == "pin"_ctv;
      if (scenario.calls == 2)
      {
         (void)scenario.client->shutdown();
         if (scenario.guardArmed)
         {
            Ring::queueCancelTimeout(&scenario.guard);
         }
         if (scenario.heartbeatArmed)
         {
            Ring::queueCancelTimeout(&scenario.heartbeat);
         }
      }
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet == &heartbeat)
      {
         heartbeatArmed = false;
         heartbeat.clear();
         if (result != -ECANCELED && calls < 2)
         {
            ++heartbeats;
            heartbeat.setTimeoutMs(10);
            heartbeatArmed = true;
            Ring::queueTimeout(&heartbeat);
         }
         if (client->shutdownSafe() && !guardArmed && !heartbeatArmed)
         {
            Ring::exit = true;
         }
         return;
      }
      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guard.clear();
      if (result != -ECANCELED)
      {
         timedOut = true;
         (void)client->shutdown();
      }
      if (client->shutdownSafe() && !heartbeatArmed)
      {
         Ring::exit = true;
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if (client->shutdownSafe() && !guardArmed && !heartbeatArmed)
      {
         Ring::exit = true;
      }
   }
};

static void testQueuedPinExpiryReresolves(TestSuite& suite)
{
   DnsFixture dns(100);
   HttpFixture http("pin", 1200, 2);
   EXPECT_TRUE(suite, dns.ready());
   EXPECT_TRUE(suite, http.ready());
   if (!dns.ready() || !http.ready())
   {
      return;
   }

   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(128, 256, 8, 2, -1, -1, 8);

   PinRefreshScenario scenario;
   RingDispatcher::installMultiplexee(&scenario, &scenario);
   RingDispatcher::installMultiplexer(&scenario);
   CurlMultiRingClient::Config config;
   config.totalConnections = 1;
   config.hostConnections = 1;
   config.dnsBackend.servers = dns.servers();
   scenario.client = new CurlMultiRingClient(std::move(config));
   EXPECT_TRUE(suite, scenario.client->ready());

   CurlMultiRingClient::Request request;
   request.url.snprintf<"http://queue.test:{itoa}/"_ctv>(uint64_t(http.port()));
   request.requireTls = false;
   request.httpPolicy = CurlMultiRingClient::HttpPolicy::requireHttp1;
   request.overallDeadline = CurlMultiRingClient::Clock::now() + std::chrono::seconds(5);
   request.firstByteTimeout = std::chrono::seconds(3);
   scenario.client->submit(request, {&scenario, PinRefreshScenario::callback});
   scenario.client->submit(std::move(request), {&scenario, PinRefreshScenario::callback});
   scenario.guard.setTimeoutSeconds(7);
   scenario.guardArmed = true;
   Ring::queueTimeout(&scenario.guard);
   scenario.heartbeat.setTimeoutMs(10);
   scenario.heartbeatArmed = true;
   Ring::queueTimeout(&scenario.heartbeat);
   Ring::start();

   EXPECT_FALSE(suite, scenario.timedOut);
   EXPECT_TRUE(suite, scenario.allSucceeded);
   EXPECT_EQ(suite, scenario.calls, uint32_t(2));
   EXPECT_TRUE(suite, scenario.heartbeats >= 5);
   EXPECT_TRUE(suite, dns.queryCount() >= 4);
   EXPECT_TRUE(suite, scenario.client->shutdownSafe());
   delete scenario.client;
   RingDispatcher::eraseMultiplexee(&scenario);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
}

} // namespace

int main()
{
   TestSuite suite;
   if (!ringSupported())
   {
      std::cout << "curl multi Ring tests skipped: io_uring unavailable.\n";
      return suite.finish("curl multi Ring");
   }
   testConcurrentCompletionCancellationAndShutdown(suite);
   testResetAndActiveShutdownBarriers(suite, true);
   testResetAndActiveShutdownBarriers(suite, false);
   testQueuedPinExpiryReresolves(suite);
   return suite.finish("curl multi Ring");
}
