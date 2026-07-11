// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/async.dns.cares.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

using Resolver = RingAsyncDnsResolver;
using Status = AsyncDnsResolver::Status;

static_assert(Resolver::maximumConfiguredTimeoutMilliseconds == 30'000);
static_assert(Resolver::maximumConfiguredTries == 3);
static_assert(Resolver::maximumConfiguredUdpQueriesPerSocket == 10'000);
static_assert(Resolver::maximumConfiguredServersBytes == 4096);

static void append16(Vector<uint8_t>& packet, uint16_t value)
{
   packet.push_back(uint8_t(value >> 8));
   packet.push_back(uint8_t(value));
}

static void append32(Vector<uint8_t>& packet, uint32_t value)
{
   packet.push_back(uint8_t(value >> 24));
   packet.push_back(uint8_t(value >> 16));
   packet.push_back(uint8_t(value >> 8));
   packet.push_back(uint8_t(value));
}

static void appendName(Vector<uint8_t>& packet, const String& name)
{
   size_t begin = 0;
   while (begin < name.size())
   {
      size_t end = begin;
      while (end < name.size() && name[end] != '.')
      {
         ++end;
      }
      const size_t length = end - begin;
      packet.push_back(uint8_t(length));
      packet.insert(packet.end(), name.begin() + begin, name.begin() + begin + length);
      if (end == name.size())
      {
         break;
      }
      begin = end + 1;
   }
   packet.push_back(0);
}

class DnsFixture {
private:

   int fd = -1;
   uint16_t boundPort = 0;
   std::atomic<bool> stopping = false;
   std::atomic<uint32_t> receivedQueries = 0;
   std::atomic<uint16_t> lastSourcePort = 0;
   std::thread worker;

   static bool parseQuestion(const uint8_t *packet,
                             size_t size,
                             String& name,
                             uint16_t& type,
                             size_t& questionEnd)
   {
      if (size < 17)
      {
         return false;
      }

      size_t offset = 12;
      while (offset < size)
      {
         const size_t length = packet[offset++];
         if (length == 0)
         {
            break;
         }
         if (length > 63 || offset + length > size)
         {
            return false;
         }
         if (!name.empty())
         {
            name.append("."_ctv);
         }
         name.append(reinterpret_cast<const char *>(packet + offset), length);
         offset += length;
      }
      if (offset + 4 > size)
      {
         return false;
      }
      type = uint16_t(packet[offset] << 8 | packet[offset + 1]);
      questionEnd = offset + 4;
      return true;
   }

   static Vector<uint8_t> answer(const uint8_t *query,
                                 const String& name,
                                 uint16_t type,
                                 size_t questionEnd)
   {
      const bool missing = name == "missing.test"_ctv;
      Vector<uint8_t> response;
      response.reserve(128);
      response.insert(response.end(), query, query + 2);
      append16(response, missing ? 0x8183 : 0x8180);
      append16(response, 1);
      append16(response, missing ? 0 : 2);
      append16(response, 0);
      append16(response, 0);
      response.insert(response.end(), query + 12, query + questionEnd);
      if (missing)
      {
         return response;
      }

      append16(response, 0xC00C);
      append16(response, 5);
      append16(response, 1);
      append32(response, 40);
      Vector<uint8_t> canonical;
      appendName(canonical, "target.test");
      append16(response, uint16_t(canonical.size()));
      response.insert(response.end(), canonical.begin(), canonical.end());

      appendName(response, "target.test");
      append16(response, type);
      append16(response, 1);
      const bool ipv6 = type == 28;
      append32(response, ipv6 ? 20 : 30);
      append16(response, ipv6 ? 16 : 4);
      if (ipv6)
      {
         in6_addr address = {};
         inet_pton(AF_INET6, "2001:db8::10", &address);
         const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&address);
         response.insert(response.end(), bytes, bytes + sizeof(address));
      }
      else
      {
         in_addr address = {};
         inet_pton(AF_INET, "192.0.2.10", &address);
         const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&address);
         response.insert(response.end(), bytes, bytes + sizeof(address));
      }
      return response;
   }

   void run(void)
   {
      while (!stopping.load(std::memory_order_relaxed))
      {
         pollfd descriptor {.fd = fd, .events = POLLIN, .revents = 0};
         if (poll(&descriptor, 1, 50) <= 0)
         {
            continue;
         }

         uint8_t packet[512] = {};
         sockaddr_storage peer = {};
         socklen_t peerLength = sizeof(peer);
         const ssize_t size = recvfrom(fd,
                                       packet,
                                       sizeof(packet),
                                       0,
                                       reinterpret_cast<sockaddr *>(&peer),
                                       &peerLength);
         if (size <= 0)
         {
            continue;
         }
         if (peer.ss_family == AF_INET)
         {
            lastSourcePort.store(
                ntohs(reinterpret_cast<const sockaddr_in *>(&peer)->sin_port),
                std::memory_order_relaxed);
         }

         receivedQueries.fetch_add(1, std::memory_order_relaxed);
         String name;
         uint16_t type = 0;
         size_t questionEnd = 0;
         if (!parseQuestion(packet, size_t(size), name, type, questionEnd) ||
             (type != 1 && type != 28) || name == "drop.test"_ctv)
         {
            continue;
         }
         if (name == "slow.test"_ctv)
         {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
         }

         Vector<uint8_t> response = answer(packet, name, type, questionEnd);
         (void)sendto(fd,
                      response.data(),
                      response.size(),
                      0,
                      reinterpret_cast<sockaddr *>(&peer),
                      peerLength);
      }
   }

public:

   DnsFixture()
   {
      fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0)
      {
         return;
      }
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_port = 0;
      inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
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
      worker = std::thread([this]() { run(); });
   }

   ~DnsFixture()
   {
      stopping.store(true, std::memory_order_relaxed);
      if (worker.joinable())
      {
         worker.join();
      }
      if (fd >= 0)
      {
         close(fd);
      }
   }

   bool ready(void) const
   {
      return fd >= 0 && boundPort != 0;
   }

   String servers(void) const
   {
      String result;
      result.snprintf<"127.0.0.1:{itoa}"_ctv>(uint64_t(boundPort));
      return result;
   }

   uint32_t queryCount(void) const
   {
      return receivedQueries.load(std::memory_order_relaxed);
   }

   uint16_t sourcePort(void) const
   {
      return lastSourcePort.load(std::memory_order_relaxed);
   }
};

struct ReservedUdpPorts
{
   uint16_t first = 0;
   uint16_t second = 0;
};

static ReservedUdpPorts reserveLoopbackUdpPorts(void)
{
   int descriptors[2] = {socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0),
                         socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
   ReservedUdpPorts result;
   uint16_t *ports[2] = {&result.first, &result.second};
   for (size_t index = 0; index < 2 && descriptors[index] >= 0; ++index)
   {
      sockaddr_in address = {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      socklen_t length = sizeof(address);
      if (bind(descriptors[index], reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 &&
          getsockname(descriptors[index], reinterpret_cast<sockaddr *>(&address), &length) == 0)
      {
         *ports[index] = ntohs(address.sin_port);
      }
   }
   for (int fd : descriptors)
   {
      if (fd >= 0)
      {
         close(fd);
      }
   }
   return result;
}

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

struct ScenarioMonitor final : RingMultiplexer {
   Resolver *resolver = nullptr;
   TimeoutPacket heartbeat;
   TimeoutPacket guard;
   bool heartbeatArmed = false;
   bool guardArmed = false;
   bool heartbeatCancellationRequested = false;
   bool guardCancellationRequested = false;
   bool done = false;
   bool timedOut = false;
   uint32_t heartbeats = 0;

   ScenarioMonitor()
   {
      heartbeat.originator = this;
      heartbeat.dispatcher = nullptr;
      guard.originator = this;
      guard.dispatcher = nullptr;
   }

   void start(void)
   {
      heartbeat.setTimeoutMs(10);
      heartbeatArmed = true;
      Ring::queueTimeout(&heartbeat);
      guard.setTimeoutSeconds(3);
      guardArmed = true;
      Ring::queueTimeout(&guard);
   }

   void finish(void)
   {
      done = true;
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet == &heartbeat)
      {
         heartbeatArmed = false;
         heartbeatCancellationRequested = false;
         heartbeat.clear();
         if (!done && result != -ECANCELED)
         {
            ++heartbeats;
            heartbeat.setTimeoutMs(10);
            heartbeatArmed = true;
            Ring::queueTimeout(&heartbeat);
         }
      }
      else if (packet == &guard)
      {
         guardArmed = false;
         guardCancellationRequested = false;
         guard.clear();
         if (result != -ECANCELED)
         {
            timedOut = true;
            done = true;
         }
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if (!done || resolver == nullptr)
      {
         return;
      }

      (void)resolver->shutdown();
      if (heartbeatArmed && !heartbeatCancellationRequested)
      {
         Ring::queueCancelTimeout(&heartbeat);
         heartbeatCancellationRequested = true;
      }
      if (guardArmed && !guardCancellationRequested)
      {
         Ring::queueCancelTimeout(&guard);
         guardCancellationRequested = true;
      }
      if (resolver->shutdownSafe() && !heartbeatArmed && !guardArmed)
      {
         Ring::exit = true;
      }
   }
};

template <typename Start>
static void runScenario(TestSuite& suite,
                        DnsFixture& fixture,
                        ScenarioMonitor& monitor,
                        Start&& start)
{
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(128, 256, 8, 2, -1, -1, 8);
   RingDispatcher::installMultiplexee(&monitor, &monitor);
   RingDispatcher::installMultiplexer(&monitor);

   Resolver::BackendConfig backend;
   backend.servers = fixture.servers();
   backend.udpMaximumQueries = 1;
   const ReservedUdpPorts ports = reserveLoopbackUdpPorts();
   sockaddr_in local = {};
   local.sin_family = AF_INET;
   local.sin_port = htons(ports.first);
   local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   sockaddr_in alternate = local;
   alternate.sin_port = htons(ports.second);
   EXPECT_TRUE(suite, ports.first != 0 && ports.second != 0 && ports.first != ports.second);
   EXPECT_TRUE(suite,
               backend.udpBinds.add(reinterpret_cast<const sockaddr *>(&local), sizeof(local)));
   EXPECT_TRUE(suite,
               backend.tcpBinds.add(reinterpret_cast<const sockaddr *>(&local), sizeof(local)));
   EXPECT_TRUE(suite,
               backend.udpBinds.add(reinterpret_cast<const sockaddr *>(&alternate), sizeof(alternate)));
   EXPECT_TRUE(suite,
               backend.tcpBinds.add(reinterpret_cast<const sockaddr *>(&alternate), sizeof(alternate)));
   {
      Resolver resolver({}, backend);
      monitor.resolver = &resolver;
      EXPECT_TRUE(suite, resolver.ready());
      monitor.start();
      start(resolver, monitor);
      Ring::start();
      EXPECT_TRUE(suite, resolver.shutdownSafe());
      EXPECT_EQ(suite, resolver.activeWatcherCount(), size_t(0));
   }

   RingDispatcher::eraseMultiplexee(&monitor);
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   EXPECT_FALSE(suite, monitor.timedOut);
   EXPECT_TRUE(suite, fixture.sourcePort() == ports.first || fixture.sourcePort() == ports.second);
}

struct ReloadContext {
   Resolver *resolver = nullptr;
   ScenarioMonitor *monitor = nullptr;
   TestSuite *suite = nullptr;
   AsyncDnsResolver::Result first;
   AsyncDnsResolver::Result second;
   size_t calls = 0;

   static void callback(void *context,
                        AsyncDnsResolver::Ticket,
                        AsyncDnsResolver::Result&& result)
   {
      ReloadContext& state = *static_cast<ReloadContext *>(context);
      if (state.calls++ == 0)
      {
         state.first = std::move(result);
         state.suite->expectTrue(state.resolver->reloadConfiguration(),
                                 "resolver->reloadConfiguration()",
                                 __FILE__,
                                 __LINE__);
         state.resolver->resolve("slow.test", "443", Resolver::Family::any, {&state, callback});
         return;
      }
      state.second = std::move(result);
      state.monitor->finish();
   }
};

static void testDelayedDualStackAndReload(TestSuite& suite, DnsFixture& fixture)
{
   const uint32_t before = fixture.queryCount();
   ScenarioMonitor monitor;
   ReloadContext context;
   context.monitor = &monitor;
   context.suite = &suite;
   runScenario(suite, fixture, monitor, [&](Resolver& resolver, ScenarioMonitor&) {
      context.resolver = &resolver;
      resolver.resolve("slow.test", "443", Resolver::Family::any, {&context, ReloadContext::callback});
   });

   EXPECT_EQ(suite, context.calls, size_t(2));
   EXPECT_TRUE(suite, context.first.status == Status::success);
   EXPECT_TRUE(suite, context.second.status == Status::success);
   EXPECT_FALSE(suite, context.second.fromCache);
   EXPECT_EQ(suite, context.second.addresses.size(), size_t(2));
   bool saw4 = false;
   bool saw6 = false;
   for (const auto& address : context.second.addresses)
   {
      saw4 = saw4 || (address.family() == AF_INET && address.ttlSeconds == 30);
      saw6 = saw6 || (address.family() == AF_INET6 && address.ttlSeconds == 20);
   }
   EXPECT_TRUE(suite, saw4);
   EXPECT_TRUE(suite, saw6);
   EXPECT_TRUE(suite, context.second.canonicalName == "target.test"_ctv);
   EXPECT_EQ(suite, context.second.canonicalNameTtlSeconds, uint32_t(40));
   EXPECT_TRUE(suite, monitor.heartbeats >= 4);
   EXPECT_TRUE(suite, fixture.queryCount() >= before + 4);
}

static void testSameFDRejectsStaleEpoch(TestSuite& suite)
{
   AsyncDnsSocketEpochTracker tracker;
   constexpr int reusedFD = 41;
   const uint64_t retiredEpoch = tracker.advance(reusedFD);
   tracker.erase(reusedFD);
   const uint64_t currentEpoch = tracker.advance(reusedFD);

   EXPECT_TRUE(suite, retiredEpoch != currentEpoch);
   EXPECT_FALSE(suite, tracker.matches(reusedFD, retiredEpoch));
   EXPECT_TRUE(suite, tracker.matches(reusedFD, currentEpoch));
}

struct NegativeContext {
   Resolver *resolver = nullptr;
   ScenarioMonitor *monitor = nullptr;
   AsyncDnsResolver::Result first;
   AsyncDnsResolver::Result second;
   size_t calls = 0;

   static void callback(void *context,
                        AsyncDnsResolver::Ticket,
                        AsyncDnsResolver::Result&& result)
   {
      NegativeContext& state = *static_cast<NegativeContext *>(context);
      if (state.calls++ == 0)
      {
         state.first = std::move(result);
         state.resolver->resolve("missing.test", "443", Resolver::Family::any, {&state, callback});
         return;
      }
      state.second = std::move(result);
      state.monitor->finish();
   }
};

static void testNXDomainAndNegativeCache(TestSuite& suite, DnsFixture& fixture)
{
   ScenarioMonitor monitor;
   NegativeContext context;
   context.monitor = &monitor;
   runScenario(suite, fixture, monitor, [&](Resolver& resolver, ScenarioMonitor&) {
      context.resolver = &resolver;
      resolver.resolve("missing.test", "443", Resolver::Family::any, {&context, NegativeContext::callback});
   });
   EXPECT_EQ(suite, context.calls, size_t(2));
   EXPECT_TRUE(suite, context.first.status == Status::notFound);
   EXPECT_TRUE(suite, context.second.status == Status::notFound);
   EXPECT_TRUE(suite, context.second.fromCache);
}

struct CancellationContext {
   ScenarioMonitor *monitor = nullptr;
   size_t calls = 0;
   bool canceled = false;
   bool deadline = false;

   static void callback(void *context,
                        AsyncDnsResolver::Ticket,
                        AsyncDnsResolver::Result&& result)
   {
      CancellationContext& state = *static_cast<CancellationContext *>(context);
      ++state.calls;
      state.canceled = state.canceled || result.status == Status::canceled;
      state.deadline = state.deadline || result.status == Status::deadlineExceeded;
      if (state.calls == 2)
      {
         state.monitor->finish();
      }
   }
};

static void testCancellationDeadlineAndShutdownBarrier(TestSuite& suite, DnsFixture& fixture)
{
   ScenarioMonitor monitor;
   CancellationContext context {.monitor = &monitor};
   runScenario(suite, fixture, monitor, [&](Resolver& resolver, ScenarioMonitor&) {
      const auto first = resolver.resolve("drop.test",
                                          "443",
                                          Resolver::Family::any,
                                          {&context, CancellationContext::callback});
      resolver.resolve("drop.test",
                       "443",
                       Resolver::Family::any,
                       {&context, CancellationContext::callback},
                       AsyncDnsResolver::Clock::now() + std::chrono::milliseconds(40));
      EXPECT_TRUE(suite, resolver.cancel(first));
   });
   EXPECT_EQ(suite, context.calls, size_t(2));
   EXPECT_TRUE(suite, context.canceled);
   EXPECT_TRUE(suite, context.deadline);
}

static void testDispatcherAndSingleOwnerAdmission(TestSuite& suite, DnsFixture& fixture)
{
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(32, 64, 4, 2, -1, -1, 4);
   Resolver::BackendConfig backend;
   backend.servers = fixture.servers();
   Resolver first({}, backend);
   Resolver second({}, backend);
   EXPECT_TRUE(suite, first.ready());
   EXPECT_FALSE(suite, second.ready());
   EXPECT_TRUE(suite, second.initializationStatus() == Resolver::InitializationStatus::anotherResolverOwnsThread);
   EXPECT_TRUE(suite, first.shutdown());
   Ring::shutdownForExec();
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   RingDispatcher::dispatcher = nullptr;
}

struct NumericSelfReleaseContext {
   Resolver **resolver = nullptr;
   Status status = Status::backendFailure;
   bool called = false;

   static void callback(void *context,
                        AsyncDnsResolver::Ticket,
                        AsyncDnsResolver::Result&& result)
   {
      NumericSelfReleaseContext& state = *static_cast<NumericSelfReleaseContext *>(context);
      state.called = true;
      state.status = result.status;
      Resolver *released = std::exchange(*state.resolver, nullptr);
      delete released;
   }
};

static void testNumericCallbackCanReleaseWrapper(TestSuite& suite)
{
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Resolver *resolver = new Resolver();
   NumericSelfReleaseContext context {.resolver = &resolver};

   const auto ticket = resolver->resolve("127.0.0.1",
                                         "443",
                                         Resolver::Family::any,
                                         {&context, NumericSelfReleaseContext::callback});

   EXPECT_TRUE(suite, bool(ticket));
   EXPECT_TRUE(suite, context.called);
   EXPECT_TRUE(suite, context.status == Status::success);
   EXPECT_TRUE(suite, resolver == nullptr);
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   RingDispatcher::dispatcher = nullptr;
}

struct CacheSelfReleaseMonitor final : RingMultiplexer {
   Resolver *resolver = nullptr;
   TimeoutPacket heartbeat;
   TimeoutPacket guard;
   bool heartbeatArmed = false;
   bool guardArmed = false;
   bool firstReady = false;
   bool released = false;
   bool cacheHit = false;
   bool timedOut = false;

   CacheSelfReleaseMonitor()
   {
      heartbeat.originator = this;
      guard.originator = this;
   }

   static void initialCallback(void *context,
                               AsyncDnsResolver::Ticket,
                               AsyncDnsResolver::Result&& result)
   {
      CacheSelfReleaseMonitor& monitor = *static_cast<CacheSelfReleaseMonitor *>(context);
      monitor.firstReady = result.status == Status::notFound;
   }

   static void cachedCallback(void *context,
                              AsyncDnsResolver::Ticket,
                              AsyncDnsResolver::Result&& result)
   {
      CacheSelfReleaseMonitor& monitor = *static_cast<CacheSelfReleaseMonitor *>(context);
      monitor.cacheHit = result.status == Status::notFound && result.fromCache;
      Resolver *releasedResolver = std::exchange(monitor.resolver, nullptr);
      delete releasedResolver;
      monitor.released = true;
   }

   void start(void)
   {
      heartbeat.setTimeoutMs(5);
      heartbeatArmed = true;
      Ring::queueTimeout(&heartbeat);
      guard.setTimeoutSeconds(3);
      guardArmed = true;
      Ring::queueTimeout(&guard);
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      if (packet == &heartbeat)
      {
         heartbeatArmed = false;
         heartbeat.clear();
         if (result != -ECANCELED && firstReady && resolver && resolver->idle())
         {
            resolver->resolve("missing.test",
                              "443",
                              Resolver::Family::any,
                              {this, cachedCallback});
            if (released && guardArmed)
            {
               Ring::queueCancelTimeout(&guard);
            }
            return;
         }
         if (result != -ECANCELED)
         {
            heartbeat.setTimeoutMs(5);
            heartbeatArmed = true;
            Ring::queueTimeout(&heartbeat);
         }
         return;
      }

      if (packet != &guard)
      {
         return;
      }
      guardArmed = false;
      guard.clear();
      if (released && result == -ECANCELED)
      {
         Ring::exit = true;
         return;
      }

      timedOut = true;
      if (resolver)
      {
         (void)resolver->shutdown();
      }
   }

   void completionBatchHandler(uint32_t) override
   {
      if (!timedOut || resolver == nullptr)
      {
         return;
      }
      (void)resolver->shutdown();
      if (resolver->shutdownSafe())
      {
         delete std::exchange(resolver, nullptr);
         Ring::exit = true;
      }
   }
};

static void testCachedCallbackCanReleaseIdleWrapper(TestSuite& suite, DnsFixture& fixture)
{
   Ring::interfacer = nullptr;
   Ring::lifecycler = nullptr;
   Ring::exit = false;
   Ring::shuttingDown = false;
   RingDispatcher::dispatcher = nullptr;
   RingDispatcher dispatcher;
   Ring::createRing(64, 128, 4, 2, -1, -1, 4);

   CacheSelfReleaseMonitor monitor;
   RingDispatcher::installMultiplexee(&monitor, &monitor);
   RingDispatcher::installMultiplexer(&monitor);
   Resolver::BackendConfig backend;
   backend.servers = fixture.servers();
   backend.udpMaximumQueries = 1;
   monitor.resolver = new Resolver({}, backend);
   monitor.start();
   monitor.resolver->resolve("missing.test",
                             "443",
                             Resolver::Family::any,
                             {&monitor, CacheSelfReleaseMonitor::initialCallback});
   Ring::start();

   EXPECT_TRUE(suite, monitor.firstReady);
   EXPECT_TRUE(suite, monitor.released);
   EXPECT_TRUE(suite, monitor.cacheHit);
   EXPECT_FALSE(suite, monitor.timedOut);
   EXPECT_TRUE(suite, monitor.resolver == nullptr);
   RingDispatcher::eraseMultiplexee(&monitor);
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
   testSameFDRejectsStaleEpoch(suite);
   testNumericCallbackCanReleaseWrapper(suite);
   if (!ringSupported())
   {
      std::cout << "async DNS c-ares tests skipped: io_uring unavailable.\n";
      return suite.finish("async DNS c-ares");
   }

   DnsFixture fixture;
   EXPECT_TRUE(suite, fixture.ready());
   if (fixture.ready())
   {
      testDelayedDualStackAndReload(suite, fixture);
      testNXDomainAndNegativeCache(suite, fixture);
      testCancellationDeadlineAndShutdownBarrier(suite, fixture);
      testDispatcherAndSingleOwnerAdmission(suite, fixture);
      testCachedCallbackCanReleaseIdleWrapper(suite, fixture);
   }
   return suite.finish("async DNS c-ares");
}
