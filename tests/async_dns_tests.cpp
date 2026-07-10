// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/async.dns.h>

#include <arpa/inet.h>
#include <chrono>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <utility>

using Resolver = AsyncDnsResolver;

struct FakeClock {
   Resolver::TimePoint current = Resolver::TimePoint(std::chrono::seconds(1));

   static Resolver::TimePoint read(void *context)
   {
      return static_cast<FakeClock *>(context)->current;
   }

   Resolver::TimeSource source(void)
   {
      return {this, read};
   }

   void advance(uint32_t seconds)
   {
      current += std::chrono::seconds(seconds);
   }
};

struct Completion {
   Resolver::Ticket ticket;
   Resolver::Result result;
};

class OwnedCoroutine {
public:

   struct promise_type {
      OwnedCoroutine get_return_object(void)
      {
         return OwnedCoroutine(std::coroutine_handle<promise_type>::from_promise(*this));
      }

      std::suspend_never initial_suspend(void) noexcept
      {
         return {};
      }

      std::suspend_always final_suspend(void) noexcept
      {
         return {};
      }

      void return_void(void)
      {}

      void unhandled_exception(void)
      {
         std::abort();
      }
   };

private:

   std::coroutine_handle<promise_type> handle;

   explicit OwnedCoroutine(std::coroutine_handle<promise_type> requestedHandle)
       : handle(requestedHandle)
   {}

public:

   OwnedCoroutine(const OwnedCoroutine&) = delete;
   OwnedCoroutine& operator=(const OwnedCoroutine&) = delete;

   OwnedCoroutine(OwnedCoroutine&& other) noexcept
       : handle(std::exchange(other.handle, {}))
   {}

   ~OwnedCoroutine()
   {
      destroy();
   }

   bool done(void) const
   {
      return handle && handle.done();
   }

   void destroy(void)
   {
      if (handle)
      {
         handle.destroy();
         handle = {};
      }
   }
};

static OwnedCoroutine awaitResolution(Resolver& resolver,
                                      const String& hostname,
                                      Resolver::Family family,
                                      Vector<Resolver::Completion>& completions,
                                      size_t& resumes,
                                      Resolver::TimePoint deadline = Resolver::TimePoint::max(),
                                      Resolver::Ticket *issuedTicket = nullptr)
{
   Resolver::Completion completion = co_await resolver.resolveAsync(hostname,
                                                                     "443",
                                                                     family,
                                                                     deadline,
                                                                     issuedTicket);
   ++resumes;
   completions.push_back(std::move(completion));
}

struct Recorder {
   Vector<Completion> completions;

   static void record(void *context, Resolver::Ticket ticket, Resolver::Result&& result)
   {
      static_cast<Recorder *>(context)->completions.push_back({ticket, std::move(result)});
   }

   Resolver::Callback callback(void)
   {
      return {this, record};
   }
};

struct StartedQuery {
   uint64_t identifier = 0;
   String hostname;
   String service;
   Resolver::Family family = Resolver::Family::any;
};

static Resolver::BackendResult successfulResult(uint32_t ttl = 30);

struct FakeBackend {
   Vector<StartedQuery> started;
   bool accepts = true;

   static bool start(void *context, const Resolver::BackendQuery& query)
   {
      FakeBackend *backend = static_cast<FakeBackend *>(context);
      backend->started.push_back({query.identifier,
                                  String(query.hostname),
                                  String(query.service),
                                  query.family});
      return backend->accepts;
   }

   Resolver::Backend interface(void)
   {
      return {this, start};
   }
};

struct SynchronousBackend {
   Resolver *resolver = nullptr;
   size_t starts = 0;

   static bool start(void *context, const Resolver::BackendQuery& query)
   {
      SynchronousBackend *backend = static_cast<SynchronousBackend *>(context);
      ++backend->starts;
      return backend->resolver->complete(query.identifier, successfulResult());
   }
};

struct StateObservingRecorder {
   Resolver *resolver = nullptr;
   bool sawFullyRetiredQuery = false;
   size_t calls = 0;

   static void record(void *context, Resolver::Ticket, Resolver::Result&&)
   {
      StateObservingRecorder *recorder = static_cast<StateObservingRecorder *>(context);
      ++recorder->calls;
      recorder->sawFullyRetiredQuery = recorder->resolver->activeQueryCount() == 0 &&
                                       recorder->resolver->waiterCount() == 0;
   }
};

static Resolver::Address address4(const char *text, uint16_t port, uint32_t ttl)
{
   sockaddr_in address = {};
   address.sin_family = AF_INET;
   address.sin_port = htons(port);
   inet_pton(AF_INET, text, &address.sin_addr);

   Resolver::Address result;
   std::memcpy(&result.storage, &address, sizeof(address));
   result.length = sizeof(address);
   result.ttlSeconds = ttl;
   return result;
}

static Resolver::Address address6(const char *text, uint16_t port, uint32_t ttl)
{
   sockaddr_in6 address = {};
   address.sin6_family = AF_INET6;
   address.sin6_port = htons(port);
   inet_pton(AF_INET6, text, &address.sin6_addr);

   Resolver::Address result;
   std::memcpy(&result.storage, &address, sizeof(address));
   result.length = sizeof(address);
   result.ttlSeconds = ttl;
   return result;
}

static Resolver::BackendResult successfulResult(uint32_t ttl)
{
   Resolver::BackendResult result;
   result.status = Resolver::Status::success;
   result.canonicalName = "canonical.example";
   result.canonicalNameTtlSeconds = ttl + 10;
   result.addresses.push_back(address6("2001:db8::1", 443, ttl));
   result.addresses.push_back(address4("192.0.2.1", 443, ttl + 5));
   return result;
}

static void testNormalizationAndNumericFastPath(TestSuite& suite)
{
   auto normalized = Resolver::normalize("WWW.Example.COM", "00443", Resolver::Family::any);
   EXPECT_TRUE(suite, normalized.valid());
   EXPECT_TRUE(suite, normalized.hostname == "www.example.com"_ctv);
   EXPECT_TRUE(suite, normalized.service == "443"_ctv);
   EXPECT_FALSE(suite, normalized.numeric);

   EXPECT_TRUE(suite, Resolver::normalize("localhost", "443", Resolver::Family::any).status ==
                          Resolver::Status::singleLabelRejected);
   EXPECT_TRUE(suite, Resolver::normalize("-bad.example", "443", Resolver::Family::any).status ==
                          Resolver::Status::invalidHostname);
   EXPECT_TRUE(suite, Resolver::normalize("bad_.example", "443", Resolver::Family::any).status ==
                          Resolver::Status::invalidHostname);
   EXPECT_TRUE(suite, Resolver::normalize("example.com", "https", Resolver::Family::any).status ==
                          Resolver::Status::invalidService);
   EXPECT_TRUE(suite, Resolver::normalize("example.com", "65536", Resolver::Family::any).status ==
                          Resolver::Status::invalidService);
   EXPECT_TRUE(suite, Resolver::normalize("example.com", "443", static_cast<Resolver::Family>(99)).status ==
                          Resolver::Status::unsupportedFamily);

   auto numeric4 = Resolver::normalize("127.0.0.1", "8080", Resolver::Family::any);
   EXPECT_TRUE(suite, numeric4.valid());
   EXPECT_TRUE(suite, numeric4.numeric);
   EXPECT_EQ(suite, numeric4.numericAddress.family(), AF_INET);
   EXPECT_EQ(suite, reinterpret_cast<const sockaddr_in *>(&numeric4.numericAddress.storage)->sin_port,
             htons(uint16_t(8080)));

   auto numeric6 = Resolver::normalize("2001:db8::1", "443", Resolver::Family::ipv6);
   EXPECT_TRUE(suite, numeric6.valid());
   EXPECT_TRUE(suite, numeric6.numeric);
   EXPECT_EQ(suite, numeric6.numericAddress.family(), AF_INET6);
   EXPECT_TRUE(suite, Resolver::normalize("2001:db8::1", "443", Resolver::Family::ipv4).status ==
                          Resolver::Status::unsupportedFamily);

   FakeClock clock;
   Recorder recorder;
   Resolver resolver({}, {}, clock.source());
   Resolver::Ticket ticket = resolver.resolve("127.0.0.1", "8080", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, bool(ticket));
   EXPECT_EQ(suite, recorder.completions.size(), size_t(1));
   EXPECT_TRUE(suite, recorder.completions[0].result.status == Resolver::Status::success);
   EXPECT_EQ(suite, recorder.completions[0].result.addresses.size(), size_t(1));
   EXPECT_EQ(suite, resolver.activeQueryCount(), size_t(0));
}

static void testBackendRequirementAndSingleflight(TestSuite& suite)
{
   FakeClock clock;
   Recorder missingRecorder;
   Resolver missing({}, {}, clock.source());
   missing.resolve("example.com", "443", Resolver::Family::any, missingRecorder.callback());
   EXPECT_EQ(suite, missingRecorder.completions.size(), size_t(1));
   EXPECT_TRUE(suite, missingRecorder.completions[0].result.status == Resolver::Status::backendRequired);

   FakeBackend backend;
   Recorder recorder;
   Resolver resolver({}, backend.interface(), clock.source());
   Resolver::Ticket first = resolver.resolve("EXAMPLE.com", "443", Resolver::Family::any, recorder.callback());
   Resolver::Ticket second = resolver.resolve("example.COM", "0443", Resolver::Family::any, recorder.callback());

   EXPECT_TRUE(suite, first.identifier != second.identifier);
   EXPECT_TRUE(suite, first.generation != second.generation);
   EXPECT_EQ(suite, backend.started.size(), size_t(1));
   EXPECT_TRUE(suite, backend.started[0].hostname == "example.com"_ctv);
   EXPECT_TRUE(suite, backend.started[0].service == "443"_ctv);
   EXPECT_EQ(suite, resolver.activeQueryCount(), size_t(1));
   EXPECT_EQ(suite, resolver.waiterCount(), size_t(2));

   EXPECT_TRUE(suite, resolver.complete(backend.started[0].identifier, successfulResult()));
   EXPECT_FALSE(suite, resolver.complete(backend.started[0].identifier, successfulResult()));
   EXPECT_EQ(suite, recorder.completions.size(), size_t(2));
   EXPECT_EQ(suite, recorder.completions[0].result.addresses.size(), size_t(2));
   EXPECT_EQ(suite, recorder.completions[1].result.addresses.size(), size_t(2));
   EXPECT_EQ(suite, resolver.activeQueryCount(), size_t(0));
   EXPECT_EQ(suite, resolver.waiterCount(), size_t(0));
}

static void testSynchronousBackendAndCallbackOrdering(TestSuite& suite)
{
   FakeClock clock;
   SynchronousBackend backend;
   Resolver::Backend backendInterface {&backend, SynchronousBackend::start};
   Resolver resolver({}, backendInterface, clock.source());
   backend.resolver = &resolver;

   StateObservingRecorder recorder;
   recorder.resolver = &resolver;
   Resolver::Callback callback {&recorder, StateObservingRecorder::record};
   resolver.resolve("synchronous.example", "443", Resolver::Family::any, callback);

   EXPECT_EQ(suite, backend.starts, size_t(1));
   EXPECT_EQ(suite, recorder.calls, size_t(1));
   EXPECT_TRUE(suite, recorder.sawFullyRetiredQuery);
   EXPECT_EQ(suite, resolver.activeQueryCount(), size_t(0));
   EXPECT_EQ(suite, resolver.waiterCount(), size_t(0));
}

static void testPositiveAndNegativeCaching(TestSuite& suite)
{
   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver resolver({}, backend.interface(), clock.source());

   resolver.resolve("cache.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult(3)));
   EXPECT_EQ(suite, resolver.positiveCacheCount(), size_t(1));

   resolver.resolve("CACHE.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), size_t(1));
   EXPECT_TRUE(suite, recorder.completions.back().result.fromCache);

   clock.advance(4);
   resolver.resolve("cache.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), size_t(2));

   Resolver::BackendResult missing;
   missing.status = Resolver::Status::notFound;
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, std::move(missing)));
   EXPECT_EQ(suite, resolver.negativeCacheCount(), size_t(1));
   resolver.resolve("cache.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), size_t(2));
   EXPECT_TRUE(suite, recorder.completions.back().result.fromCache);
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::notFound);

   clock.advance(6);
   resolver.resolve("cache.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), size_t(3));
   resolver.shutdown();
}

static void testNegativeCacheCannotEvictPositiveCache(TestSuite& suite)
{
   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver::Config config;
   config.positiveCacheEntries = 1;
   config.negativeCacheEntries = 1;
   Resolver resolver(config, backend.interface(), clock.source());

   resolver.resolve("positive.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));

   for (const char *hostname : {"negative-one.example", "negative-two.example"})
   {
      resolver.resolve(hostname, "443", Resolver::Family::any, recorder.callback());
      Resolver::BackendResult missing;
      missing.status = Resolver::Status::notFound;
      EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, std::move(missing)));
   }

   EXPECT_EQ(suite, resolver.positiveCacheCount(), size_t(1));
   EXPECT_EQ(suite, resolver.negativeCacheCount(), size_t(1));
   const size_t starts = backend.started.size();
   resolver.resolve("positive.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), starts);
   EXPECT_TRUE(suite, recorder.completions.back().result.fromCache);
}

static void testCacheClearAndEarliestDeadline(TestSuite& suite)
{
   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver resolver({}, backend.interface(), clock.source());

   resolver.resolve("reload.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
   resolver.resolve("reload.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), size_t(1));
   EXPECT_TRUE(suite, recorder.completions.back().result.fromCache);

   EXPECT_TRUE(suite, resolver.invalidateCache("RELOAD.example", "00443", Resolver::Family::any));
   EXPECT_FALSE(suite, resolver.invalidateCache("reload.example", "443", Resolver::Family::any));
   EXPECT_FALSE(suite, resolver.invalidateCache("127.0.0.1", "443", Resolver::Family::any));
   resolver.resolve("reload.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), size_t(2));
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));

   resolver.clearCache();
   EXPECT_EQ(suite, resolver.positiveCacheCount(), size_t(0));
   EXPECT_EQ(suite, resolver.negativeCacheCount(), size_t(0));
   const Resolver::TimePoint deadline = clock.current + std::chrono::seconds(7);
   resolver.resolve("reload.example", "443", Resolver::Family::any, recorder.callback(), deadline);
   EXPECT_EQ(suite, backend.started.size(), size_t(3));
   EXPECT_TRUE(suite, resolver.earliestDeadline() == deadline);

   resolver.shutdown();
   EXPECT_TRUE(suite, resolver.earliestDeadline() == Resolver::TimePoint::max());
}

static void testCancellationDeadlinesAndShutdown(TestSuite& suite)
{
   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver resolver({}, backend.interface(), clock.source());

   Resolver::Ticket canceled = resolver.resolve("cancel.example", "443", Resolver::Family::any, recorder.callback());
   Resolver::Ticket surviving = resolver.resolve("cancel.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_FALSE(suite, resolver.cancel({canceled.identifier, canceled.generation + 1}));
   EXPECT_TRUE(suite, resolver.cancel(canceled));
   EXPECT_FALSE(suite, resolver.cancel(canceled));
   EXPECT_EQ(suite, recorder.completions.size(), size_t(1));
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::canceled);
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
   EXPECT_EQ(suite, recorder.completions.size(), size_t(2));
   EXPECT_EQ(suite, recorder.completions.back().ticket.identifier, surviving.identifier);

   const Resolver::TimePoint deadline = clock.current + std::chrono::seconds(2);
   resolver.resolve("already-expired.example", "443", Resolver::Family::any, recorder.callback(), clock.current);
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::deadlineExceeded);
   resolver.resolve("deadline.example", "443", Resolver::Family::any, recorder.callback(), deadline);
   clock.advance(3);
   EXPECT_EQ(suite, resolver.expireDeadlines(), size_t(1));
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::deadlineExceeded);

   resolver.resolve("shutdown.example", "443", Resolver::Family::any, recorder.callback());
   resolver.shutdown();
   EXPECT_TRUE(suite, resolver.isShutdown());
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::shutdown);
   EXPECT_EQ(suite, resolver.activeQueryCount(), size_t(0));
   EXPECT_EQ(suite, resolver.waiterCount(), size_t(0));
   resolver.resolve("after.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::shutdown);
}

static void testBoundsAndDeterministicEviction(TestSuite& suite)
{
   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver::Config config;
   config.positiveCacheEntries = 2;
   config.negativeCacheEntries = 1;
   config.activeQueries = 2;
   config.waitersPerQuery = 2;
   config.totalWaiters = 3;
   config.answers = 2;
   Resolver resolver(config, backend.interface(), clock.source());

   resolver.resolve("one.example", "443", Resolver::Family::any, recorder.callback());
   resolver.resolve("one.example", "443", Resolver::Family::any, recorder.callback());
   resolver.resolve("one.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::overloaded);

   resolver.resolve("two.example", "443", Resolver::Family::any, recorder.callback());
   resolver.resolve("three.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::overloaded);

   EXPECT_TRUE(suite, resolver.complete(backend.started[0].identifier, successfulResult()));
   EXPECT_TRUE(suite, resolver.complete(backend.started[1].identifier, successfulResult()));

   resolver.resolve("three.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
   EXPECT_EQ(suite, resolver.positiveCacheCount(), size_t(2));

   const size_t startsBeforeEvictedLookup = backend.started.size();
   resolver.resolve("one.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_EQ(suite, backend.started.size(), startsBeforeEvictedLookup + 1);

   Resolver::BackendResult excessive = successfulResult();
   excessive.addresses.push_back(address4("192.0.2.2", 443, 10));
   EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, std::move(excessive)));
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::tooManyAnswers);
   resolver.shutdown();
}

static void testHardCapsClampConfiguration(TestSuite& suite)
{
   Resolver::Config config;
   config.positiveCacheEntries = 10'000;
   config.negativeCacheEntries = 10'000;
   config.activeQueries = 10'000;
   config.waitersPerQuery = 10'000;
   config.totalWaiters = 10'000;
   config.answers = 10'000;

   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver resolver(config, backend.interface(), clock.source());

   for (size_t index = 0; index < Resolver::maximumWaitersPerQuery + 1; ++index)
   {
      resolver.resolve("bounded.example", "443", Resolver::Family::any, recorder.callback());
   }
   EXPECT_EQ(suite, resolver.waiterCount(), Resolver::maximumWaitersPerQuery);
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::overloaded);
   resolver.shutdown();
}

static void testExactActiveWaiterAnswerAndCacheCaps(TestSuite& suite)
{
   FakeClock clock;
   FakeBackend backend;
   Recorder recorder;
   Resolver resolver({}, backend.interface(), clock.source());

   for (size_t index = 0; index < Resolver::maximumActiveQueries; ++index)
   {
      resolver.resolve(String("active-") + String(index) + String(".example"),
                       "443",
                       Resolver::Family::any,
                       recorder.callback());
   }
   EXPECT_EQ(suite, resolver.activeQueryCount(), Resolver::maximumActiveQueries);
   resolver.resolve("active-overflow.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::overloaded);

   for (size_t repeat = 0; repeat < 3; ++repeat)
   {
      for (size_t index = 0; index < Resolver::maximumActiveQueries; ++index)
      {
         resolver.resolve(String("active-") + String(index) + String(".example"),
                          "443",
                          Resolver::Family::any,
                          recorder.callback());
      }
   }
   EXPECT_EQ(suite, resolver.waiterCount(), Resolver::maximumTotalWaiters);
   resolver.resolve("active-0.example", "443", Resolver::Family::any, recorder.callback());
   EXPECT_TRUE(suite, recorder.completions.back().result.status == Resolver::Status::overloaded);
   resolver.shutdown();

   FakeBackend answersBackend;
   Recorder answersRecorder;
   Resolver answersResolver({}, answersBackend.interface(), clock.source());
   answersResolver.resolve("answers.example", "443", Resolver::Family::any, answersRecorder.callback());
   Resolver::BackendResult exact;
   exact.status = Resolver::Status::success;
   exact.canonicalName = "answers.example";
   exact.canonicalNameTtlSeconds = 30;
   for (size_t index = 0; index < Resolver::maximumAnswers; ++index)
   {
      exact.addresses.push_back(address4("192.0.2.1", 443, 30));
   }
   EXPECT_TRUE(suite, answersResolver.complete(answersBackend.started.back().identifier, std::move(exact)));
   EXPECT_TRUE(suite, answersRecorder.completions.back().result.status == Resolver::Status::success);
   EXPECT_EQ(suite, answersRecorder.completions.back().result.addresses.size(), Resolver::maximumAnswers);

   answersResolver.resolve("too-many.example", "443", Resolver::Family::any, answersRecorder.callback());
   Resolver::BackendResult excessive;
   excessive.status = Resolver::Status::success;
   for (size_t index = 0; index <= Resolver::maximumAnswers; ++index)
   {
      excessive.addresses.push_back(address4("192.0.2.2", 443, 30));
   }
   EXPECT_TRUE(suite, answersResolver.complete(answersBackend.started.back().identifier, std::move(excessive)));
   EXPECT_TRUE(suite, answersRecorder.completions.back().result.status == Resolver::Status::tooManyAnswers);

   Resolver::Config cacheConfig;
   cacheConfig.positiveCacheEntries = 10'000;
   cacheConfig.negativeCacheEntries = 10'000;
   FakeBackend cacheBackend;
   Recorder cacheRecorder;
   Resolver cacheResolver(cacheConfig, cacheBackend.interface(), clock.source());
   for (size_t index = 0; index <= Resolver::maximumCacheEntries; ++index)
   {
      cacheResolver.resolve(String("cache-cap-") + String(index) + String(".example"),
                            "443",
                            Resolver::Family::any,
                            cacheRecorder.callback());
      EXPECT_TRUE(suite, cacheResolver.complete(cacheBackend.started.back().identifier, successfulResult()));
   }
   EXPECT_EQ(suite, cacheResolver.positiveCacheCount(), Resolver::maximumCacheEntries);
}

static void testCoroutineResolutionLifecycle(TestSuite& suite)
{
   {
      FakeClock clock;
      Resolver resolver({}, {}, clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      Resolver::Ticket ticket;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "127.0.0.1",
                                            Resolver::Family::any,
                                            completions,
                                            resumes,
                                            Resolver::TimePoint::max(),
                                            &ticket);

      EXPECT_TRUE(suite, task.done());
      EXPECT_TRUE(suite, bool(ticket));
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_EQ(suite, completions.size(), size_t(1));
      EXPECT_EQ(suite, completions[0].ticket.identifier, ticket.identifier);
      EXPECT_EQ(suite, completions[0].ticket.generation, ticket.generation);
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::success);
   }

   {
      FakeClock clock;
      Resolver resolver({}, {}, clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "missing-backend.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes);

      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::backendRequired);
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Recorder recorder;
      Resolver resolver({}, backend.interface(), clock.source());
      resolver.resolve("cached-coroutine.example", "443", Resolver::Family::any, recorder.callback());
      EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));

      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "CACHED-COROUTINE.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes);

      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.fromCache);
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::success);
   }

   {
      FakeClock clock;
      SynchronousBackend backend;
      Resolver::Backend backendInterface {&backend, SynchronousBackend::start};
      Resolver resolver({}, backendInterface, clock.source());
      backend.resolver = &resolver;

      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "synchronous-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes,
                                            Resolver::TimePoint::max(),
                                            nullptr);

      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, backend.starts, size_t(1));
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::success);
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Resolver resolver({}, backend.interface(), clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "pending-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes);

      EXPECT_FALSE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(0));
      EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_FALSE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
      EXPECT_EQ(suite, resumes, size_t(1));
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Resolver resolver({}, backend.interface(), clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "failed-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes);
      const uint64_t queryIdentifier = backend.started.back().identifier;
      Resolver::BackendResult failure;
      failure.status = Resolver::Status::backendFailure;

      EXPECT_TRUE(suite, resolver.complete(queryIdentifier, std::move(failure)));
      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::backendFailure);
      EXPECT_FALSE(suite, resolver.complete(queryIdentifier, successfulResult()));
      EXPECT_EQ(suite, resumes, size_t(1));
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Resolver resolver({}, backend.interface(), clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      Resolver::Ticket ticket;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "cancel-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes,
                                            Resolver::TimePoint::max(),
                                            &ticket);

      EXPECT_FALSE(suite, resolver.cancel({ticket.identifier, ticket.generation + 1}));
      EXPECT_FALSE(suite, task.done());
      EXPECT_TRUE(suite, resolver.cancel(ticket));
      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::canceled);
      EXPECT_FALSE(suite, resolver.cancel(ticket));
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Resolver resolver({}, backend.interface(), clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "deadline-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes,
                                            clock.current + std::chrono::seconds(1));

      clock.advance(2);
      EXPECT_EQ(suite, resolver.expireDeadlines(), size_t(1));
      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::deadlineExceeded);
      EXPECT_EQ(suite, resolver.expireDeadlines(), size_t(0));
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, resolver.complete(backend.started.back().identifier, successfulResult()));
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Resolver resolver({}, backend.interface(), clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "shutdown-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes);

      resolver.shutdown();
      EXPECT_TRUE(suite, task.done());
      EXPECT_EQ(suite, resumes, size_t(1));
      EXPECT_TRUE(suite, completions[0].result.status == Resolver::Status::shutdown);
      resolver.shutdown();
      EXPECT_EQ(suite, resumes, size_t(1));
   }

   {
      FakeClock clock;
      FakeBackend backend;
      Resolver resolver({}, backend.interface(), clock.source());
      Vector<Resolver::Completion> completions;
      size_t resumes = 0;
      Resolver::Ticket ticket;
      OwnedCoroutine task = awaitResolution(resolver,
                                            "destroyed-coroutine.example",
                                            Resolver::Family::any,
                                            completions,
                                            resumes,
                                            Resolver::TimePoint::max(),
                                            &ticket);
      const uint64_t queryIdentifier = backend.started.back().identifier;

      task.destroy();
      EXPECT_EQ(suite, resolver.waiterCount(), size_t(0));
      EXPECT_FALSE(suite, resolver.cancel(ticket));
      EXPECT_TRUE(suite, resolver.complete(queryIdentifier, successfulResult()));
      EXPECT_EQ(suite, resumes, size_t(0));
      EXPECT_TRUE(suite, completions.empty());
   }
}

struct StateChangeOrderContext {
   size_t changes = 0;
   size_t observedByBackend = 0;
   size_t observedByCallback = 0;

   static void observe(void *context)
   {
      ++static_cast<StateChangeOrderContext *>(context)->changes;
   }

   static void callback(void *context, Resolver::Ticket, Resolver::Result&&)
   {
      StateChangeOrderContext& state = *static_cast<StateChangeOrderContext *>(context);
      state.observedByCallback = state.changes;
   }
};

struct StateChangeOrderBackend {
   StateChangeOrderContext *state = nullptr;

   static bool start(void *context, const Resolver::BackendQuery&)
   {
      StateChangeOrderBackend& backend = *static_cast<StateChangeOrderBackend *>(context);
      backend.state->observedByBackend = backend.state->changes;
      return true;
   }
};

static void testStateChangesPublishBeforeExternalCallbacks(TestSuite& suite)
{
   FakeClock clock;
   StateChangeOrderContext state;
   StateChangeOrderBackend backend {.state = &state};
   Resolver resolver({},
                     {&backend, StateChangeOrderBackend::start},
                     clock.source(),
                     {&state, StateChangeOrderContext::observe});

   const Resolver::Ticket canceled = resolver.resolve("observer-cancel.example",
                                                       "443",
                                                       Resolver::Family::any,
                                                       {&state, StateChangeOrderContext::callback});
   EXPECT_EQ(suite, state.changes, size_t(1));
   EXPECT_EQ(suite, state.observedByBackend, size_t(1));
   EXPECT_TRUE(suite, resolver.cancel(canceled));
   EXPECT_EQ(suite, state.observedByCallback, size_t(2));

   const auto deadline = clock.current + std::chrono::seconds(1);
   resolver.resolve("observer-deadline.example",
                    "443",
                    Resolver::Family::any,
                    {&state, StateChangeOrderContext::callback},
                    deadline);
   EXPECT_EQ(suite, state.observedByBackend, size_t(3));
   clock.advance(1);
   EXPECT_EQ(suite, resolver.expireDeadlines(), size_t(1));
   EXPECT_EQ(suite, state.observedByCallback, size_t(4));
   resolver.shutdown();
}

int main()
{
   TestSuite suite;
   testNormalizationAndNumericFastPath(suite);
   testBackendRequirementAndSingleflight(suite);
   testSynchronousBackendAndCallbackOrdering(suite);
   testPositiveAndNegativeCaching(suite);
   testNegativeCacheCannotEvictPositiveCache(suite);
   testCacheClearAndEarliestDeadline(suite);
   testCancellationDeadlinesAndShutdown(suite);
   testBoundsAndDeterministicEviction(suite);
   testHardCapsClampConfiguration(suite);
   testExactActiveWaiterAnswerAndCacheCaps(suite);
   testCoroutineResolutionLifecycle(suite);
   testStateChangesPublishBeforeExternalCallbacks(suite);
   return suite.finish("async DNS");
}
