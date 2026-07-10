// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/includes.h>
#include <types/types.containers.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <coroutine>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

class AsyncDnsResolver {
public:

   static constexpr size_t maximumCacheEntries = 512;
   static constexpr size_t maximumActiveQueries = 256;
   static constexpr size_t maximumWaitersPerQuery = 64;
   static constexpr size_t maximumTotalWaiters = 1024;
   static constexpr size_t maximumAnswers = 32;
   static constexpr size_t maximumHostnameBytes = 253;
   static constexpr uint32_t negativeCacheTtlSeconds = 5;

   using Clock = std::chrono::steady_clock;
   using TimePoint = Clock::time_point;

   enum class Family : uint8_t {
      any,
      ipv4,
      ipv6
   };

   enum class Status : uint8_t {
      success,
      pending,
      canceled,
      deadlineExceeded,
      invalidHostname,
      invalidService,
      singleLabelRejected,
      unsupportedFamily,
      notFound,
      noData,
      tooManyAnswers,
      overloaded,
      backendRequired,
      backendFailure,
      shutdown
   };

   struct Address {
      sockaddr_storage storage = {};
      socklen_t length = 0;
      uint32_t ttlSeconds = 0;

      int family(void) const
      {
         return storage.ss_family;
      }
   };

   struct Result {
      Status status = Status::backendFailure;
      Vector<Address> addresses;
      String canonicalName;
      uint32_t canonicalNameTtlSeconds = 0;
      uint32_t timeouts = 0;
      bool fromCache = false;

      bool succeeded(void) const
      {
         return status == Status::success;
      }

      uint32_t minimumTtlSeconds(void) const
      {
         uint32_t minimum = canonicalNameTtlSeconds == 0
                                ? std::numeric_limits<uint32_t>::max()
                                : canonicalNameTtlSeconds;
         bool hasTtl = canonicalNameTtlSeconds != 0;

         for (const Address& address : addresses)
         {
            minimum = std::min(minimum, address.ttlSeconds);
            hasTtl = true;
         }

         return hasTtl ? minimum : 0;
      }
   };

   struct Ticket {
      uint64_t identifier = 0;
      uint64_t generation = 0;

      explicit operator bool(void) const
      {
         return identifier != 0 && generation != 0;
      }
   };

   struct Completion {
      Ticket ticket;
      Result result;
   };

   class ResolveAwaiter;
   class ResolveOperation;

   struct NormalizedQuery {
      Status status = Status::success;
      String hostname;
      String service;
      Family family = Family::any;
      bool numeric = false;
      Address numericAddress;

      bool valid(void) const
      {
         return status == Status::success;
      }
   };

   struct BackendQuery {
      uint64_t identifier = 0;
      const String& hostname;
      const String& service;
      Family family = Family::any;
   };

   struct BackendResult {
      Status status = Status::backendFailure;
      Vector<Address> addresses;
      String canonicalName;
      uint32_t canonicalNameTtlSeconds = 0;
      uint32_t timeouts = 0;
   };

   struct Callback {
      void *context = nullptr;
      void (*function)(void *context, Ticket ticket, Result&& result) = nullptr;

      explicit operator bool(void) const
      {
         return function != nullptr;
      }
   };

   struct StateChangeObserver {
      void *context = nullptr;
      void (*function)(void *context) = nullptr;

      void invoke(void) const
      {
         if (function)
         {
            function(context);
         }
      }
   };

   struct Backend {
      void *context = nullptr;
      bool (*start)(void *context, const BackendQuery& query) = nullptr;

      explicit operator bool(void) const
      {
         return start != nullptr;
      }
   };

   struct TimeSource {
      void *context = nullptr;
      TimePoint (*now)(void *context) = nullptr;
   };

   struct Config {
      size_t positiveCacheEntries = 448;
      size_t negativeCacheEntries = 64;
      size_t activeQueries = maximumActiveQueries;
      size_t waitersPerQuery = maximumWaitersPerQuery;
      size_t totalWaiters = maximumTotalWaiters;
      size_t answers = maximumAnswers;
      uint32_t maximumPositiveTtlSeconds = 3600;
      bool rejectSingleLabel = true;
   };

private:

   struct Waiter {
      Ticket ticket;
      Callback callback;
      TimePoint deadline;
   };

   struct ActiveQuery {
      uint64_t identifier = 0;
      String hostname;
      String service;
      Family family = Family::any;
      Vector<Waiter> waiters;
   };

   struct RequestLocation {
      String key;
      uint64_t generation = 0;
   };

   struct CacheEntry {
      String key;
      Result result;
      TimePoint expires;
      CacheEntry *newer = nullptr;
      CacheEntry *older = nullptr;
   };

   struct Cache {
      bytell_hash_map<String, std::unique_ptr<CacheEntry>> entries;
      CacheEntry *newest = nullptr;
      CacheEntry *oldest = nullptr;
      size_t capacity = 0;

      void unlink(CacheEntry *entry)
      {
         if (entry->newer)
         {
            entry->newer->older = entry->older;
         }
         else
         {
            newest = entry->older;
         }

         if (entry->older)
         {
            entry->older->newer = entry->newer;
         }
         else
         {
            oldest = entry->newer;
         }

         entry->newer = nullptr;
         entry->older = nullptr;
      }

      void makeNewest(CacheEntry *entry)
      {
         if (newest == entry)
         {
            return;
         }

         if (entry->newer || entry->older || oldest == entry)
         {
            unlink(entry);
         }

         entry->older = newest;
         if (newest)
         {
            newest->newer = entry;
         }
         else
         {
            oldest = entry;
         }
         newest = entry;
      }

      void erase(CacheEntry *entry)
      {
         String key = entry->key;
         unlink(entry);
         entries.erase(key);
      }

      bool erase(const String& key)
      {
         auto it = entries.find(key);
         if (it == entries.end())
         {
            return false;
         }
         erase(it->second.get());
         return true;
      }

      bool get(const String& key, TimePoint now, Result& result)
      {
         auto it = entries.find(key);
         if (it == entries.end())
         {
            return false;
         }

         CacheEntry *entry = it->second.get();
         if (entry->expires <= now)
         {
            erase(entry);
            return false;
         }

         const auto remainingDuration = std::chrono::duration_cast<std::chrono::seconds>(entry->expires - now);
         const auto remainingCount = remainingDuration.count();
         if (remainingCount == 0)
         {
            erase(entry);
            return false;
         }

         makeNewest(entry);
         result = entry->result;
         const uint32_t remaining = remainingCount >= std::numeric_limits<uint32_t>::max()
                                        ? std::numeric_limits<uint32_t>::max()
                                        : static_cast<uint32_t>(remainingCount);

         for (Address& address : result.addresses)
         {
            if (address.ttlSeconds != 0)
            {
               address.ttlSeconds = std::min(address.ttlSeconds, remaining);
            }
         }
         if (result.canonicalNameTtlSeconds != 0)
         {
            result.canonicalNameTtlSeconds = std::min(result.canonicalNameTtlSeconds, remaining);
         }
         return true;
      }

      void put(const String& key, Result result, TimePoint expires)
      {
         if (capacity == 0)
         {
            return;
         }

         if (auto it = entries.find(key); it != entries.end())
         {
            CacheEntry *entry = it->second.get();
            entry->result = std::move(result);
            entry->expires = expires;
            makeNewest(entry);
            return;
         }

         while (entries.size() >= capacity)
         {
            erase(oldest);
         }

         auto entry = std::make_unique<CacheEntry>();
         entry->key = key;
         entry->result = std::move(result);
         entry->expires = expires;
         CacheEntry *identity = entry.get();
         entries.emplace(key, std::move(entry));
         makeNewest(identity);
      }

      void clear(void)
      {
         entries.clear();
         newest = nullptr;
         oldest = nullptr;
      }
   };

   Config config;
   Backend backend;
   TimeSource timeSource;
   StateChangeObserver stateChangeObserver;
   Cache positiveCache;
   Cache negativeCache;
   bytell_hash_map<String, std::unique_ptr<ActiveQuery>> activeByKey;
   bytell_hash_map<uint64_t, String> queryKeyByIdentifier;
   bytell_hash_map<uint64_t, RequestLocation> requestLocations;
   size_t totalWaiterCount = 0;
   uint64_t nextTicketIdentifier = 1;
   uint64_t nextTicketGeneration = 1;
   uint64_t nextQueryIdentifier = 1;
   bool stopping = false;

   static TimePoint systemNow(void *)
   {
      return Clock::now();
   }

   TimePoint now(void) const
   {
      return timeSource.now(timeSource.context);
   }

   static uint64_t advance(uint64_t& value)
   {
      uint64_t result = value++;
      if (result == 0)
      {
         result = value++;
      }
      if (value == 0)
      {
         value = 1;
      }
      return result;
   }

   Ticket issueTicket(void)
   {
      return {advance(nextTicketIdentifier), advance(nextTicketGeneration)};
   }

   static uint16_t portFromService(const String& service)
   {
      uint32_t port = 0;
      for (char character : service)
      {
         port = (port * 10) + uint32_t(character - '0');
      }
      return uint16_t(port);
   }

   static String keyFor(const NormalizedQuery& query)
   {
      String key;
      key.reserve(query.hostname.size() + query.service.size() + 3);
      key.append(query.hostname);
      key.append('\0');
      key.append(query.service);
      key.append('\0');
      key.append(char(query.family));
      return key;
   }

   static Result resultWithStatus(Status status)
   {
      Result result;
      result.status = status;
      return result;
   }

   static void deliver(Callback callback, Ticket ticket, Result result)
   {
      if (callback)
      {
         callback.function(callback.context, ticket, std::move(result));
      }
   }

   bool cached(const String& key, TimePoint current, Result& result)
   {
      if (positiveCache.get(key, current, result))
      {
         return true;
      }
      return negativeCache.get(key, current, result);
   }

   void cache(const String& key, const Result& result, TimePoint current)
   {
      if (result.status == Status::success)
      {
         uint32_t ttl = result.minimumTtlSeconds();
         ttl = std::min(ttl, config.maximumPositiveTtlSeconds);
         if (ttl > 0)
         {
            positiveCache.put(key, result, current + std::chrono::seconds(ttl));
         }
      }
      else if (result.status == Status::notFound || result.status == Status::noData)
      {
         negativeCache.put(key, result, current + std::chrono::seconds(negativeCacheTtlSeconds));
      }
   }

   void eraseLocation(const Waiter& waiter)
   {
      requestLocations.erase(waiter.ticket.identifier);
      --totalWaiterCount;
   }

   void publishStateChange(void) const
   {
      stateChangeObserver.invoke();
   }

   static bool validAddress(const Address& address)
   {
      if (address.length > sizeof(sockaddr_storage))
      {
         return false;
      }
      if (address.storage.ss_family == AF_INET)
      {
         return address.length == sizeof(sockaddr_in);
      }
      if (address.storage.ss_family == AF_INET6)
      {
         return address.length == sizeof(sockaddr_in6);
      }
      return false;
   }

public:

   AsyncDnsResolver()
       : AsyncDnsResolver(Config {}, Backend {}, TimeSource {})
   {}

   explicit AsyncDnsResolver(Config requested)
       : AsyncDnsResolver(requested, Backend {}, TimeSource {})
   {}

   AsyncDnsResolver(Config requested, Backend queryBackend, TimeSource clock)
       : AsyncDnsResolver(requested, queryBackend, clock, StateChangeObserver {})
   {}

   AsyncDnsResolver(Config requested,
                    Backend queryBackend,
                    TimeSource clock,
                    StateChangeObserver observer)
       : config(requested), backend(queryBackend), timeSource(clock), stateChangeObserver(observer)
   {
      config.positiveCacheEntries = std::min(config.positiveCacheEntries, maximumCacheEntries);
      config.negativeCacheEntries = std::min(config.negativeCacheEntries,
                                             maximumCacheEntries - config.positiveCacheEntries);
      config.activeQueries = std::min(config.activeQueries, maximumActiveQueries);
      config.waitersPerQuery = std::min(config.waitersPerQuery, maximumWaitersPerQuery);
      config.totalWaiters = std::min(config.totalWaiters, maximumTotalWaiters);
      config.answers = std::min(config.answers, maximumAnswers);
      positiveCache.capacity = config.positiveCacheEntries;
      negativeCache.capacity = config.negativeCacheEntries;
      if (timeSource.now == nullptr)
      {
         timeSource.now = systemNow;
      }
   }

   ~AsyncDnsResolver()
   {
      if (!activeByKey.empty() || !requestLocations.empty())
      {
         std::abort();
      }
   }

   AsyncDnsResolver(const AsyncDnsResolver&) = delete;
   AsyncDnsResolver& operator=(const AsyncDnsResolver&) = delete;

   static NormalizedQuery normalize(const String& hostname,
                                    const String& service,
                                    Family family,
                                    bool rejectSingleLabel = true)
   {
      NormalizedQuery query;
      query.family = family;

      if (family != Family::any && family != Family::ipv4 && family != Family::ipv6)
      {
         query.status = Status::unsupportedFamily;
         return query;
      }

      if (hostname.empty() || hostname.size() > maximumHostnameBytes || hostname[0] == '.' || hostname[hostname.size() - 1] == '.')
      {
         query.status = Status::invalidHostname;
         return query;
      }

      if (service.empty())
      {
         query.service = "0";
      }
      else
      {
         if (service.size() > 5)
         {
            query.status = Status::invalidService;
            return query;
         }

         uint32_t port = 0;
         for (char character : service)
         {
            if (character < '0' || character > '9')
            {
               query.status = Status::invalidService;
               return query;
            }
            port = (port * 10) + uint32_t(character - '0');
         }
         if (port > 65535)
         {
            query.status = Status::invalidService;
            return query;
         }
         query.service = String(port);
      }

      query.hostname.assign(hostname);
      const uint16_t port = portFromService(query.service);
      sockaddr_in address4 = {};
      sockaddr_in6 address6 = {};

      if (inet_pton(AF_INET, query.hostname.c_str(), &address4.sin_addr) == 1)
      {
         if (family == Family::ipv6)
         {
            query.status = Status::unsupportedFamily;
            return query;
         }
         address4.sin_family = AF_INET;
         address4.sin_port = htons(port);
         std::memcpy(&query.numericAddress.storage, &address4, sizeof(address4));
         query.numericAddress.length = sizeof(address4);
         query.numericAddress.ttlSeconds = std::numeric_limits<uint32_t>::max();
         query.numeric = true;
         return query;
      }

      if (inet_pton(AF_INET6, query.hostname.c_str(), &address6.sin6_addr) == 1)
      {
         if (family == Family::ipv4)
         {
            query.status = Status::unsupportedFamily;
            return query;
         }
         address6.sin6_family = AF_INET6;
         address6.sin6_port = htons(port);
         std::memcpy(&query.numericAddress.storage, &address6, sizeof(address6));
         query.numericAddress.length = sizeof(address6);
         query.numericAddress.ttlSeconds = std::numeric_limits<uint32_t>::max();
         query.numeric = true;
         return query;
      }

      bool hasDot = false;
      size_t labelStart = 0;
      for (size_t index = 0; index <= query.hostname.size(); ++index)
      {
         if (index == query.hostname.size() || query.hostname[index] == '.')
         {
            const size_t labelLength = index - labelStart;
            if (labelLength == 0 || labelLength > 63 || query.hostname[labelStart] == '-' || query.hostname[index - 1] == '-')
            {
               query.status = Status::invalidHostname;
               return query;
            }
            hasDot = hasDot || index != query.hostname.size();
            labelStart = index + 1;
            continue;
         }

         unsigned char character = static_cast<unsigned char>(query.hostname[index]);
         if (character >= 'A' && character <= 'Z')
         {
            query.hostname[index] = char(character + ('a' - 'A'));
         }
         else if ((character < 'a' || character > 'z') &&
                  (character < '0' || character > '9') &&
                  character != '-')
         {
            query.status = Status::invalidHostname;
            return query;
         }
      }

      if (rejectSingleLabel && !hasDot)
      {
         query.status = Status::singleLabelRejected;
      }
      return query;
   }

   Ticket resolve(const String& hostname,
                  const String& service,
                  Family family,
                  Callback callback,
                  TimePoint deadline = TimePoint::max())
   {
      Ticket ticket = issueTicket();
      if (stopping)
      {
         deliver(callback, ticket, resultWithStatus(Status::shutdown));
         return ticket;
      }

      NormalizedQuery normalized = normalize(hostname, service, family, config.rejectSingleLabel);
      if (!normalized.valid())
      {
         deliver(callback, ticket, resultWithStatus(normalized.status));
         return ticket;
      }

      if (normalized.numeric)
      {
         Result result;
         result.status = Status::success;
         result.canonicalName = normalized.hostname;
         result.canonicalNameTtlSeconds = std::numeric_limits<uint32_t>::max();
         result.addresses.push_back(normalized.numericAddress);
         deliver(callback, ticket, std::move(result));
         return ticket;
      }

      const TimePoint current = now();
      if (deadline <= current)
      {
         deliver(callback, ticket, resultWithStatus(Status::deadlineExceeded));
         return ticket;
      }

      const String key = keyFor(normalized);
      Result cachedResult;
      if (cached(key, current, cachedResult))
      {
         cachedResult.fromCache = true;
         deliver(callback, ticket, std::move(cachedResult));
         return ticket;
      }

      if (auto it = activeByKey.find(key); it != activeByKey.end())
      {
         ActiveQuery& active = *it->second;
         if (active.waiters.size() >= config.waitersPerQuery || totalWaiterCount >= config.totalWaiters)
         {
            deliver(callback, ticket, resultWithStatus(Status::overloaded));
            return ticket;
         }
         active.waiters.push_back({ticket, callback, deadline});
         requestLocations.emplace(ticket.identifier, RequestLocation {key, ticket.generation});
         ++totalWaiterCount;
         publishStateChange();
         return ticket;
      }

      if (!backend)
      {
         deliver(callback, ticket, resultWithStatus(Status::backendRequired));
         return ticket;
      }
      if (activeByKey.size() >= config.activeQueries || totalWaiterCount >= config.totalWaiters)
      {
         deliver(callback, ticket, resultWithStatus(Status::overloaded));
         return ticket;
      }

      auto active = std::make_unique<ActiveQuery>();
      active->identifier = advance(nextQueryIdentifier);
      active->hostname = normalized.hostname;
      active->service = normalized.service;
      active->family = normalized.family;
      active->waiters.push_back({ticket, callback, deadline});
      const uint64_t queryIdentifier = active->identifier;
      activeByKey.emplace(key, std::move(active));
      queryKeyByIdentifier.emplace(queryIdentifier, key);
      requestLocations.emplace(ticket.identifier, RequestLocation {key, ticket.generation});
      ++totalWaiterCount;
      publishStateChange();

      ActiveQuery *started = activeByKey.find(key)->second.get();
      const BackendQuery backendQuery {
         .identifier = queryIdentifier,
         .hostname = started->hostname,
         .service = started->service,
         .family = started->family
      };

      if (!backend.start(backend.context, backendQuery))
      {
         auto stillActive = activeByKey.find(key);
         if (stillActive != activeByKey.end() && stillActive->second->identifier == queryIdentifier)
         {
            BackendResult failure;
            failure.status = Status::backendRequired;
            complete(queryIdentifier, std::move(failure));
         }
      }
      return ticket;
   }

   bool complete(uint64_t queryIdentifier, BackendResult backendResult)
   {
      auto keyIt = queryKeyByIdentifier.find(queryIdentifier);
      if (keyIt == queryKeyByIdentifier.end())
      {
         return false;
      }

      String key = keyIt->second;
      auto queryIt = activeByKey.find(key);
      if (queryIt == activeByKey.end() || queryIt->second->identifier != queryIdentifier)
      {
         queryKeyByIdentifier.erase(keyIt);
         return false;
      }

      Result result;
      result.status = backendResult.status;
      result.canonicalName = std::move(backendResult.canonicalName);
      result.canonicalNameTtlSeconds = backendResult.canonicalNameTtlSeconds;
      result.timeouts = backendResult.timeouts;

      if (result.status == Status::success)
      {
         if (backendResult.addresses.empty())
         {
            result.status = Status::noData;
         }
         else if (backendResult.addresses.size() > config.answers ||
                  std::any_of(backendResult.addresses.begin(), backendResult.addresses.end(),
                              [](const Address& address) { return !validAddress(address); }))
         {
            result.status = backendResult.addresses.size() > config.answers
                                ? Status::tooManyAnswers
                                : Status::backendFailure;
         }
         else
         {
            result.addresses = std::move(backendResult.addresses);
         }
      }

      Vector<Waiter> waiters = std::move(queryIt->second->waiters);
      for (const Waiter& waiter : waiters)
      {
         eraseLocation(waiter);
      }
      activeByKey.erase(queryIt);
      queryKeyByIdentifier.erase(keyIt);
      cache(key, result, now());
      publishStateChange();

      for (size_t index = 0; index < waiters.size(); ++index)
      {
         deliver(waiters[index].callback,
                 waiters[index].ticket,
                 index + 1 == waiters.size() ? std::move(result) : Result(result));
      }
      return true;
   }

   bool cancel(Ticket ticket)
   {
      auto locationIt = requestLocations.find(ticket.identifier);
      if (locationIt == requestLocations.end() || locationIt->second.generation != ticket.generation)
      {
         return false;
      }

      auto queryIt = activeByKey.find(locationIt->second.key);
      if (queryIt == activeByKey.end())
      {
         requestLocations.erase(locationIt);
         publishStateChange();
         return false;
      }

      Vector<Waiter>& waiters = queryIt->second->waiters;
      auto waiter = std::find_if(waiters.begin(), waiters.end(), [&](const Waiter& candidate) {
         return candidate.ticket.identifier == ticket.identifier && candidate.ticket.generation == ticket.generation;
      });
      if (waiter == waiters.end())
      {
         requestLocations.erase(locationIt);
         publishStateChange();
         return false;
      }

      Callback callback = waiter->callback;
      waiters.erase(waiter);
      requestLocations.erase(locationIt);
      --totalWaiterCount;
      publishStateChange();
      deliver(callback, ticket, resultWithStatus(Status::canceled));
      return true;
   }

   size_t expireDeadlines(void)
   {
      const TimePoint current = now();
      Vector<std::pair<Ticket, Callback>> expired;

      for (auto& [key, query] : activeByKey)
      {
         (void)key;
         for (size_t index = 0; index < query->waiters.size();)
         {
            if (query->waiters[index].deadline > current)
            {
               ++index;
               continue;
            }

            Waiter waiter = query->waiters[index];
            query->waiters.erase(query->waiters.begin() + index);
            requestLocations.erase(waiter.ticket.identifier);
            --totalWaiterCount;
            expired.push_back({waiter.ticket, waiter.callback});
         }
      }

      if (!expired.empty())
      {
         publishStateChange();
      }
      for (auto& [ticket, callback] : expired)
      {
         deliver(callback, ticket, resultWithStatus(Status::deadlineExceeded));
      }
      return expired.size();
   }

   void shutdown(void)
   {
      if (stopping)
      {
         return;
      }
      stopping = true;

      Vector<std::pair<Ticket, Callback>> callbacks;
      for (auto& [key, query] : activeByKey)
      {
         (void)key;
         for (const Waiter& waiter : query->waiters)
         {
            callbacks.push_back({waiter.ticket, waiter.callback});
         }
      }

      activeByKey.clear();
      queryKeyByIdentifier.clear();
      requestLocations.clear();
      totalWaiterCount = 0;
      positiveCache.clear();
      negativeCache.clear();
      publishStateChange();

      for (auto& [ticket, callback] : callbacks)
      {
         deliver(callback, ticket, resultWithStatus(Status::shutdown));
      }
   }

   size_t activeQueryCount(void) const
   {
      return activeByKey.size();
   }

   size_t waiterCount(void) const
   {
      return totalWaiterCount;
   }

   size_t positiveCacheCount(void) const
   {
      return positiveCache.entries.size();
   }

   size_t negativeCacheCount(void) const
   {
      return negativeCache.entries.size();
   }

   void clearCache(void)
   {
      positiveCache.clear();
      negativeCache.clear();
   }

   bool invalidateCache(const String& hostname,
                        const String& service,
                        Family family)
   {
      NormalizedQuery normalized = normalize(hostname, service, family, config.rejectSingleLabel);
      if (!normalized.valid() || normalized.numeric)
      {
         return false;
      }
      const String key = keyFor(normalized);
      const bool positiveErased = positiveCache.erase(key);
      return negativeCache.erase(key) || positiveErased;
   }

   TimePoint earliestDeadline(void) const
   {
      TimePoint earliest = TimePoint::max();
      for (const auto& [key, query] : activeByKey)
      {
         (void)key;
         for (const Waiter& waiter : query->waiters)
         {
            earliest = std::min(earliest, waiter.deadline);
         }
      }
      return earliest;
   }

   bool isShutdown(void) const
   {
      return stopping;
   }

   ResolveOperation resolveAsync(const String& hostname,
                                 const String& service,
                                 Family family,
                                 TimePoint deadline = TimePoint::max(),
                                 Ticket *issuedTicket = nullptr);

};

class AsyncDnsResolver::ResolveAwaiter {
private:

   friend class ResolveOperation;

   AsyncDnsResolver *resolver;
   Ticket requestTicket;
   std::optional<Result> requestResult;
   std::coroutine_handle<> continuation;
   bool abandoned = false;

   static void complete(void *context, Ticket ticket, Result&& result)
   {
      ResolveAwaiter *awaiter = static_cast<ResolveAwaiter *>(context);
      if (awaiter->abandoned || awaiter->requestResult.has_value())
      {
         return;
      }

      awaiter->requestTicket = ticket;
      awaiter->requestResult.emplace(std::move(result));
      std::coroutine_handle<> handle = std::exchange(awaiter->continuation, {});
      if (handle)
      {
         handle.resume();
      }
   }

   ResolveAwaiter(AsyncDnsResolver& requestedResolver,
                  const String& hostname,
                  const String& service,
                  Family family,
                  TimePoint deadline,
                  Ticket *issuedTicket)
       : resolver(&requestedResolver)
   {
      requestTicket = resolver->resolve(hostname,
                                        service,
                                        family,
                                        Callback {this, complete},
                                        deadline);
      if (issuedTicket)
      {
         *issuedTicket = requestTicket;
      }
   }

public:

   ResolveAwaiter(const ResolveAwaiter&) = delete;
   ResolveAwaiter& operator=(const ResolveAwaiter&) = delete;
   ResolveAwaiter(ResolveAwaiter&&) = delete;
   ResolveAwaiter& operator=(ResolveAwaiter&&) = delete;

   ~ResolveAwaiter()
   {
      if (requestResult.has_value())
      {
         return;
      }

      abandoned = true;
      continuation = {};
      if (resolver && requestTicket)
      {
         resolver->cancel(requestTicket);
      }
   }

   bool await_ready(void) const noexcept
   {
      return requestResult.has_value();
   }

   bool await_suspend(std::coroutine_handle<> handle) noexcept
   {
      if (requestResult.has_value())
      {
         return false;
      }
      continuation = handle;
      return true;
   }

   Completion await_resume(void)
   {
      continuation = {};
      return {requestTicket, std::move(*requestResult)};
   }
};

class AsyncDnsResolver::ResolveOperation {
private:

   friend class AsyncDnsResolver;

   AsyncDnsResolver *resolver;
   String hostname;
   String service;
   Family family;
   TimePoint deadline;
   Ticket *issuedTicket;

   ResolveOperation(AsyncDnsResolver& requestedResolver,
                    const String& requestedHostname,
                    const String& requestedService,
                    Family requestedFamily,
                    TimePoint requestedDeadline,
                    Ticket *requestedTicket)
       : resolver(&requestedResolver),
         hostname(requestedHostname),
         service(requestedService),
         family(requestedFamily),
         deadline(requestedDeadline),
         issuedTicket(requestedTicket)
   {}

public:

   ResolveOperation(const ResolveOperation&) = delete;
   ResolveOperation& operator=(const ResolveOperation&) = delete;
   ResolveOperation(ResolveOperation&&) noexcept = default;
   ResolveOperation& operator=(ResolveOperation&&) noexcept = default;

   ResolveAwaiter operator co_await(void) &&
   {
      return ResolveAwaiter(*resolver,
                            hostname,
                            service,
                            family,
                            deadline,
                            issuedTicket);
   }

   ResolveAwaiter operator co_await(void) & = delete;
};

inline AsyncDnsResolver::ResolveOperation AsyncDnsResolver::resolveAsync(
    const String& hostname,
    const String& service,
    Family family,
    TimePoint deadline,
    Ticket *issuedTicket)
{
   return ResolveOperation(*this, hostname, service, family, deadline, issuedTicket);
}
