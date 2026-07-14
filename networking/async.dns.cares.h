// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/async.dns.h>
#include <networking/multiplexer.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/ring.h>

#include <ares.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <poll.h>
#include <thread>
#include <utility>

class AsyncDnsSocketEpochTracker {
private:

   bytell_hash_map<int, uint64_t> epochByFD;
   uint64_t nextEpoch = 1;

public:

   uint64_t advance(int fd)
   {
      uint64_t epoch = nextEpoch++;
      if (epoch == 0)
      {
         epoch = nextEpoch++;
      }
      if (nextEpoch == 0)
      {
         nextEpoch = 1;
      }
      epochByFD.insert_or_assign(fd, epoch);
      return epoch;
   }

   bool matches(int fd, uint64_t epoch) const
   {
      auto current = epochByFD.find(fd);
      return current != epochByFD.end() && current->second == epoch;
   }

   void erase(int fd)
   {
      epochByFD.erase(fd);
   }

   void clear(void)
   {
      epochByFD.clear();
      nextEpoch = 1;
   }
};

// RingAsyncDnsResolver is deliberately both the coordinator owner and the
// c-ares adapter. Keeping the coordinator private makes every request,
// cancellation, and waiter-deadline change refresh the one Ring timer.
class RingAsyncDnsResolver final : public AsyncDnsClient, private RingInterface {
public:

   using Resolver = AsyncDnsResolver;
   using Ticket = Resolver::Ticket;
   using Callback = Resolver::Callback;
   using Family = Resolver::Family;
   using TimePoint = Resolver::TimePoint;

   static constexpr int maximumConfiguredTimeoutMilliseconds = 30'000;
   static constexpr int maximumConfiguredTries = 3;
   static constexpr int maximumConfiguredUdpQueriesPerSocket = 10'000;
   static constexpr size_t maximumConfiguredServersBytes = 4096;
   static constexpr size_t maximumConfiguredHostsPathBytes = 4096;

   struct BackendConfig {
      int timeoutMilliseconds = 1000;
      int tries = 3;
      int maximumTimeoutMilliseconds = 2000;
      int udpMaximumQueries = 0;
      String servers;
      String hostsPath;
      LocalSocketBindSet udpBinds;
      LocalSocketBindSet tcpBinds;
      bool stayOpen = false;
   };

   enum class InitializationStatus : uint8_t {
      ready,
      anotherResolverOwnsThread,
      ringDispatcherRequired,
      libraryInitializationFailed,
      libraryNotThreadSafe,
      channelInitializationFailed,
      invalidServers,
      invalidHostsPath
   };

private:

   struct LifetimeState {
      bool alive = true;
   };

   struct Query {
      RingAsyncDnsResolver *owner = nullptr;
      uint64_t identifier = 0;
      String hostname;
      String service;
   };

   struct Completion {
      uint64_t identifier = 0;
      Resolver::BackendResult result;
   };

   struct Watch {
      int fd = -1;
      uint64_t epoch = 0;
      unsigned mask = 0;
      bool cancellationRequested = false;
   };

   struct SocketStateEvent {
      int fd = -1;
      unsigned mask = 0;
   };

   // 256 active AF_UNSPEC queries can each transition independent A, AAAA,
   // UDP, and TCP sockets off and on in one c-ares processing frame.
   static constexpr size_t maximumSocketStateEvents = 4096;
   // Current and cancellation-retiring A/AAAA/TCP watches remain bounded
   // even when all 256 coordinator queries own independent transports.
   static constexpr size_t maximumSocketWatches = 1024;

   static inline std::once_flag libraryInitializationOnce;
   static inline int libraryInitializationResult = ARES_ENOTINITIALIZED;
   static inline bool libraryIsThreadSafe = false;
   static thread_local inline RingAsyncDnsResolver *threadOwner = nullptr;

   std::shared_ptr<LifetimeState> lifetimeState = std::make_shared<LifetimeState>();
   BackendConfig backendConfig;
   LocalSocketBindPool udpBindPool;
   LocalSocketBindPool tcpBindPool;
   InitializationStatus initialization = InitializationStatus::channelInitializationFailed;
   ares_channel_t *channel = nullptr;
   bytell_hash_map<uint64_t, std::unique_ptr<Query>> queries;
   Vector<Completion> stagedCompletions;
   Vector<SocketStateEvent> stagedSocketStates;
   bytell_hash_map<int, unsigned> socketMasks;
   AsyncDnsSocketEpochTracker socketEpochs;
   bytell_hash_map<int, Ring::RawPollTicket> activeTicketByFD;
   bytell_hash_map<Ring::RawPollTicket, Watch> watches;
   TimeoutPacket timer;
   TimePoint timerDeadline = TimePoint::max();
   bool timerArmed = false;
   bool timerCancellationRequested = false;
   bool stopping = false;
   bool backendFault = false;
   bool dispatcherInstalled = false;
   std::thread::id ownerThread = std::this_thread::get_id();
   Resolver coordinator;

   void requireOwnerThread(void) const
   {
      if (std::this_thread::get_id() != ownerThread)
      {
         std::abort();
      }
   }

   static void initializeLibrary(void)
   {
      libraryInitializationResult = ares_library_init(ARES_LIB_INIT_ALL);
      if (libraryInitializationResult == ARES_SUCCESS)
      {
         libraryIsThreadSafe = ares_threadsafety() == ARES_TRUE;
      }
   }

   static bool startBackend(void *context, const Resolver::BackendQuery& query)
   {
      return static_cast<RingAsyncDnsResolver *>(context)->start(query);
   }

   static void refreshAfterCoordinatorAction(void *context)
   {
      RingAsyncDnsResolver *owner = static_cast<RingAsyncDnsResolver *>(context);
      owner->requireOwnerThread();
      owner->refreshTimer();
   }

   static ares_socket_t openSocket(int domain, int type, int protocol, void *context)
   {
      RingAsyncDnsResolver& owner = *static_cast<RingAsyncDnsResolver *>(context);
      owner.requireOwnerThread();
      const int fd = socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
      if (fd < 0)
      {
         return ARES_SOCKET_BAD;
      }
      if (type == SOCK_STREAM)
      {
         const int enabled = 1;
         if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0)
         {
            close(fd);
            return ARES_SOCKET_BAD;
         }
      }
      return fd;
   }

   static int closeSocket(ares_socket_t fd, void *context)
   {
      RingAsyncDnsResolver& owner = *static_cast<RingAsyncDnsResolver *>(context);
      owner.requireOwnerThread();
      owner.udpBindPool.release(fd);
      owner.tcpBindPool.release(fd);
      return close(fd);
   }

   static int setSocketOption(ares_socket_t fd,
                              ares_socket_opt_t option,
                              const void *value,
                              ares_socklen_t length,
                              void *)
   {
      switch (option)
      {
         case ARES_SOCKET_OPT_SENDBUF_SIZE:
         case ARES_SOCKET_OPT_RECVBUF_SIZE:
            if (length != sizeof(int))
            {
               errno = EINVAL;
               return -1;
            }
            return setsockopt(fd,
                              SOL_SOCKET,
                              option == ARES_SOCKET_OPT_SENDBUF_SIZE ? SO_SNDBUF : SO_RCVBUF,
                              value,
                              length);
         case ARES_SOCKET_OPT_BIND_DEVICE:
#ifdef SO_BINDTODEVICE
            return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, value, length);
#else
            errno = ENOSYS;
            return -1;
#endif
         case ARES_SOCKET_OPT_TCP_FASTOPEN:
#ifdef TCP_FASTOPEN_CONNECT
         {
            if (length != sizeof(ares_bool_t))
            {
               errno = EINVAL;
               return -1;
            }
            const int enabled = *static_cast<const ares_bool_t *>(value) != ARES_FALSE;
            return setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &enabled, sizeof(enabled));
         }
#else
            errno = ENOSYS;
            return -1;
#endif
      }
      errno = ENOSYS;
      return -1;
   }

   static int connectSocket(ares_socket_t fd,
                            const sockaddr *address,
                            ares_socklen_t length,
                            unsigned int,
                            void *context)
   {
      RingAsyncDnsResolver& owner = *static_cast<RingAsyncDnsResolver *>(context);
      owner.requireOwnerThread();
      int type = 0;
      socklen_t typeLength = sizeof(type);
      if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typeLength) != 0)
      {
         return -1;
      }
      LocalSocketBindPool *pool = type == SOCK_DGRAM
                                      ? &owner.udpBindPool
                                      : type == SOCK_STREAM ? &owner.tcpBindPool : nullptr;
      const LocalSocketBindSet *binds = type == SOCK_DGRAM
                                            ? &owner.backendConfig.udpBinds
                                            : type == SOCK_STREAM ? &owner.backendConfig.tcpBinds : nullptr;
      if (pool == nullptr)
      {
         errno = EPROTOTYPE;
         return -1;
      }
      if (!binds->empty() && !pool->acquireAndBind(fd, address, length, type))
      {
         return -1;
      }
      const int result = connect(fd, address, length);
      const int error = errno;
      if (result != 0 && error != EINPROGRESS && error != EALREADY && error != EWOULDBLOCK)
      {
         pool->release(fd);
      }
      errno = error;
      return result;
   }

   static ares_ssize_t receiveSocket(ares_socket_t fd,
                                     void *buffer,
                                     size_t length,
                                     int flags,
                                     sockaddr *address,
                                     ares_socklen_t *addressLength,
                                     void *)
   {
      return recvfrom(fd, buffer, length, flags, address, addressLength);
   }

   static ares_ssize_t sendSocket(ares_socket_t fd,
                                  const void *buffer,
                                  size_t length,
                                  int flags,
                                  const sockaddr *address,
                                  ares_socklen_t addressLength,
                                  void *)
   {
      return address
                 ? sendto(fd, buffer, length, flags, address, addressLength)
                 : send(fd, buffer, length, flags);
   }

   static int socketName(ares_socket_t fd,
                         sockaddr *address,
                         ares_socklen_t *addressLength,
                         void *)
   {
      return getsockname(fd, address, addressLength);
   }

   static Resolver::Status statusFromAres(int status, bool shuttingDown)
   {
      switch (status)
      {
         case ARES_SUCCESS:
            return Resolver::Status::success;
         case ARES_ENODATA:
            return Resolver::Status::noData;
         case ARES_ENOTFOUND:
         case ARES_ENONAME:
            return Resolver::Status::notFound;
         case ARES_EBADNAME:
            return Resolver::Status::invalidHostname;
         case ARES_EBADFAMILY:
            return Resolver::Status::unsupportedFamily;
         case ARES_ESERVICE:
            return Resolver::Status::invalidService;
         case ARES_ECANCELLED:
            return Resolver::Status::canceled;
         case ARES_EDESTRUCTION:
            return shuttingDown ? Resolver::Status::shutdown : Resolver::Status::backendFailure;
         default:
            return Resolver::Status::backendFailure;
      }
   }

   static uint32_t ttlFromAres(int ttl)
   {
      return ttl <= 0 ? 0 : uint32_t(ttl);
   }

   static void addrInfoCallback(void *context, int status, int timeouts, ares_addrinfo *answer)
   {
      Query *query = static_cast<Query *>(context);
      if (query == nullptr || query->owner == nullptr)
      {
         if (answer)
         {
            ares_freeaddrinfo(answer);
         }
         return;
      }

      RingAsyncDnsResolver& owner = *query->owner;
      owner.requireOwnerThread();
      Resolver::BackendResult result;
      result.status = statusFromAres(status, owner.stopping);
      result.timeouts = timeouts < 0 ? 0 : uint32_t(timeouts);

      if (status == ARES_SUCCESS && answer)
      {
         size_t answerCount = 0;
         for (ares_addrinfo_node *node = answer->nodes; node; node = node->ai_next)
         {
            if (node->ai_family != AF_INET && node->ai_family != AF_INET6)
            {
               continue;
            }
            if (++answerCount > Resolver::maximumAnswers)
            {
               result.status = Resolver::Status::tooManyAnswers;
               result.addresses.clear();
               break;
            }

            const socklen_t expectedLength = node->ai_family == AF_INET
                                                 ? sizeof(sockaddr_in)
                                                 : sizeof(sockaddr_in6);
            if (node->ai_addr == nullptr || node->ai_addrlen != expectedLength)
            {
               result.status = Resolver::Status::backendFailure;
               result.addresses.clear();
               break;
            }

            Resolver::Address address;
            std::memcpy(&address.storage, node->ai_addr, expectedLength);
            address.length = expectedLength;
            address.ttlSeconds = ttlFromAres(node->ai_ttl);
            result.addresses.push_back(address);
         }

         uint32_t canonicalTtl = std::numeric_limits<uint32_t>::max();
         for (ares_addrinfo_cname *cname = answer->cnames; cname; cname = cname->next)
         {
            if (cname->name && cname->name[0] != '\0')
            {
               result.canonicalName.assign(cname->name);
            }
            const uint32_t ttl = ttlFromAres(cname->ttl);
            if (ttl > 0)
            {
               canonicalTtl = std::min(canonicalTtl, ttl);
            }
         }
         if (result.canonicalName.empty() && answer->name)
         {
            result.canonicalName.assign(answer->name);
         }
         result.canonicalNameTtlSeconds = canonicalTtl == std::numeric_limits<uint32_t>::max()
                                               ? 0
                                               : canonicalTtl;
      }

      if (answer)
      {
         ares_freeaddrinfo(answer);
      }
      owner.stagedCompletions.push_back({query->identifier, std::move(result)});
   }

   static void socketStateCallback(void *context, ares_socket_t fd, int readable, int writable)
   {
      RingAsyncDnsResolver *owner = static_cast<RingAsyncDnsResolver *>(context);
      if (owner == nullptr || fd < 0)
      {
         return;
      }

      owner->requireOwnerThread();

      unsigned mask = 0;
      if (readable)
      {
         mask |= POLLIN;
      }
      if (writable)
      {
         mask |= POLLOUT;
      }
      if (owner->stagedSocketStates.size() >= maximumSocketStateEvents)
      {
         owner->backendFault = true;
         return;
      }
      owner->stagedSocketStates.push_back({fd, mask});
   }

   void cancelWatch(Ring::RawPollTicket ticket)
   {
      auto watch = watches.find(ticket);
      if (watch == watches.end() || watch->second.cancellationRequested)
      {
         return;
      }
      watch->second.cancellationRequested = true;
      (void)Ring::cancelRawFDPoll(ticket);
   }

   bool armWatch(int fd, unsigned mask)
   {
      if (watches.size() >= maximumSocketWatches)
      {
         backendFault = true;
         return false;
      }

      const uint64_t epoch = socketEpochs.advance(fd);
      const Ring::RawPollTicket ticket = Ring::queueRawFDPoll(this, epoch, fd, mask);
      if (ticket == Ring::invalidRawPollTicket)
      {
         backendFault = true;
         return false;
      }
      watches.emplace(ticket, Watch {.fd = fd, .epoch = epoch, .mask = mask});
      activeTicketByFD.insert_or_assign(fd, ticket);
      return true;
   }

   void applyStagedSocketStates(void)
   {
      if (!stagedSocketStates.empty())
      {
         Vector<SocketStateEvent> staged = std::move(stagedSocketStates);
         stagedSocketStates.clear();
         for (const SocketStateEvent& event : staged)
         {
            const unsigned previous = socketMasks.contains(event.fd) ? socketMasks.find(event.fd)->second : 0;
            if (previous == event.mask)
            {
               continue;
            }

            if (auto active = activeTicketByFD.find(event.fd); active != activeTicketByFD.end())
            {
               cancelWatch(active->second);
               activeTicketByFD.erase(active);
            }

            // Every state transition invalidates the previous fd incarnation,
            // including a close/open pair collapsed onto the same integer fd.
            if (event.mask == 0)
            {
               socketEpochs.erase(event.fd);
               socketMasks.erase(event.fd);
            }
            else
            {
               socketEpochs.advance(event.fd);
               socketMasks.insert_or_assign(event.fd, event.mask);
            }
         }
      }

      if (stopping || channel == nullptr)
      {
         return;
      }

      for (const auto& [fd, mask] : socketMasks)
      {
         if (mask == 0 || activeTicketByFD.contains(fd))
         {
            continue;
         }

         if (!armWatch(fd, mask))
         {
            break;
         }
      }
   }

   void failQueriesAfterBackendFault(void)
   {
      if (!backendFault || channel == nullptr || stopping)
      {
         return;
      }

      backendFault = false;
      Vector<uint64_t> identifiers;
      identifiers.reserve(queries.size());
      for (const auto& [identifier, query] : queries)
      {
         (void)query;
         identifiers.push_back(identifier);
      }

      stagedCompletions.clear();
      stagedSocketStates.clear();
      ares_cancel(channel);
      stagedCompletions.clear();
      for (uint64_t identifier : identifiers)
      {
         Resolver::BackendResult failure;
         failure.status = Resolver::Status::backendFailure;
         stagedCompletions.push_back({identifier, std::move(failure)});
      }
   }

   void drainCompletions(void)
   {
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      if (!lifetime->alive)
      {
         queries.clear();
         stagedCompletions.clear();
         return;
      }
      while (!stagedCompletions.empty())
      {
         Vector<Completion> completions = std::move(stagedCompletions);
         stagedCompletions.clear();
         for (Completion& completion : completions)
         {
            queries.erase(completion.identifier);
            (void)coordinator.complete(completion.identifier, std::move(completion.result));
            if (!lifetime->alive)
            {
               return;
            }
         }
      }
   }

   TimePoint cAresDeadline(void) const
   {
      if (channel == nullptr || queries.empty())
      {
         return TimePoint::max();
      }

      timeval interval = {};
      timeval *value = ares_timeout(channel, nullptr, &interval);
      if (value == nullptr)
      {
         return TimePoint::max();
      }
      const auto duration = std::chrono::seconds(value->tv_sec) +
                            std::chrono::microseconds(value->tv_usec);
      return Resolver::Clock::now() + duration;
   }

   TimePoint requiredTimerDeadline(void) const
   {
      return std::min(coordinator.earliestDeadline(), cAresDeadline());
   }

   void armTimer(TimePoint deadline)
   {
      auto delay = std::chrono::duration_cast<std::chrono::microseconds>(deadline - Resolver::Clock::now());
      if (delay <= std::chrono::microseconds::zero())
      {
         delay = std::chrono::milliseconds(1);
      }

      timer.clear();
      timer.setTimeoutUs(uint64_t(delay.count()));
      timerDeadline = deadline;
      timerArmed = true;
      Ring::queueTimeout(&timer);
   }

   void refreshTimer(void)
   {
      const TimePoint required = stopping ? TimePoint::max() : requiredTimerDeadline();
      if (!timerArmed)
      {
         if (required != TimePoint::max())
         {
            armTimer(required);
         }
         return;
      }

      if (timerCancellationRequested || required == timerDeadline)
      {
         return;
      }

      // The packet identity is not submitted again until the original timeout
      // acknowledges either expiry or cancellation.
      timerCancellationRequested = true;
      Ring::queueCancelTimeout(&timer);
   }

   void afterCaresFrame(void)
   {
      applyStagedSocketStates();
      failQueriesAfterBackendFault();
      applyStagedSocketStates();
      refreshTimer();
      retireDispatcherIfSafe();
      drainCompletions();
   }

   bool start(const Resolver::BackendQuery& request)
   {
      if (stopping)
      {
         return false;
      }
      if (channel == nullptr)
      {
         Resolver::BackendResult failure;
         failure.status = Resolver::Status::backendFailure;
         stagedCompletions.push_back({request.identifier, std::move(failure)});
         drainCompletions();
         return true;
      }

      auto query = std::make_unique<Query>();
      query->owner = this;
      query->identifier = request.identifier;
      query->hostname.assign(request.hostname);
      query->service.assign(request.service);
      Query *context = query.get();
      queries.emplace(request.identifier, std::move(query));

      ares_addrinfo_hints hints = {};
      hints.ai_family = request.family == Family::ipv4
                            ? AF_INET
                            : request.family == Family::ipv6 ? AF_INET6 : AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_NOSORT | ARES_AI_NUMERICSERV;
      ares_getaddrinfo(channel,
                       context->hostname.c_str(),
                       context->service.c_str(),
                       &hints,
                       addrInfoCallback,
                       context);
      afterCaresFrame();
      return true;
   }

   void processEvents(const ares_fd_events_t *events, size_t count)
   {
      if (channel)
      {
         const int status = ares_process_fds(channel, events, count, ARES_PROCESS_FLAG_NONE);
         if (status != ARES_SUCCESS)
         {
            // Individual query callbacks retain their authoritative c-ares
            // status; a process-frame error is retried by the channel timer.
         }
      }
      afterCaresFrame();
   }

   bool teardownSafe(void) const
   {
      return channel == nullptr &&
             queries.empty() &&
             watches.empty() &&
             activeTicketByFD.empty() &&
             socketMasks.empty() &&
             stagedSocketStates.empty() &&
             !timerArmed &&
             stagedCompletions.empty() &&
             udpBindPool.drained() &&
             tcpBindPool.drained();
   }

   void retireDispatcherIfSafe(void)
   {
      if (!stopping || !dispatcherInstalled || !teardownSafe())
      {
         return;
      }
      RingDispatcher::eraseMultiplexee(this);
      dispatcherInstalled = false;
      if (threadOwner == this)
      {
         threadOwner = nullptr;
      }
   }

   void rawFDPollHandler(void *owner, uint64_t generation, uint64_t ticket, int result) override
   {
      requireOwnerThread();
      if (owner != this)
      {
         return;
      }

      auto watch = watches.find(ticket);
      if (watch == watches.end() || watch->second.epoch != generation)
      {
         return;
      }

      const Watch completed = watch->second;
      const auto active = activeTicketByFD.find(completed.fd);
      const bool wasCurrent = active != activeTicketByFD.end() &&
                              active->second == ticket &&
                              socketEpochs.matches(completed.fd, completed.epoch);
      watches.erase(watch);
      if (wasCurrent)
      {
         activeTicketByFD.erase(active);
      }

      if (wasCurrent && !stopping && channel && result != -ECANCELED &&
          socketMasks.contains(completed.fd) && completed.epoch == generation)
      {
         unsigned events = 0;
         if (result < 0 || (unsigned(result) & (POLLIN | POLLERR | POLLHUP | POLLNVAL)))
         {
            events |= ARES_FD_EVENT_READ;
         }
         if (result < 0 || (unsigned(result) & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)))
         {
            events |= ARES_FD_EVENT_WRITE;
         }
         const ares_fd_events_t ready {.fd = completed.fd, .events = events};
         processEvents(&ready, 1);
         return;
      }

      applyStagedSocketStates();
      refreshTimer();
      retireDispatcherIfSafe();
   }

   void timeoutHandler(TimeoutPacket *packet, int result) override
   {
      requireOwnerThread();
      if (packet != &timer)
      {
         return;
      }

      timerArmed = false;
      timerCancellationRequested = false;
      timerDeadline = TimePoint::max();
      timer.clear();

      if (!stopping && result != -ECANCELED)
      {
         (void)coordinator.expireDeadlines();
         processEvents(nullptr, 0);
         return;
      }

      refreshTimer();
      retireDispatcherIfSafe();
   }

public:

   RingAsyncDnsResolver()
       : RingAsyncDnsResolver(Resolver::Config {}, BackendConfig {})
   {}

   explicit RingAsyncDnsResolver(Resolver::Config resolverConfig)
       : RingAsyncDnsResolver(resolverConfig, BackendConfig {})
   {}

   RingAsyncDnsResolver(Resolver::Config resolverConfig, BackendConfig requestedBackend)
       : backendConfig(std::move(requestedBackend)),
         udpBindPool(backendConfig.udpBinds),
         tcpBindPool(backendConfig.tcpBinds),
         coordinator(resolverConfig,
                     Resolver::Backend {.context = this, .start = startBackend},
                     Resolver::TimeSource {},
                     Resolver::StateChangeObserver {this, refreshAfterCoordinatorAction})
   {
      timer.originator = this;
      timer.dispatcher = nullptr;

      if (threadOwner)
      {
         initialization = InitializationStatus::anotherResolverOwnsThread;
         return;
      }

      RingDispatcher& dispatcher = RingDispatcher::current();
      if (Ring::interfacer != &dispatcher)
      {
         initialization = InitializationStatus::ringDispatcherRequired;
         return;
      }

      std::call_once(libraryInitializationOnce, initializeLibrary);
      if (libraryInitializationResult != ARES_SUCCESS)
      {
         initialization = InitializationStatus::libraryInitializationFailed;
         return;
      }
      if (!libraryIsThreadSafe)
      {
         initialization = InitializationStatus::libraryNotThreadSafe;
         return;
      }
      if (backendConfig.servers.size() > maximumConfiguredServersBytes)
      {
         initialization = InitializationStatus::invalidServers;
         return;
      }
      if (backendConfig.hostsPath.size() > maximumConfiguredHostsPathBytes)
      {
         initialization = InitializationStatus::invalidHostsPath;
         return;
      }

      ares_options options = {};
      options.flags = ARES_FLAG_NOSEARCH | ARES_FLAG_NOALIASES |
                      (backendConfig.stayOpen ? ARES_FLAG_STAYOPEN : 0);
      options.timeout = std::clamp(backendConfig.timeoutMilliseconds, 1, maximumConfiguredTimeoutMilliseconds);
      options.tries = std::clamp(backendConfig.tries, 1, maximumConfiguredTries);
      options.maxtimeout = std::clamp(backendConfig.maximumTimeoutMilliseconds,
                                     options.timeout,
                                     maximumConfiguredTimeoutMilliseconds);
      options.udp_max_queries = std::clamp(backendConfig.udpMaximumQueries,
                                           0,
                                           maximumConfiguredUdpQueriesPerSocket);
      options.qcache_max_ttl = 0;
      options.sock_state_cb = socketStateCallback;
      options.sock_state_cb_data = this;
      options.hosts_path = backendConfig.hostsPath.empty()
                               ? nullptr
                               : const_cast<char *>(backendConfig.hostsPath.c_str());
      char hostsFirstLookups[] = "fb";
      options.lookups = options.hosts_path ? hostsFirstLookups : nullptr;
      int optionMask = ARES_OPT_FLAGS |
                       ARES_OPT_TIMEOUTMS |
                       ARES_OPT_TRIES |
                       ARES_OPT_MAXTIMEOUTMS |
                       ARES_OPT_QUERY_CACHE |
                       ARES_OPT_SOCK_STATE_CB;
      if (options.hosts_path)
      {
         optionMask |= ARES_OPT_HOSTS_FILE | ARES_OPT_LOOKUPS;
      }
      if (options.udp_max_queries > 0)
      {
         optionMask |= ARES_OPT_UDP_MAX_QUERIES;
      }
      if (ares_init_options(&channel, &options, optionMask) != ARES_SUCCESS)
      {
         channel = nullptr;
         initialization = InitializationStatus::channelInitializationFailed;
         return;
      }

      if (!backendConfig.servers.empty() &&
          ares_set_servers_ports_csv(channel, backendConfig.servers.c_str()) != ARES_SUCCESS)
      {
         ares_destroy(channel);
         channel = nullptr;
         initialization = InitializationStatus::invalidServers;
         return;
      }
      ares_socket_functions_ex socketFunctions = {};
      socketFunctions.version = 1;
      socketFunctions.flags = ARES_SOCKFUNC_FLAG_NONBLOCKING;
      socketFunctions.asocket = openSocket;
      socketFunctions.aclose = closeSocket;
      socketFunctions.asetsockopt = setSocketOption;
      socketFunctions.aconnect = connectSocket;
      socketFunctions.arecvfrom = receiveSocket;
      socketFunctions.asendto = sendSocket;
      socketFunctions.agetsockname = socketName;
      if (ares_set_socket_functions_ex(channel, &socketFunctions, this) != ARES_SUCCESS)
      {
         ares_destroy(channel);
         channel = nullptr;
         initialization = InitializationStatus::channelInitializationFailed;
         return;
      }

      threadOwner = this;
      RingDispatcher::installMultiplexee(this, this);
      dispatcherInstalled = true;
      initialization = InitializationStatus::ready;
   }

   ~RingAsyncDnsResolver()
   {
      requireOwnerThread();
      lifetimeState->alive = false;
      shutdown();
      if (!teardownSafe())
      {
         std::abort();
      }
      retireDispatcherIfSafe();
   }

   RingAsyncDnsResolver(const RingAsyncDnsResolver&) = delete;
   RingAsyncDnsResolver& operator=(const RingAsyncDnsResolver&) = delete;

   bool ready(void) const override
   {
      requireOwnerThread();
      return initialization == InitializationStatus::ready && !stopping;
   }

   InitializationStatus initializationStatus(void) const
   {
      requireOwnerThread();
      return initialization;
   }

   Ticket resolve(const String& hostname,
                  const String& service,
                  Family family,
                  Callback callback,
                  TimePoint deadline = TimePoint::max()) override
   {
      requireOwnerThread();
      return coordinator.resolve(hostname, service, family, callback, deadline);
   }

   bool cancel(Ticket ticket) override
   {
      requireOwnerThread();
      return coordinator.cancel(ticket);
   }

   Resolver::ResolveOperation resolveAsync(const String& hostname,
                                           const String& service,
                                           Family family,
                                           TimePoint deadline = TimePoint::max(),
                                           Ticket *issuedTicket = nullptr)
   {
      requireOwnerThread();
      return coordinator.resolveAsync(hostname,
                                      service,
                                      family,
                                      deadline,
                                      issuedTicket);
   }

   size_t expireDeadlines(void)
   {
      requireOwnerThread();
      return coordinator.expireDeadlines();
   }

   bool invalidateCache(const String& hostname, const String& service, Family family)
   {
      requireOwnerThread();
      return coordinator.invalidateCache(hostname, service, family);
   }

   bool reloadConfiguration(void)
   {
      requireOwnerThread();
      if (stopping || channel == nullptr)
      {
         return false;
      }
      const int status = ares_reinit(channel);
      const int serverStatus = status == ARES_SUCCESS && !backendConfig.servers.empty()
                                   ? ares_set_servers_ports_csv(channel, backendConfig.servers.c_str())
                                   : ARES_SUCCESS;
      afterCaresFrame();
      if (status != ARES_SUCCESS || serverStatus != ARES_SUCCESS)
      {
         return false;
      }
      coordinator.clearCache();
      return true;
   }

   bool shutdown(void)
   {
      requireOwnerThread();
      if (!stopping)
      {
         stopping = true;
         coordinator.shutdown();
         if (channel)
         {
            ares_destroy(channel);
            channel = nullptr;
         }
         applyStagedSocketStates();
         drainCompletions();

         for (auto& [ticket, watch] : watches)
         {
            (void)watch;
            cancelWatch(ticket);
         }
         activeTicketByFD.clear();
         socketMasks.clear();
         socketEpochs.clear();
         refreshTimer();
      }
      retireDispatcherIfSafe();
      return teardownSafe();
   }

   bool shutdownSafe(void) const
   {
      requireOwnerThread();
      return stopping && teardownSafe();
   }

   size_t activeQueryCount(void) const
   {
      requireOwnerThread();
      return coordinator.activeQueryCount();
   }

   size_t waiterCount(void) const
   {
      requireOwnerThread();
      return coordinator.waiterCount();
   }

   size_t positiveCacheCount(void) const
   {
      requireOwnerThread();
      return coordinator.positiveCacheCount();
   }

   size_t negativeCacheCount(void) const
   {
      requireOwnerThread();
      return coordinator.negativeCacheCount();
   }

   size_t activeWatcherCount(void) const
   {
      requireOwnerThread();
      return watches.size();
   }

   bool idle(void) const
   {
      requireOwnerThread();
      return coordinator.activeQueryCount() == 0 &&
             queries.empty() &&
             watches.empty() &&
             stagedSocketStates.empty() &&
             stagedCompletions.empty() &&
             !timerArmed;
   }

};
