// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/async.dns.h>
#include <networking/happy.eyeballs.h>
#include <networking/multiplexer.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/ring.h>

#include <curl/curl.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

class MultiCurlClient final : private RingInterface
{
public:

   using Clock = std::chrono::steady_clock;
   using TimePoint = Clock::time_point;

   static constexpr size_t maximumTransfers = 256;
   static constexpr size_t maximumRequestBytes = 16 * 1024 * 1024;
   static constexpr size_t maximumHeaderBytes = 32 * 1024;
   static constexpr size_t maximumResponseBytes = 16 * 1024 * 1024;
   static constexpr size_t maximumUrlBytes = 8192;
   static constexpr size_t maximumRequestHeaders = 32;
   static constexpr size_t maximumHeaderLineBytes = 8192;
   static constexpr size_t maximumSocketWatches = 1024;
   static constexpr size_t maximumStagedSocketEvents = 4096;
   static constexpr size_t maximumConcurrentStreams = 32;

   enum class Status : uint8_t
   {
      success,
      canceled,
      deadlineExceeded,
      invalidRequest,
      unsupportedProtocol,
      overloaded,
      dnsFailure,
      addressRejected,
      initializationFailure,
      transportFailure,
      requestTooLarge,
      headersTooLarge,
      responseTooLarge,
      invalidResponse,
      httpVersionRejected,
      reset,
      shutdown
   };

   enum class Method : uint8_t
   {
      get,
      head,
      post,
      put,
      delete_
   };

   enum class HttpPolicy : uint8_t
   {
      preferHttp2,
      requireHttp2,
      requireHttp1
   };

   enum class TlsMinimum : uint8_t
   {
      tls12,
      tls13
   };

   enum class CaSource : uint8_t
   {
      system,
      file,
      path,
      blob
   };

   enum class InitializationStatus : uint8_t
   {
      ready,
      ringDispatcherRequired,
      threadClientAlreadyExists,
      curlInitializationFailed,
      sslRequired,
      http2Required
   };

   struct Ticket
   {
      uint64_t identifier = 0;
      uint64_t generation = 0;

      explicit operator bool(void) const
      {
         return identifier != 0 && generation != 0;
      }
   };

   struct AddressPolicy
   {
      void *context = nullptr;
      bool (*accept)(void *context, const AsyncDnsResolver::Address& address) = nullptr;

      bool accepts(const AsyncDnsResolver::Address& address) const
      {
         return accept == nullptr || accept(context, address);
      }
   };

   struct OriginPolicy
   {
      void *context = nullptr;
      String requiredScheme;
      String requiredHost;
      String requiredAuthority;
      String requiredService;
      String requiredResolveHost;
      bool (*accept)(void *context,
                     const String& scheme,
                     const String& host,
                     const String& authority,
                     const String& service,
                     const String& resolveHost) = nullptr;

      bool accepts(const String& scheme,
                   const String& host,
                   const String& authority,
                   const String& service,
                   const String& resolveHost) const
      {
         if ((!requiredScheme.empty() && requiredScheme != scheme) ||
             (!requiredHost.empty() && requiredHost != host) ||
             (!requiredAuthority.empty() && requiredAuthority != authority) ||
             (!requiredService.empty() && requiredService != service) ||
             (!requiredResolveHost.empty() && requiredResolveHost != resolveHost))
         {
            return false;
         }
         return accept == nullptr || accept(context, scheme, host, authority, service, resolveHost);
      }
   };

   struct Header
   {
      String name;
      String value;
   };

   struct Config
   {
      size_t transfers = 64;
      size_t requestBytes = 4 * 1024 * 1024;
      size_t headerBytes = 16 * 1024;
      size_t responseBytes = 8 * 1024 * 1024;
      size_t totalConnections = 64;
      size_t hostConnections = 16;
      size_t concurrentStreams = maximumConcurrentStreams;
      std::chrono::milliseconds defaultConnectTimeout = std::chrono::seconds(10);
      std::chrono::milliseconds defaultFirstByteTimeout = std::chrono::seconds(15);
      std::chrono::milliseconds defaultIdleTimeout = std::chrono::seconds(15);
      std::chrono::milliseconds defaultOverallTimeout = std::chrono::seconds(30);
      LocalSocketBindSet localBinds;
   };

   struct Request
   {
      String url;
      String resolveHost;
      String authority;
      Method method = Method::get;
      HttpPolicy httpPolicy = HttpPolicy::preferHttp2;
      TlsMinimum tlsMinimum = TlsMinimum::tls12;
      Vector<Header> headers;
      String body;
      CaSource caSource = CaSource::system;
      String caFile;
      String caPath;
      String caBlob;
      String clientCertificateFile;
      String clientKeyFile;
      String clientCertificateBlob;
      String clientKeyBlob;
      AsyncDnsResolver::Family family = AsyncDnsResolver::Family::any;
      AddressPolicy addressPolicy;
      OriginPolicy originPolicy;
      std::chrono::milliseconds connectTimeout = {};
      std::chrono::milliseconds firstByteTimeout = {};
      std::chrono::milliseconds idleTimeout = {};
      size_t responseBytes = 0;
      TimePoint overallDeadline = TimePoint::max();
      uint64_t resolutionGeneration = 0;
      uint64_t identityGeneration = 0;
      bool requireTls = true;
      bool pathAsIs = false;
   };

   struct Result
   {
      Status status = Status::transportFailure;
      CURLcode curlCode = CURLE_OK;
      long statusCode = 0;
      long httpVersion = CURL_HTTP_VERSION_NONE;
      String effectiveUrl;
      String location;
      String headers;
      String body;
      uint32_t resolvedTtlSeconds = 0;

      bool succeeded(void) const
      {
         return status == Status::success;
      }
   };

   struct Callback
   {
      // The client and callback context must outlive every callback. A callback
      // may request shutdown, but must not destroy the client; destruction is
      // valid only after shutdownSafe() reports true.
      void *context = nullptr;
      void (*function)(void *context, Ticket ticket, Result&& result) = nullptr;

      explicit operator bool(void) const
      {
         return function != nullptr;
      }
   };

private:

   enum class TransferState : uint8_t
   {
      resolving,
      active
   };

   struct LifetimeState
   {
      bool alive = true;
   };

   struct Transfer
   {
      MultiCurlClient *owner = nullptr;
      Ticket ticket;
      Request request;
      Callback callback;
      TransferState state = TransferState::resolving;
      AsyncDnsResolver::Ticket dnsTicket;
      CURL *easy = nullptr;
      curl_slist *requestHeaders = nullptr;
      curl_slist *resolveRules = nullptr;
      String scheme;
      String host;
      String connectHost;
      String service;
      Vector<AsyncDnsResolver::Address> approvedAddresses;
      Result result;
      TimePoint submitted = Clock::now();
      TimePoint firstByteDeadline = TimePoint::max();
      TimePoint overallDeadline = TimePoint::max();
      TimePoint resolutionExpires = TimePoint::max();
      TimePoint lastActivity = Clock::now();
      std::chrono::milliseconds idleTimeout = {};
      size_t responseLimit = 0;
      size_t responseHeaderCount = 0;
      size_t declaredContentLength = 0;
      bool contentLengthSeen = false;
      bool locationSeen = false;
      bool firstByteSeen = false;
      bool headerOverflow = false;
      bool bodyOverflow = false;
      bool invalidHeaders = false;
      bool pinExpired = false;
      uint8_t pinRefreshes = 0;
      bool addedToMulti = false;
      Status forcedStatus = Status::success;

      ~Transfer()
      {
         if (easy)
         {
            curl_easy_cleanup(easy);
         }
         if (requestHeaders)
         {
            curl_slist_free_all(requestHeaders);
         }
         if (resolveRules)
         {
            curl_slist_free_all(resolveRules);
         }
      }
   };

   struct SocketState
   {
      unsigned mask = 0;
      uint64_t generation = 0;
      Ring::RawPollTicket activeTicket = Ring::invalidRawPollTicket;
   };

   struct Watch
   {
      int fd = -1;
      uint64_t generation = 0;
      bool cancellationRequested = false;
   };

   struct SocketEvent
   {
      int fd = -1;
      unsigned mask = 0;
   };

   struct DeferredCompletion
   {
      Callback callback;
      Ticket ticket;
      Result result;
   };

   struct ConnectionIdentity
   {
      uint64_t resolution = 0;
      uint64_t credentials = 0;
      String pins;
   };

   static inline std::once_flag curlInitializationOnce;
   static inline CURLcode curlInitializationResult = CURLE_FAILED_INIT;
   static thread_local inline MultiCurlClient *threadOwner = nullptr;

   std::shared_ptr<LifetimeState> lifetimeState = std::make_shared<LifetimeState>();
   Config config;
   LocalSocketBindPool bindPool;
   AsyncDnsClient& resolver;
   InitializationStatus initialization = InitializationStatus::curlInitializationFailed;
   CURLM *multi = nullptr;
   bytell_hash_map<uint64_t, std::unique_ptr<Transfer>> transfers;
   bytell_hash_map<CURL *, uint64_t> ticketByEasy;
   Vector<CURL *> orphanedEasyHandles;
   bytell_hash_map<String, ConnectionIdentity> connectionIdentityByOrigin;
   bytell_hash_map<int, SocketState> sockets;
   bytell_hash_map<Ring::RawPollTicket, Watch> watches;
   Vector<SocketEvent> stagedSocketEvents;
   Vector<DeferredCompletion> deferredCompletions;
   TimeoutPacket timer;
   TimePoint requestedTimerDeadline = TimePoint::max();
   TimePoint armedTimerDeadline = TimePoint::max();
   bool timerArmed = false;
   bool timerCancellationRequested = false;
   bool socketEventOverflow = false;
   bool resetting = false;
   bool fatalMulti = false;
   bool deferCallbacks = false;
   uint32_t curlFrameDepth = 0;
   bool policyCallbackActive = false;
   bool callbackActive = false;
   bool stopping = false;
   bool dispatcherInstalled = false;
   uint64_t nextTicketIdentifier = 1;
   uint64_t nextTicketGeneration = 1;
   uint64_t nextSocketGeneration = 1;
   uint64_t multiGeneration = 0;
   uint64_t nextMultiGeneration = 1;
   std::thread::id ownerThread = std::this_thread::get_id();

   static void initializeCurl(void)
   {
      curlInitializationResult = curl_global_init(CURL_GLOBAL_DEFAULT);
   }

   void requireOwnerThread(void) const
   {
      if (std::this_thread::get_id() != ownerThread)
      {
         std::abort();
      }
   }

   static uint64_t advance(uint64_t& value)
   {
      uint64_t current = value++;
      if (current == 0)
      {
         current = value++;
      }
      if (value == 0)
      {
         value = 1;
      }
      return current;
   }

   static constexpr Status exhaustedBindStatus = Status::overloaded;
   static_assert(exhaustedBindStatus == Status::overloaded);

   static constexpr Status statusForBindFailure(LocalSocketBindPool::AcquireStatus status)
   {
      return status == LocalSocketBindPool::AcquireStatus::exhausted
                 ? exhaustedBindStatus
                 : Status::transportFailure;
   }

   Ticket issueTicket(void)
   {
      return {advance(nextTicketIdentifier), advance(nextTicketGeneration)};
   }

   void deliverNow(Callback callback, Ticket ticket, Result&& result)
   {
      if (!callback)
      {
         return;
      }
      callbackActive = true;
      callback.function(callback.context, ticket, std::move(result));
      callbackActive = false;
   }

   static size_t writeCallback(char *data, size_t size, size_t count, void *context)
   {
      Transfer& transfer = *static_cast<Transfer *>(context);
      transfer.firstByteSeen = true;
      transfer.lastActivity = Clock::now();
      if (size != 0 && count > std::numeric_limits<size_t>::max() / size)
      {
         transfer.bodyOverflow = true;
         return 0;
      }
      const size_t bytes = size * count;
      if (bytes > transfer.responseLimit - transfer.result.body.size())
      {
         transfer.bodyOverflow = true;
         return 0;
      }
      transfer.result.body.append(data, bytes);
      return bytes;
   }

   static bool startsWithLocation(const char *data, size_t bytes)
   {
      static constexpr char name[] = "location:";
      if (bytes < sizeof(name) - 1)
      {
         return false;
      }
      for (size_t index = 0; index < sizeof(name) - 1; ++index)
      {
         char character = data[index];
         if (character >= 'A' && character <= 'Z')
         {
            character = char(character + ('a' - 'A'));
         }
         if (character != name[index])
         {
            return false;
         }
      }
      return true;
   }

   static bool startsWithHeader(const char *data, size_t bytes, const char *name, size_t nameBytes)
   {
      if (bytes < nameBytes)
      {
         return false;
      }
      for (size_t index = 0; index < nameBytes; ++index)
      {
         char character = data[index];
         if (character >= 'A' && character <= 'Z')
         {
            character = char(character + ('a' - 'A'));
         }
         if (character != name[index])
         {
            return false;
         }
      }
      return true;
   }

   static size_t headerCallback(char *data, size_t size, size_t count, void *context)
   {
      Transfer& transfer = *static_cast<Transfer *>(context);
      transfer.firstByteSeen = true;
      transfer.lastActivity = Clock::now();
      if (size != 0 && count > std::numeric_limits<size_t>::max() / size)
      {
         transfer.headerOverflow = true;
         return 0;
      }
      const size_t bytes = size * count;
      if (bytes > maximumHeaderLineBytes)
      {
         transfer.headerOverflow = true;
         return 0;
      }
      if (bytes > transfer.owner->config.headerBytes - transfer.result.headers.size())
      {
         transfer.headerOverflow = true;
         return 0;
      }
      transfer.result.headers.append(data, bytes);

      const bool statusLine = bytes >= 5 && startsWithHeader(data, bytes, "http/", 5);
      const bool blankLine = (bytes == 1 && data[0] == '\n') ||
                             (bytes == 2 && data[0] == '\r' && data[1] == '\n');
      if (statusLine)
      {
         transfer.responseHeaderCount = 0;
         transfer.declaredContentLength = 0;
         transfer.contentLengthSeen = false;
         transfer.locationSeen = false;
         transfer.result.location.clear();
      }
      bool fieldLine = false;
      if (!statusLine && !blankLine)
      {
         for (size_t index = 0; index < bytes; ++index)
         {
            if (data[index] == ':')
            {
               fieldLine = index != 0;
               break;
            }
            if (data[index] == '\r' || data[index] == '\n')
            {
               break;
            }
         }
         if (!fieldLine || ++transfer.responseHeaderCount > maximumRequestHeaders)
         {
            transfer.invalidHeaders = true;
            return 0;
         }
      }

      if (startsWithLocation(data, bytes))
      {
         if (transfer.locationSeen)
         {
            transfer.invalidHeaders = true;
            return 0;
         }
         transfer.locationSeen = true;
         size_t begin = 9;
         while (begin < bytes && (data[begin] == ' ' || data[begin] == '\t'))
         {
            ++begin;
         }
         size_t end = bytes;
         while (end > begin && (data[end - 1] == '\r' || data[end - 1] == '\n' ||
                                data[end - 1] == ' ' || data[end - 1] == '\t'))
         {
            --end;
         }
         transfer.result.location.assign(data + begin, end - begin);
      }
      if (startsWithHeader(data, bytes, "content-length:", 15))
      {
         size_t index = 15;
         while (index < bytes && (data[index] == ' ' || data[index] == '\t'))
         {
            ++index;
         }
         size_t length = 0;
         bool valid = index < bytes;
         const size_t digitsBegin = index;
         while (index < bytes && data[index] >= '0' && data[index] <= '9')
         {
            const size_t digit = size_t(data[index++] - '0');
            if (length > (std::numeric_limits<size_t>::max() - digit) / 10)
            {
               valid = false;
               break;
            }
            length = length * 10 + digit;
         }
         valid = valid && index != digitsBegin;
         while (index < bytes && (data[index] == ' ' || data[index] == '\t' ||
                                  data[index] == '\r' || data[index] == '\n'))
         {
            ++index;
         }
         valid = valid && index == bytes;
         if (!valid || (transfer.contentLengthSeen && transfer.declaredContentLength != length))
         {
            transfer.invalidHeaders = true;
            return 0;
         }
         transfer.contentLengthSeen = true;
         transfer.declaredContentLength = length;
         if (length > transfer.responseLimit)
         {
            transfer.bodyOverflow = true;
            return 0;
         }
      }
      return bytes;
   }

   static bool sameEndpoint(const sockaddr *left,
                            socklen_t leftLength,
                            const AsyncDnsResolver::Address& right)
   {
      if (left == nullptr || left->sa_family != right.family())
      {
         return false;
      }
      if (left->sa_family == AF_INET && leftLength == sizeof(sockaddr_in) &&
          right.length == sizeof(sockaddr_in))
      {
         sockaddr_in rightAddress = {};
         std::memcpy(&rightAddress, &right.storage, sizeof(rightAddress));
         const sockaddr_in *leftAddress = reinterpret_cast<const sockaddr_in *>(left);
         return leftAddress->sin_port == rightAddress.sin_port &&
                std::memcmp(&leftAddress->sin_addr, &rightAddress.sin_addr, sizeof(in_addr)) == 0;
      }
      if (left->sa_family == AF_INET6 && leftLength == sizeof(sockaddr_in6) &&
          right.length == sizeof(sockaddr_in6))
      {
         sockaddr_in6 rightAddress = {};
         std::memcpy(&rightAddress, &right.storage, sizeof(rightAddress));
         const sockaddr_in6 *leftAddress = reinterpret_cast<const sockaddr_in6 *>(left);
         return leftAddress->sin6_port == rightAddress.sin6_port &&
                leftAddress->sin6_scope_id == rightAddress.sin6_scope_id &&
                std::memcmp(&leftAddress->sin6_addr, &rightAddress.sin6_addr, sizeof(in6_addr)) == 0;
      }
      return false;
   }

   static curl_socket_t openSocketCallback(void *context,
                                           curlsocktype purpose,
                                           struct curl_sockaddr *address)
   {
      Transfer& transfer = *static_cast<Transfer *>(context);
      if (Clock::now() >= transfer.resolutionExpires)
      {
         transfer.pinExpired = true;
         return CURL_SOCKET_BAD;
      }
      if (purpose != CURLSOCKTYPE_IPCXN || address == nullptr)
      {
         return CURL_SOCKET_BAD;
      }
      bool approved = false;
      for (const AsyncDnsResolver::Address& candidate : transfer.approvedAddresses)
      {
         if (sameEndpoint(&address->addr, address->addrlen, candidate))
         {
            approved = true;
            break;
         }
      }
      if (!approved)
      {
         return CURL_SOCKET_BAD;
      }

      const int fd = socket(address->family,
                            address->socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                            address->protocol);
      if (fd < 0)
      {
         return CURL_SOCKET_BAD;
      }
      if (!transfer.owner->config.localBinds.empty())
      {
         const int socketType = address->socktype & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
         const LocalSocketBindPool::AcquireResult acquisition =
             transfer.owner->bindPool.acquireAndBind(fd,
                                                     &address->addr,
                                                     address->addrlen,
                                                     socketType);
         if (!acquisition)
         {
            transfer.forcedStatus = statusForBindFailure(acquisition.status);
            close(fd);
            return CURL_SOCKET_BAD;
         }
      }
      return fd;
   }

   static int closeSocketCallback(void *context, curl_socket_t fd)
   {
      MultiCurlClient& owner = *static_cast<MultiCurlClient *>(context);
      owner.bindPool.release(fd);
      return close(fd);
   }

   static int prerequisiteCallback(void *context,
                                   char *primaryIp,
                                   char *localIp,
                                   int primaryPort,
                                   int localPort)
   {
      Transfer& transfer = *static_cast<Transfer *>(context);
      if (Clock::now() >= transfer.resolutionExpires)
      {
         transfer.pinExpired = true;
         return CURL_PREREQFUNC_ABORT;
      }
      if (primaryIp == nullptr || primaryPort <= 0 || primaryPort > 65535)
      {
         return CURL_PREREQFUNC_ABORT;
      }

      sockaddr_storage peer = {};
      socklen_t peerLength = 0;
      sockaddr_in peer4 = {};
      sockaddr_in6 peer6 = {};
      if (inet_pton(AF_INET, primaryIp, &peer4.sin_addr) == 1)
      {
         peer4.sin_family = AF_INET;
         peer4.sin_port = htons(uint16_t(primaryPort));
         std::memcpy(&peer, &peer4, sizeof(peer4));
         peerLength = sizeof(peer4);
      }
      else if (inet_pton(AF_INET6, primaryIp, &peer6.sin6_addr) == 1)
      {
         peer6.sin6_family = AF_INET6;
         peer6.sin6_port = htons(uint16_t(primaryPort));
         std::memcpy(&peer, &peer6, sizeof(peer6));
         peerLength = sizeof(peer6);
      }
      else
      {
         return CURL_PREREQFUNC_ABORT;
      }

      bool approved = false;
      for (const AsyncDnsResolver::Address& candidate : transfer.approvedAddresses)
      {
         if (sameEndpoint(reinterpret_cast<const sockaddr *>(&peer), peerLength, candidate))
         {
            approved = true;
            break;
         }
      }
      if (!approved)
      {
         return CURL_PREREQFUNC_ABORT;
      }

      if (!transfer.owner->config.localBinds.empty())
      {
         if (localIp == nullptr || localPort <= 0 || localPort > 65535)
         {
            return CURL_PREREQFUNC_ABORT;
         }
         sockaddr_storage local = {};
         socklen_t localLength = 0;
         if (reinterpret_cast<const sockaddr *>(&peer)->sa_family == AF_INET)
         {
            sockaddr_in local4 = {};
            local4.sin_family = AF_INET;
            local4.sin_port = htons(uint16_t(localPort));
            if (inet_pton(AF_INET, localIp, &local4.sin_addr) != 1)
            {
               return CURL_PREREQFUNC_ABORT;
            }
            std::memcpy(&local, &local4, sizeof(local4));
            localLength = sizeof(local4);
         }
         else
         {
            sockaddr_in6 local6 = {};
            local6.sin6_family = AF_INET6;
            local6.sin6_port = htons(uint16_t(localPort));
            if (inet_pton(AF_INET6, localIp, &local6.sin6_addr) != 1)
            {
               return CURL_PREREQFUNC_ABORT;
            }
            std::memcpy(&local, &local6, sizeof(local6));
            localLength = sizeof(local6);
         }
         if (!transfer.owner->bindPool.containsLocal(
                 reinterpret_cast<const sockaddr *>(&local), localLength))
         {
            return CURL_PREREQFUNC_ABORT;
         }
      }
      if (transfer.request.httpPolicy == HttpPolicy::requireHttp2 &&
          transfer.scheme.equals("https"_ctv))
      {
         curl_tlssessioninfo *session = nullptr;
         const CURLcode sessionStatus = curl_easy_getinfo(transfer.easy,
                                                          CURLINFO_TLS_SSL_PTR,
                                                          &session);
         const unsigned char *protocol = nullptr;
         unsigned int protocolLength = 0;
         if (sessionStatus == CURLE_OK && session &&
             session->backend == CURLSSLBACKEND_OPENSSL && session->internals)
         {
            SSL_get0_alpn_selected(static_cast<SSL *>(session->internals),
                                   &protocol,
                                   &protocolLength);
         }
         if (protocol == nullptr || protocolLength != 2 || std::memcmp(protocol, "h2", 2) != 0)
         {
            transfer.forcedStatus = Status::httpVersionRejected;
            return CURL_PREREQFUNC_ABORT;
         }
      }
      return CURL_PREREQFUNC_OK;
   }

   static int socketCallback(CURL *, curl_socket_t fd, int action, void *context, void *)
   {
      MultiCurlClient& client = *static_cast<MultiCurlClient *>(context);
      client.requireOwnerThread();
      if (client.stagedSocketEvents.size() >= maximumStagedSocketEvents)
      {
         client.socketEventOverflow = true;
         return -1;
      }

      unsigned mask = 0;
      if (action == CURL_POLL_IN || action == CURL_POLL_INOUT)
      {
         mask |= POLLIN;
      }
      if (action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
      {
         mask |= POLLOUT;
      }
      client.stagedSocketEvents.push_back({int(fd), mask});
      return 0;
   }

   static int timerCallback(CURLM *, long milliseconds, void *context)
   {
      MultiCurlClient& client = *static_cast<MultiCurlClient *>(context);
      client.requireOwnerThread();
      if (milliseconds < 0)
      {
         client.requestedTimerDeadline = TimePoint::max();
      }
      else
      {
         client.requestedTimerDeadline = Clock::now() +
                                         std::chrono::milliseconds(std::max(1L, milliseconds));
      }
      return 0;
   }

   static void dnsCallback(void *context,
                           AsyncDnsResolver::Ticket ticket,
                           AsyncDnsResolver::Result&& result)
   {
      Transfer *transfer = static_cast<Transfer *>(context);
      if (transfer == nullptr || transfer->owner == nullptr)
      {
         return;
      }
      transfer->owner->dnsCompleted(transfer->ticket, std::move(result));
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

   void applySocketEvents(void)
   {
      if (!stagedSocketEvents.empty())
      {
         Vector<SocketEvent> staged = std::move(stagedSocketEvents);
         stagedSocketEvents.clear();
         for (const SocketEvent& event : staged)
         {
            auto position = sockets.find(event.fd);
            const bool inserted = position == sockets.end();
            if (inserted)
            {
               position = sockets.emplace(event.fd, SocketState {}).first;
            }
            SocketState& socket = position->second;
            if (!inserted && socket.mask == event.mask)
            {
               continue;
            }
            socket.mask = event.mask;
            socket.generation = advance(nextSocketGeneration);
            if (socket.activeTicket != Ring::invalidRawPollTicket)
            {
               cancelWatch(socket.activeTicket);
            }
         }
      }

      for (auto position = sockets.begin(); position != sockets.end();)
      {
         SocketState& socket = position->second;
         if (socket.mask == 0 && socket.activeTicket == Ring::invalidRawPollTicket)
         {
            position = sockets.erase(position);
            continue;
         }
         if (!stopping && !resetting && socket.mask != 0 &&
             socket.activeTicket == Ring::invalidRawPollTicket)
         {
            if (watches.size() >= maximumSocketWatches)
            {
               socketEventOverflow = true;
               ++position;
               continue;
            }
            const Ring::RawPollTicket ticket = Ring::queueRawFDPoll(this,
                                                                    socket.generation,
                                                                    position->first,
                                                                    socket.mask);
            if (ticket == Ring::invalidRawPollTicket)
            {
               socketEventOverflow = true;
               ++position;
               continue;
            }
            socket.activeTicket = ticket;
            watches.emplace(ticket, Watch {.fd = position->first,
                                            .generation = socket.generation});
         }
         ++position;
      }
   }

   void armTimer(TimePoint deadline)
   {
      auto delay = std::chrono::duration_cast<std::chrono::microseconds>(deadline - Clock::now());
      if (delay <= std::chrono::microseconds::zero())
      {
         delay = std::chrono::milliseconds(1);
      }
      timer.clear();
      timer.setTimeoutUs(uint64_t(delay.count()));
      timerArmed = true;
      armedTimerDeadline = deadline;
      Ring::queueTimeout(&timer);
   }

   TimePoint requiredTimerDeadline(void) const
   {
      TimePoint required = requestedTimerDeadline;
      for (const auto& [identifier, transfer] : transfers)
      {
         (void)identifier;
         required = std::min(required, transfer->overallDeadline);
         if (!transfer->firstByteSeen)
         {
            required = std::min(required, transfer->firstByteDeadline);
         }
         else if (transfer->idleTimeout > std::chrono::milliseconds::zero())
         {
            required = std::min(required, transfer->lastActivity + transfer->idleTimeout);
         }
      }
      return required;
   }

   bool expirePolicyDeadlines(void)
   {
      const TimePoint now = Clock::now();
      Vector<uint64_t> expired;
      for (const auto& [identifier, transfer] : transfers)
      {
         if (now >= transfer->overallDeadline ||
             (!transfer->firstByteSeen && now >= transfer->firstByteDeadline) ||
             (transfer->firstByteSeen && transfer->idleTimeout > std::chrono::milliseconds::zero() &&
              now >= transfer->lastActivity + transfer->idleTimeout))
         {
            expired.push_back(identifier);
         }
      }
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      const bool callbacksLive = lifetime->alive;
      for (uint64_t identifier : expired)
      {
         finish(identifier, Status::deadlineExceeded, CURLE_OPERATION_TIMEDOUT);
         if (callbacksLive && !lifetime->alive)
         {
            return false;
         }
      }
      return true;
   }

   void refreshTimer(void)
   {
      const TimePoint required = stopping || resetting ? TimePoint::max() : requiredTimerDeadline();
      if (!timerArmed)
      {
         if (required != TimePoint::max())
         {
            armTimer(required);
         }
         return;
      }
      if (!timerCancellationRequested && required != armedTimerDeadline)
      {
         timerCancellationRequested = true;
         Ring::queueCancelTimeout(&timer);
      }
   }

   bool completeAll(Status status, CURLcode code)
   {
      Vector<uint64_t> identifiers;
      identifiers.reserve(transfers.size());
      for (const auto& [identifier, transfer] : transfers)
      {
         (void)transfer;
         identifiers.push_back(identifier);
      }
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      const bool callbacksLive = lifetime->alive;
      for (uint64_t identifier : identifiers)
      {
         auto position = transfers.find(identifier);
         if (position == transfers.end())
         {
            continue;
         }
         position->second->forcedStatus = status;
         if (position->second->state == TransferState::resolving &&
             resolver.cancel(position->second->dnsTicket))
         {
            if (callbacksLive && !lifetime->alive)
            {
               return false;
            }
            continue;
         }
         finish(identifier, status, code);
         if (callbacksLive && !lifetime->alive)
         {
            return false;
         }
      }
      return true;
   }

   bool initializeMultiHandle(void)
   {
      multi = curl_multi_init();
      if (multi == nullptr ||
          curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, socketCallback) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, this) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, timerCallback) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_TIMERDATA, this) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                            long(config.totalConnections)) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS,
                            long(config.hostConnections)) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS,
                            long(config.totalConnections)) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_MAX_CONCURRENT_STREAMS,
                            long(config.concurrentStreams)) != CURLM_OK ||
          curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX) != CURLM_OK)
      {
         if (multi)
         {
            curl_multi_cleanup(multi);
            multi = nullptr;
         }
         for (CURL *easy : orphanedEasyHandles)
         {
            curl_easy_cleanup(easy);
         }
         orphanedEasyHandles.clear();
         return false;
      }
      multiGeneration = advance(nextMultiGeneration);
      return true;
   }

   void tryFinishReset(void)
   {
      if (!resetting || !watches.empty() || !sockets.empty() || timerArmed ||
          !stagedSocketEvents.empty() || !bindPool.drained())
      {
         return;
      }
      connectionIdentityByOrigin.clear();
      resetting = false;
      fatalMulti = false;
      if (!stopping && !initializeMultiHandle())
      {
         fatalMulti = true;
         initialization = InitializationStatus::curlInitializationFailed;
      }
      deferCallbacks = false;
   }

   bool beginReset(Status completionStatus, bool fatal)
   {
      if (stopping || resetting)
      {
         return false;
      }
      resetting = true;
      fatalMulti = fatal;
      deferCallbacks = true;
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      if (!completeAll(completionStatus, CURLE_ABORTED_BY_CALLBACK) || !lifetime->alive)
      {
         return false;
      }
      if (multi)
      {
         curl_multi_cleanup(multi);
         multi = nullptr;
      }
      for (CURL *easy : orphanedEasyHandles)
      {
         curl_easy_cleanup(easy);
      }
      orphanedEasyHandles.clear();
      requestedTimerDeadline = TimePoint::max();
      applySocketEvents();
      for (auto& [ticket, watch] : watches)
      {
         (void)watch;
         cancelWatch(ticket);
      }
      for (auto& [fd, socket] : sockets)
      {
         (void)fd;
         socket.mask = 0;
      }
      refreshTimer();
      applySocketEvents();
      tryFinishReset();
      deliverDeferredCompletions();
      return true;
   }

   bool afterCurlFrame(void)
   {
      applySocketEvents();
      refreshTimer();
      if (socketEventOverflow)
      {
         socketEventOverflow = false;
         return beginReset(Status::transportFailure, true);
      }
      if (fatalMulti && !resetting)
      {
         return beginReset(Status::transportFailure, true);
      }
      return true;
   }

   bool startResolution(uint64_t identifier)
   {
      auto position = transfers.find(identifier);
      if (position == transfers.end())
      {
         return true;
      }
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      if (!resolver.ready())
      {
         finish(identifier, Status::dnsFailure, CURLE_COULDNT_RESOLVE_HOST);
         return lifetime->alive;
      }
      Transfer *transfer = position->second.get();
      const AsyncDnsResolver::Ticket dnsTicket = resolver.resolve(transfer->connectHost,
                                                                  transfer->service,
                                                                  transfer->request.family,
                                                                  {transfer, dnsCallback},
                                                                  transfer->overallDeadline);
      if (!lifetime->alive)
      {
         return false;
      }
      position = transfers.find(identifier);
      if (position != transfers.end())
      {
         position->second->dnsTicket = dnsTicket;
      }
      return true;
   }

   bool preparePinRefresh(Transfer& transfer)
   {
      if (!transfer.pinExpired || transfer.pinRefreshes >= 2 ||
          Clock::now() >= transfer.overallDeadline || transfer.easy == nullptr || multi == nullptr)
      {
         return false;
      }
      ticketByEasy.erase(transfer.easy);
      if (transfer.addedToMulti && curl_multi_remove_handle(multi, transfer.easy) != CURLM_OK)
      {
         fatalMulti = true;
         return false;
      }
      transfer.addedToMulti = false;
      curl_easy_cleanup(transfer.easy);
      transfer.easy = nullptr;
      if (transfer.requestHeaders)
      {
         curl_slist_free_all(transfer.requestHeaders);
         transfer.requestHeaders = nullptr;
      }
      if (transfer.resolveRules)
      {
         curl_slist_free_all(transfer.resolveRules);
         transfer.resolveRules = nullptr;
      }
      transfer.approvedAddresses.clear();
      transfer.result = Result {};
      transfer.firstByteSeen = false;
      transfer.lastActivity = Clock::now();
      transfer.pinExpired = false;
      ++transfer.pinRefreshes;
      transfer.state = TransferState::resolving;
      return true;
   }

   void runCurlAction(curl_socket_t fd, int events)
   {
      if (multi == nullptr || stopping)
      {
         return;
      }
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      const uint64_t frameGeneration = multiGeneration;
      ++curlFrameDepth;
      int running = 0;
      CURLMcode code = CURLM_OK;
      do
      {
         code = curl_multi_socket_action(multi, fd, events, &running);
      }
      while (code == CURLM_CALL_MULTI_PERFORM);
      if (!afterCurlFrame() || !lifetime->alive)
      {
         if (lifetime->alive)
         {
            --curlFrameDepth;
            deliverDeferredCompletions();
         }
         return;
      }
      if (multi == nullptr || resetting || multiGeneration != frameGeneration)
      {
         --curlFrameDepth;
         deliverDeferredCompletions();
         return;
      }
      if (code != CURLM_OK)
      {
         (void)beginReset(Status::transportFailure, true);
         if (lifetime->alive)
         {
            --curlFrameDepth;
            deliverDeferredCompletions();
         }
         return;
      }

      int remaining = 0;
      Vector<uint64_t> pinRefreshes;
      while (lifetime->alive)
      {
         CURLMsg *message = curl_multi_info_read(multi, &remaining);
         if (message == nullptr)
         {
            break;
         }
         if (message->msg != CURLMSG_DONE)
         {
            continue;
         }
         auto identifier = ticketByEasy.find(message->easy_handle);
         if (identifier != ticketByEasy.end())
         {
            const uint64_t transferIdentifier = identifier->second;
            auto transfer = transfers.find(transferIdentifier);
            if (transfer != transfers.end() && preparePinRefresh(*transfer->second))
            {
               pinRefreshes.push_back(transferIdentifier);
            }
            else
            {
               finish(transferIdentifier, Status::success, message->data.result);
            }
         }
      }
      if (lifetime->alive)
      {
         (void)afterCurlFrame();
         --curlFrameDepth;
         for (uint64_t identifier : pinRefreshes)
         {
            if (!startResolution(identifier) || !lifetime->alive)
            {
               return;
            }
         }
         deliverDeferredCompletions();
      }
   }

   static Status statusForDns(AsyncDnsResolver::Status status)
   {
      switch (status)
      {
         case AsyncDnsResolver::Status::canceled:
            return Status::canceled;
         case AsyncDnsResolver::Status::deadlineExceeded:
            return Status::deadlineExceeded;
         case AsyncDnsResolver::Status::shutdown:
            return Status::shutdown;
         case AsyncDnsResolver::Status::overloaded:
            return Status::overloaded;
         default:
            return Status::dnsFailure;
      }
   }

   bool appendResolveAddress(String& rule, const AsyncDnsResolver::Address& address)
   {
      char text[INET6_ADDRSTRLEN] = {};
      if (address.family() == AF_INET && address.length == sizeof(sockaddr_in))
      {
         sockaddr_in value = {};
         std::memcpy(&value, &address.storage, sizeof(value));
         if (inet_ntop(AF_INET, &value.sin_addr, text, sizeof(text)) == nullptr)
         {
            return false;
         }
         rule.append(text);
         return true;
      }
      if (address.family() == AF_INET6 && address.length == sizeof(sockaddr_in6))
      {
         sockaddr_in6 value = {};
         std::memcpy(&value, &address.storage, sizeof(value));
         if (value.sin6_scope_id != 0 ||
             inet_ntop(AF_INET6, &value.sin6_addr, text, sizeof(text)) == nullptr)
         {
            return false;
         }
         rule.append('[');
         rule.append(text);
         rule.append(']');
         return true;
      }
      return false;
   }

   bool appendRequestHeader(Transfer& transfer, const Header& header)
   {
      String line;
      line.append(header.name);
      line.append(": "_ctv);
      line.append(header.value);
      curl_slist *appended = curl_slist_append(transfer.requestHeaders, line.c_str());
      if (appended == nullptr)
      {
         return false;
      }
      transfer.requestHeaders = appended;
      return true;
   }

   static bool asciiEquals(const String& value, const char *expected)
   {
      size_t length = 0;
      while (expected[length] != '\0')
      {
         ++length;
      }
      if (value.size() != length)
      {
         return false;
      }
      for (size_t index = 0; index < length; ++index)
      {
         char character = value[index];
         if (character >= 'A' && character <= 'Z')
         {
            character = char(character + ('a' - 'A'));
         }
         if (character != expected[index])
         {
            return false;
         }
      }
      return true;
   }

   static bool validRequestHeader(const Header& header)
   {
      if (header.name.empty() ||
          header.name.size() + header.value.size() + 2 > maximumHeaderLineBytes ||
          asciiEquals(header.name, "host") || asciiEquals(header.name, "connection") ||
          asciiEquals(header.name, "transfer-encoding") ||
          asciiEquals(header.name, "content-length") || asciiEquals(header.name, "te") ||
          asciiEquals(header.name, "upgrade") || asciiEquals(header.name, "proxy-authorization") ||
          asciiEquals(header.name, "proxy-connection"))
      {
         return false;
      }
      for (char character : header.name)
      {
         const unsigned char byte = static_cast<unsigned char>(character);
         if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9') || byte == '!' || byte == '#' || byte == '$' ||
               byte == '%' || byte == '&' || byte == '\'' || byte == '*' || byte == '+' ||
               byte == '-' || byte == '.' || byte == '^' || byte == '_' || byte == '`' ||
               byte == '|' || byte == '~'))
         {
            return false;
         }
      }
      for (char character : header.value)
      {
         const unsigned char byte = static_cast<unsigned char>(character);
         if (byte == '\r' || byte == '\n' || byte == 0 || (byte < 0x20 && byte != '\t') || byte == 0x7f)
         {
            return false;
         }
      }
      return true;
   }

   static bool validAuthority(const String& authority)
   {
      if (authority.empty())
      {
         return true;
      }
      if (authority.size() > maximumUrlBytes)
      {
         return false;
      }
      for (char character : authority)
      {
         const unsigned char byte = static_cast<unsigned char>(character);
         if (byte <= 0x20 || byte == 0x7f || byte == '/' || byte == '\\' ||
             byte == '@' || byte == '#' || byte == '?')
         {
            return false;
         }
      }
      return true;
   }

   bool prepareEasy(Transfer& transfer)
   {
      transfer.easy = curl_easy_init();
      if (transfer.easy == nullptr)
      {
         return false;
      }

      const size_t structuredHeaderCount = transfer.request.authority.empty() ? 0 : 1;
      if (transfer.request.headers.size() + structuredHeaderCount > maximumRequestHeaders)
      {
         transfer.result.status = Status::headersTooLarge;
         return false;
      }
      size_t requestHeaderBytes = 0;
      if (!transfer.request.authority.empty())
      {
         Header authorityHeader {"Host", transfer.request.authority};
         requestHeaderBytes = authorityHeader.name.size() + authorityHeader.value.size() + 2;
         if (requestHeaderBytes > config.headerBytes ||
             !appendRequestHeader(transfer, authorityHeader))
         {
            transfer.result.status = requestHeaderBytes > config.headerBytes
                                         ? Status::headersTooLarge
                                         : Status::initializationFailure;
            return false;
         }
      }
      for (const Header& header : transfer.request.headers)
      {
         const size_t lineBytes = header.name.size() + header.value.size() + 2;
         if (lineBytes > config.headerBytes - requestHeaderBytes)
         {
            transfer.result.status = Status::headersTooLarge;
            return false;
         }
         if (!validRequestHeader(header))
         {
            transfer.result.status = Status::invalidRequest;
            return false;
         }
         if (!appendRequestHeader(transfer, header))
         {
            transfer.result.status = Status::initializationFailure;
            return false;
         }
         requestHeaderBytes += lineBytes;
      }

      CURL *easy = transfer.easy;
      CURLcode code = CURLE_OK;
      code = curl_easy_setopt(easy, CURLOPT_URL, transfer.request.url.c_str());
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_PRIVATE, &transfer) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, writeCallback) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_WRITEDATA, &transfer) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, headerCallback) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_HEADERDATA, &transfer) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_HTTPHEADER, transfer.requestHeaders) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_RESOLVE, transfer.resolveRules) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 0L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy,
                                                 CURLOPT_SSLVERSION,
                                                 transfer.request.tlsMinimum == TlsMinimum::tls13
                                                     ? CURL_SSLVERSION_TLSv1_3
                                                     : CURL_SSLVERSION_TLSv1_2) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 250L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "") : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_NETRC, CURL_NETRC_IGNORED) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_PATH_AS_IS,
                                                 transfer.request.pathAsIs ? 1L : 0L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION,
                                                 openSocketCallback) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, &transfer) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_CLOSESOCKETFUNCTION,
                                                 closeSocketCallback) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_CLOSESOCKETDATA, this) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_PREREQFUNCTION,
                                                 prerequisiteCallback) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_PREREQDATA, &transfer) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_PROXY, "") : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_NOPROXY, "*") : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR,
                                                 transfer.request.requireTls ? "https" : "http,https") : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR,
                                                 transfer.request.requireTls ? "https" : "http,https") : code;

      switch (transfer.request.caSource)
      {
         case CaSource::system:
            break;
         case CaSource::file:
            code = code == CURLE_OK && !transfer.request.caFile.empty()
                       ? curl_easy_setopt(easy, CURLOPT_CAINFO, transfer.request.caFile.c_str())
                       : CURLE_BAD_FUNCTION_ARGUMENT;
            break;
         case CaSource::path:
            code = code == CURLE_OK && !transfer.request.caPath.empty()
                       ? curl_easy_setopt(easy, CURLOPT_CAPATH, transfer.request.caPath.c_str())
                       : CURLE_BAD_FUNCTION_ARGUMENT;
            break;
         case CaSource::blob:
         {
            curl_blob blob {transfer.request.caBlob.data(),
                            transfer.request.caBlob.size(),
                            CURL_BLOB_COPY};
            code = code == CURLE_OK && !transfer.request.caBlob.empty()
                       ? curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &blob)
                       : CURLE_BAD_FUNCTION_ARGUMENT;
            break;
         }
      }

      if (!transfer.request.clientCertificateFile.empty())
      {
         code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_SSLCERT,
                                                    transfer.request.clientCertificateFile.c_str()) : code;
      }
      if (!transfer.request.clientKeyFile.empty())
      {
         code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_SSLKEY,
                                                    transfer.request.clientKeyFile.c_str()) : code;
      }
      if (!transfer.request.clientCertificateBlob.empty())
      {
         curl_blob blob {transfer.request.clientCertificateBlob.data(),
                         transfer.request.clientCertificateBlob.size(),
                         CURL_BLOB_COPY};
         code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_SSLCERT_BLOB, &blob) : code;
      }
      if (!transfer.request.clientKeyBlob.empty())
      {
         curl_blob blob {transfer.request.clientKeyBlob.data(),
                         transfer.request.clientKeyBlob.size(),
                         CURL_BLOB_COPY};
         code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_SSLKEY_BLOB, &blob) : code;
      }

      const long httpVersion = transfer.request.httpPolicy == HttpPolicy::requireHttp2
                                   ? CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
                                   : transfer.request.httpPolicy == HttpPolicy::requireHttp1
                                         ? CURL_HTTP_VERSION_1_1
                                         : CURL_HTTP_VERSION_2TLS;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, httpVersion) : code;

      const TimePoint now = Clock::now();
      if (transfer.overallDeadline <= now)
      {
         transfer.result.status = Status::deadlineExceeded;
         return false;
      }
      const auto timeout = std::max(std::chrono::milliseconds(1),
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        transfer.overallDeadline - now));
      const auto requestedConnectTimeout = transfer.request.connectTimeout > std::chrono::milliseconds::zero()
                                               ? transfer.request.connectTimeout
                                               : config.defaultConnectTimeout;
      const auto connectTimeout = std::min(timeout, requestedConnectTimeout);
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, long(timeout.count())) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS,
                                                 long(connectTimeout.count())) : code;
      const long lowSpeedSeconds = long(std::max<int64_t>(1, (transfer.idleTimeout.count() + 999) / 1000));
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, 1L) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, lowSpeedSeconds) : code;
      code = code == CURLE_OK ? curl_easy_setopt(easy,
                                                 CURLOPT_MAXFILESIZE_LARGE,
                                                 curl_off_t(transfer.responseLimit + 1)) : code;

      if (!transfer.request.body.empty())
      {
         code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_POSTFIELDS,
                                                    transfer.request.body.data()) : code;
         code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE,
                                                    curl_off_t(transfer.request.body.size())) : code;
      }
      switch (transfer.request.method)
      {
         case Method::get:
            code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L) : code;
            break;
         case Method::head:
            code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_NOBODY, 1L) : code;
            break;
         case Method::post:
            code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_POST, 1L) : code;
            break;
         case Method::put:
            code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "PUT") : code;
            break;
         case Method::delete_:
            code = code == CURLE_OK ? curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "DELETE") : code;
            break;
      }
      if (code != CURLE_OK)
      {
         transfer.result.curlCode = code;
         return false;
      }
      return true;
   }

   void dnsCompleted(Ticket ticket, AsyncDnsResolver::Result&& dnsResult)
   {
      requireOwnerThread();
      auto position = transfers.find(ticket.identifier);
      if (position == transfers.end() ||
          position->second->ticket.generation != ticket.generation)
      {
         return;
      }
      Transfer& transfer = *position->second;
      if (transfer.forcedStatus != Status::success)
      {
         finish(ticket.identifier, transfer.forcedStatus, CURLE_ABORTED_BY_CALLBACK);
         return;
      }
      if (!dnsResult.succeeded())
      {
         finish(ticket.identifier, statusForDns(dnsResult.status), CURLE_COULDNT_RESOLVE_HOST);
         return;
      }

      AsyncDnsResolver::Result accepted;
      accepted.status = AsyncDnsResolver::Status::success;
      accepted.canonicalName = dnsResult.canonicalName;
      accepted.canonicalNameTtlSeconds = dnsResult.canonicalNameTtlSeconds;
      std::shared_ptr<LifetimeState> policyLifetime = lifetimeState;
      for (const AsyncDnsResolver::Address& address : dnsResult.addresses)
      {
         policyCallbackActive = true;
         const bool addressAccepted = transfer.request.addressPolicy.accepts(address);
         if (!policyLifetime->alive)
         {
            return;
         }
         policyCallbackActive = false;
         if (!addressAccepted)
         {
            finish(ticket.identifier, Status::addressRejected, CURLE_COULDNT_CONNECT);
            return;
         }
         if (!config.localBinds.empty() && config.localBinds.count(address.family()) == 0)
         {
            continue;
         }
         accepted.addresses.push_back(address);
      }

      HappyEyeballsPlan plan(accepted);
      if (!plan.valid())
      {
         finish(ticket.identifier, Status::addressRejected, CURLE_COULDNT_CONNECT);
         return;
      }

      String rule;
      rule.append('+');
      if (transfer.host.findChar(':') >= 0)
      {
         rule.append('[');
         rule.append(transfer.host);
         rule.append(']');
      }
      else
      {
         rule.append(transfer.host);
      }
      rule.append(':');
      rule.append(transfer.service);
      rule.append(':');
      const uint32_t minimumTtl = accepted.minimumTtlSeconds();
      if (minimumTtl == 0)
      {
         finish(ticket.identifier, Status::addressRejected, CURLE_COULDNT_CONNECT);
         return;
      }
      for (size_t index = 0; index < plan.size(); ++index)
      {
         if (index != 0)
         {
            rule.append(',');
         }
         if (!appendResolveAddress(rule, plan[index].address))
         {
            finish(ticket.identifier, Status::addressRejected, CURLE_COULDNT_CONNECT);
            return;
         }
         transfer.approvedAddresses.push_back(plan[index].address);
      }
      transfer.result.resolvedTtlSeconds = minimumTtl;
      transfer.resolutionExpires = minimumTtl == std::numeric_limits<uint32_t>::max()
                                       ? transfer.overallDeadline
                                       : std::min(transfer.overallDeadline,
                                                  Clock::now() + std::chrono::seconds(minimumTtl));
      transfer.resolveRules = curl_slist_append(nullptr, rule.c_str());
      if (transfer.resolveRules == nullptr || !prepareEasy(transfer))
      {
         const Status status = transfer.result.status == Status::headersTooLarge ||
                               transfer.result.status == Status::deadlineExceeded ||
                               transfer.result.status == Status::invalidRequest ||
                               transfer.result.status == Status::initializationFailure
                                   ? transfer.result.status
                                   : Status::initializationFailure;
         finish(ticket.identifier, status,
                transfer.result.curlCode == CURLE_OK ? CURLE_FAILED_INIT : transfer.result.curlCode);
         return;
      }

      transfer.state = TransferState::active;
      String origin;
      origin.append(transfer.host);
      origin.append('\0');
      origin.append(transfer.service);
      String connectionPins = rule;
      connectionPins.append('\0');
      connectionPins.append(transfer.request.authority.empty()
                                ? transfer.host
                                : transfer.request.authority);
      const ConnectionIdentity identity {transfer.request.resolutionGeneration,
                                         transfer.request.identityGeneration,
                                         std::move(connectionPins)};
      auto previousIdentity = connectionIdentityByOrigin.find(origin);
      const bool knownOrigin = previousIdentity != connectionIdentityByOrigin.end();
      const bool connectionIdentityChanged = !knownOrigin ||
                                             previousIdentity->second.resolution != identity.resolution ||
                                             previousIdentity->second.credentials != identity.credentials ||
                                             previousIdentity->second.pins != identity.pins;
      if (connectionIdentityChanged)
      {
         const bool evictAll = !knownOrigin &&
                               connectionIdentityByOrigin.size() >= config.transfers;
         if (evictAll)
         {
            connectionIdentityByOrigin.clear();
         }
         if ((knownOrigin || evictAll) &&
             curl_multi_setopt(multi,
                               CURLMOPT_NETWORK_CHANGED,
                               CURLMNWC_CLEAR_CONNS) != CURLM_OK)
         {
            finish(ticket.identifier, Status::transportFailure, CURLE_FAILED_INIT);
            return;
         }
         if ((knownOrigin || evictAll) &&
             curl_easy_setopt(transfer.easy, CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK)
         {
            finish(ticket.identifier, Status::initializationFailure, CURLE_FAILED_INIT);
            return;
         }
      }
      ticketByEasy.emplace(transfer.easy, transfer.ticket.identifier);
      const CURLMcode added = curl_multi_add_handle(multi, transfer.easy);
      if (added != CURLM_OK)
      {
         ticketByEasy.erase(transfer.easy);
         finish(ticket.identifier, Status::transportFailure, CURLE_FAILED_INIT);
         return;
      }
      transfer.addedToMulti = true;
      if (connectionIdentityChanged)
      {
         connectionIdentityByOrigin.insert_or_assign(std::move(origin), identity);
      }
      runCurlAction(CURL_SOCKET_TIMEOUT, 0);
   }

   bool parseEndpoint(Transfer& transfer)
   {
      if (transfer.request.url.empty() || transfer.request.url.size() > maximumUrlBytes)
      {
         return false;
      }
      CURLU *url = curl_url();
      if (url == nullptr)
      {
         return false;
      }
      CURLUcode status = curl_url_set(url,
                                     CURLUPART_URL,
                                     transfer.request.url.c_str(),
                                     CURLU_DISALLOW_USER);
      char *scheme = nullptr;
      char *host = nullptr;
      char *port = nullptr;
      if (status == CURLUE_OK)
      {
         status = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
      }
      if (status == CURLUE_OK)
      {
         status = curl_url_get(url, CURLUPART_HOST, &host, 0);
      }
      if (status == CURLUE_OK)
      {
         status = curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT);
      }
      const bool https = status == CURLUE_OK && std::strcmp(scheme, "https") == 0;
      const bool http = status == CURLUE_OK && std::strcmp(scheme, "http") == 0;
      if (status == CURLUE_OK && host && port && (https || http) &&
          (!transfer.request.requireTls || https))
      {
         transfer.host.assign(host);
         transfer.scheme.assign(scheme);
         transfer.connectHost.assign(transfer.request.resolveHost.empty()
                                         ? host
                                         : transfer.request.resolveHost.c_str());
         transfer.service.assign(port);
         std::shared_ptr<LifetimeState> originPolicyLifetime = lifetimeState;
         policyCallbackActive = true;
         const bool originAccepted = transfer.request.originPolicy.accepts(transfer.scheme,
                                                                           transfer.host,
                                                                           transfer.request.authority.empty()
                                                                               ? transfer.host
                                                                               : transfer.request.authority,
                                                                           transfer.service,
                                                                           transfer.connectHost);
         if (!originPolicyLifetime->alive)
         {
            status = CURLUE_BAD_HOSTNAME;
         }
         else
         {
            policyCallbackActive = false;
            if (!originAccepted)
            {
               status = CURLUE_BAD_HOSTNAME;
            }
         }
      }
      else
      {
         status = CURLUE_BAD_SCHEME;
      }
      if (scheme)
      {
         curl_free(scheme);
      }
      if (host)
      {
         curl_free(host);
      }
      if (port)
      {
         curl_free(port);
      }
      curl_url_cleanup(url);
      return status == CURLUE_OK;
   }

   void finish(uint64_t identifier, Status requestedStatus, CURLcode curlCode)
   {
      auto position = transfers.find(identifier);
      if (position == transfers.end())
      {
         return;
      }
      std::unique_ptr<Transfer> transfer = std::move(position->second);
      transfers.erase(position);

      transfer->result.curlCode = curlCode;
      if (transfer->easy)
      {
         (void)curl_easy_getinfo(transfer->easy, CURLINFO_RESPONSE_CODE, &transfer->result.statusCode);
         (void)curl_easy_getinfo(transfer->easy, CURLINFO_HTTP_VERSION, &transfer->result.httpVersion);
         char *effective = nullptr;
         if (curl_easy_getinfo(transfer->easy, CURLINFO_EFFECTIVE_URL, &effective) == CURLE_OK && effective)
         {
            transfer->result.effectiveUrl.assign(effective);
         }
         ticketByEasy.erase(transfer->easy);
         if (transfer->addedToMulti && multi)
         {
            if (curl_multi_remove_handle(multi, transfer->easy) != CURLM_OK)
            {
               fatalMulti = true;
               requestedStatus = Status::transportFailure;
               orphanedEasyHandles.push_back(transfer->easy);
               transfer->easy = nullptr;
            }
            transfer->addedToMulti = false;
         }
      }

      Status finalStatus = requestedStatus;
      if (transfer->forcedStatus != Status::success)
      {
         finalStatus = transfer->forcedStatus;
      }
      else if (transfer->headerOverflow)
      {
         finalStatus = Status::headersTooLarge;
      }
      else if (transfer->bodyOverflow)
      {
         finalStatus = Status::responseTooLarge;
      }
      else if (transfer->invalidHeaders ||
               (curlCode == CURLE_WEIRD_SERVER_REPLY && transfer->locationSeen))
      {
         finalStatus = Status::invalidResponse;
      }
      else if (requestedStatus == Status::success && curlCode != CURLE_OK)
      {
         finalStatus = curlCode == CURLE_OPERATION_TIMEDOUT
                           ? Status::deadlineExceeded
                           : curlCode == CURLE_FILESIZE_EXCEEDED
                                 ? Status::responseTooLarge
                                 : Status::transportFailure;
      }
      else if (requestedStatus == Status::success &&
               transfer->request.httpPolicy == HttpPolicy::requireHttp2 &&
               transfer->result.httpVersion != CURL_HTTP_VERSION_2_0)
      {
         finalStatus = Status::httpVersionRejected;
      }
      else if (requestedStatus == Status::success &&
               transfer->request.httpPolicy == HttpPolicy::requireHttp1 &&
               transfer->result.httpVersion != CURL_HTTP_VERSION_1_0 &&
               transfer->result.httpVersion != CURL_HTTP_VERSION_1_1)
      {
         finalStatus = Status::httpVersionRejected;
      }
      transfer->result.status = finalStatus;

      Callback callback = transfer->callback;
      Ticket ticket = transfer->ticket;
      Result result = std::move(transfer->result);
      transfer.reset();
      if (callback && lifetimeState->alive && (deferCallbacks || curlFrameDepth != 0))
      {
         deferredCompletions.push_back({callback, ticket, std::move(result)});
      }
      else if (callback && lifetimeState->alive)
      {
         deliverNow(callback, ticket, std::move(result));
      }
   }

   bool infrastructureSafe(void) const
   {
      return stopping && multi == nullptr && transfers.empty() && ticketByEasy.empty() &&
             sockets.empty() && watches.empty() && stagedSocketEvents.empty() &&
             !timerArmed && bindPool.drained();
   }

   bool teardownSafe(void) const
   {
      return infrastructureSafe() && deferredCompletions.empty();
   }

   void deliverDeferredCompletions(void)
   {
      if (curlFrameDepth != 0 || ((resetting || deferCallbacks) && !stopping))
      {
         return;
      }
      if (stopping && !infrastructureSafe())
      {
         return;
      }
      if (stopping && dispatcherInstalled)
      {
         RingDispatcher::eraseMultiplexee(this);
         dispatcherInstalled = false;
         if (threadOwner == this)
         {
            threadOwner = nullptr;
         }
      }

      Vector<DeferredCompletion> completions = std::move(deferredCompletions);
      deferredCompletions.clear();
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      if (!lifetime->alive)
      {
         return;
      }
      for (DeferredCompletion& completion : completions)
      {
         if (completion.callback)
         {
            callbackActive = true;
            completion.callback.function(completion.callback.context,
                                         completion.ticket,
                                         std::move(completion.result));
            callbackActive = false;
            if (!lifetime->alive)
            {
               return;
            }
         }
      }
   }

   void rawFDPollHandler(void *owner, uint64_t generation, uint64_t ticket, int result) override
   {
      requireOwnerThread();
      if (owner != this)
      {
         return;
      }
      auto watchPosition = watches.find(ticket);
      if (watchPosition == watches.end() || watchPosition->second.generation != generation)
      {
         return;
      }
      const Watch watch = watchPosition->second;
      watches.erase(watchPosition);
      auto socketPosition = sockets.find(watch.fd);
      const bool acknowledgedActive = socketPosition != sockets.end() &&
                                      socketPosition->second.activeTicket == ticket;
      const bool current = acknowledgedActive &&
                           socketPosition->second.generation == generation;
      if (acknowledgedActive)
      {
         socketPosition->second.activeTicket = Ring::invalidRawPollTicket;
      }

      if (current && !stopping && !resetting && result != -ECANCELED &&
          socketPosition->second.mask != 0)
      {
         std::shared_ptr<LifetimeState> lifetime = lifetimeState;
         int events = 0;
         if (result < 0 || (unsigned(result) & (POLLERR | POLLHUP | POLLNVAL)))
         {
            events |= CURL_CSELECT_ERR;
         }
         if (result >= 0 && (unsigned(result) & POLLIN))
         {
            events |= CURL_CSELECT_IN;
         }
         if (result >= 0 && (unsigned(result) & POLLOUT))
         {
            events |= CURL_CSELECT_OUT;
         }
         runCurlAction(watch.fd, events);
         if (!lifetime->alive)
         {
            return;
         }
      }
      else
      {
         applySocketEvents();
         refreshTimer();
      }
      tryFinishReset();
      deliverDeferredCompletions();
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
      armedTimerDeadline = TimePoint::max();
      timer.clear();
      if (!stopping && result != -ECANCELED)
      {
         std::shared_ptr<LifetimeState> lifetime = lifetimeState;
         const TimePoint now = Clock::now();
         const bool curlTimerExpired = now >= requestedTimerDeadline;
         if (!expirePolicyDeadlines() || !lifetime->alive)
         {
            return;
         }
         if (curlTimerExpired)
         {
            requestedTimerDeadline = TimePoint::max();
            runCurlAction(CURL_SOCKET_TIMEOUT, 0);
            if (!lifetime->alive)
            {
               return;
            }
         }
         else
         {
            refreshTimer();
         }
      }
      else
      {
         refreshTimer();
      }
      tryFinishReset();
      deliverDeferredCompletions();
   }

public:

   explicit MultiCurlClient(AsyncDnsClient& requestedResolver)
       : MultiCurlClient(requestedResolver, Config {})
   {}

   MultiCurlClient(AsyncDnsClient& requestedResolver,
                   Config requested)
       : config(std::move(requested)),
         bindPool(config.localBinds),
         resolver(requestedResolver)
   {
      config.transfers = std::clamp(config.transfers, size_t(1), maximumTransfers);
      config.requestBytes = std::clamp(config.requestBytes, size_t(1), maximumRequestBytes);
      config.headerBytes = std::clamp(config.headerBytes, size_t(1), maximumHeaderBytes);
      config.responseBytes = std::clamp(config.responseBytes, size_t(1), maximumResponseBytes);
      config.totalConnections = std::clamp(config.totalConnections, size_t(1), maximumTransfers);
      config.hostConnections = std::clamp(config.hostConnections,
                                          size_t(1),
                                          config.totalConnections);
      config.concurrentStreams = std::clamp(config.concurrentStreams,
                                            size_t(1),
                                            maximumConcurrentStreams);
      config.defaultOverallTimeout = std::clamp(config.defaultOverallTimeout,
                                                std::chrono::milliseconds(1),
                                                std::chrono::duration_cast<std::chrono::milliseconds>(
                                                    std::chrono::hours(1)));
      config.defaultConnectTimeout = std::clamp(config.defaultConnectTimeout,
                                                std::chrono::milliseconds(1),
                                                config.defaultOverallTimeout);
      config.defaultFirstByteTimeout = std::clamp(config.defaultFirstByteTimeout,
                                                  std::chrono::milliseconds(1),
                                                  config.defaultOverallTimeout);
      config.defaultIdleTimeout = std::clamp(config.defaultIdleTimeout,
                                             std::chrono::milliseconds(1),
                                             config.defaultOverallTimeout);
      timer.originator = this;

      RingDispatcher& dispatcher = RingDispatcher::current();
      if (Ring::interfacer != &dispatcher)
      {
         initialization = InitializationStatus::ringDispatcherRequired;
         return;
      }
      if (threadOwner != nullptr)
      {
         initialization = InitializationStatus::threadClientAlreadyExists;
         return;
      }

      std::call_once(curlInitializationOnce, initializeCurl);
      if (curlInitializationResult != CURLE_OK)
      {
         initialization = InitializationStatus::curlInitializationFailed;
         return;
      }
      const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
      if (version == nullptr || !(version->features & CURL_VERSION_SSL))
      {
         initialization = InitializationStatus::sslRequired;
         return;
      }
      if (!(version->features & CURL_VERSION_HTTP2))
      {
         initialization = InitializationStatus::http2Required;
         return;
      }
      if (!initializeMultiHandle())
      {
         initialization = InitializationStatus::curlInitializationFailed;
         return;
      }

      threadOwner = this;
      RingDispatcher::installMultiplexee(this, this);
      dispatcherInstalled = true;
      initialization = InitializationStatus::ready;
   }

   ~MultiCurlClient()
   {
      requireOwnerThread();
      if (callbackActive)
      {
         std::abort();
      }
      lifetimeState->alive = false;
      shutdown();
      if (!teardownSafe())
      {
         std::abort();
      }
   }

   MultiCurlClient(const MultiCurlClient&) = delete;
   MultiCurlClient& operator=(const MultiCurlClient&) = delete;

   bool ready(void) const
   {
      requireOwnerThread();
      return initialization == InitializationStatus::ready && !stopping && !resetting && !fatalMulti;
   }

   InitializationStatus initializationStatus(void) const
   {
      requireOwnerThread();
      return initialization;
   }

   Ticket submit(Request request, Callback callback)
   {
      requireOwnerThread();
      Ticket ticket = issueTicket();
      if (stopping || policyCallbackActive || !ready())
      {
         Result result;
         result.status = stopping ? Status::shutdown : Status::initializationFailure;
         if (callback)
         {
            deliverNow(callback, ticket, std::move(result));
         }
         return ticket;
      }
      if (transfers.size() >= config.transfers)
      {
         Result result;
         result.status = Status::overloaded;
         if (callback)
         {
            deliverNow(callback, ticket, std::move(result));
         }
         return ticket;
      }
      size_t snapshotBytes = request.url.size() + request.resolveHost.size() + request.authority.size() +
                             request.body.size() +
                             request.originPolicy.requiredScheme.size() +
                             request.originPolicy.requiredHost.size() +
                             request.originPolicy.requiredAuthority.size() +
                             request.originPolicy.requiredService.size() +
                             request.originPolicy.requiredResolveHost.size() +
                             request.caFile.size() + request.caPath.size() + request.caBlob.size() +
                             request.clientCertificateFile.size() + request.clientKeyFile.size() +
                             request.clientCertificateBlob.size() + request.clientKeyBlob.size();
      for (const Header& header : request.headers)
      {
         const size_t headerBytes = header.name.size() + header.value.size();
         if (headerBytes > std::numeric_limits<size_t>::max() - snapshotBytes)
         {
            snapshotBytes = std::numeric_limits<size_t>::max();
            break;
         }
         snapshotBytes += headerBytes;
      }
      const bool certificatePathsPaired = request.clientCertificateFile.empty() ==
                                          request.clientKeyFile.empty();
      const bool certificateBlobsPaired = request.clientCertificateBlob.empty() ==
                                          request.clientKeyBlob.empty();
      const bool mixedCertificateSources = !request.clientCertificateFile.empty() &&
                                           !request.clientCertificateBlob.empty();
      const bool invalidTimeout = request.connectTimeout < std::chrono::milliseconds::zero() ||
                                  request.firstByteTimeout < std::chrono::milliseconds::zero() ||
                                  request.idleTimeout < std::chrono::milliseconds::zero();
      const bool invalidMethodBody = !request.body.empty() &&
                                     (request.method == Method::get || request.method == Method::head);
      if (snapshotBytes > config.requestBytes || !certificatePathsPaired ||
          !certificateBlobsPaired || mixedCertificateSources || invalidTimeout ||
          invalidMethodBody || !validAuthority(request.authority))
      {
         Result result;
         result.status = snapshotBytes > config.requestBytes
                             ? Status::requestTooLarge
                             : Status::invalidRequest;
         if (callback)
         {
            deliverNow(callback, ticket, std::move(result));
         }
         return ticket;
      }

      auto transfer = std::make_unique<Transfer>();
      transfer->owner = this;
      transfer->ticket = ticket;
      transfer->request = std::move(request);
      transfer->callback = callback;
      transfer->responseLimit = transfer->request.responseBytes == 0
                                    ? config.responseBytes
                                    : std::min(transfer->request.responseBytes, config.responseBytes);
      transfer->submitted = Clock::now();
      transfer->lastActivity = transfer->submitted;
      const auto maximumRequestDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::hours(1));
      transfer->overallDeadline = transfer->request.overallDeadline == TimePoint::max()
                                      ? transfer->submitted + config.defaultOverallTimeout
                                      : std::min(transfer->request.overallDeadline,
                                                 transfer->submitted + maximumRequestDuration);
      const auto firstByteTimeout = transfer->request.firstByteTimeout > std::chrono::milliseconds::zero()
                                        ? std::min(transfer->request.firstByteTimeout,
                                                   maximumRequestDuration)
                                        : config.defaultFirstByteTimeout;
      transfer->firstByteDeadline = std::min(transfer->overallDeadline,
                                             transfer->submitted + firstByteTimeout);
      transfer->idleTimeout = transfer->request.idleTimeout > std::chrono::milliseconds::zero()
                                  ? std::min(transfer->request.idleTimeout,
                                             maximumRequestDuration)
                                  : config.defaultIdleTimeout;
      if (transfer->request.connectTimeout > maximumRequestDuration)
      {
         transfer->request.connectTimeout = maximumRequestDuration;
      }
      if (transfer->overallDeadline <= transfer->submitted)
      {
         Result result;
         result.status = Status::deadlineExceeded;
         if (callback)
         {
            deliverNow(callback, ticket, std::move(result));
         }
         return ticket;
      }
      std::shared_ptr<LifetimeState> policyLifetime = lifetimeState;
      const bool endpointAccepted = parseEndpoint(*transfer);
      if (!policyLifetime->alive)
      {
         return ticket;
      }
      if (!endpointAccepted)
      {
         Result result;
         result.status = Status::unsupportedProtocol;
         if (callback)
         {
            deliverNow(callback, ticket, std::move(result));
         }
         return ticket;
      }

      transfers.emplace(ticket.identifier, std::move(transfer));
      (void)startResolution(ticket.identifier);
      return ticket;
   }

   bool cancel(Ticket ticket)
   {
      requireOwnerThread();
      if (policyCallbackActive)
      {
         return false;
      }
      auto position = transfers.find(ticket.identifier);
      if (position == transfers.end() || position->second->ticket.generation != ticket.generation)
      {
         return false;
      }
      Transfer& transfer = *position->second;
      transfer.forcedStatus = Status::canceled;
      if (transfer.state == TransferState::resolving && resolver.cancel(transfer.dnsTicket))
      {
         return true;
      }
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      finish(ticket.identifier, Status::canceled, CURLE_ABORTED_BY_CALLBACK);
      if (!lifetime->alive)
      {
         return true;
      }
      (void)afterCurlFrame();
      return true;
   }

   bool reset(void)
   {
      requireOwnerThread();
      if (policyCallbackActive)
      {
         return false;
      }
      return beginReset(Status::reset, false);
   }

   bool shutdown(void)
   {
      requireOwnerThread();
      if (policyCallbackActive && lifetimeState->alive)
      {
         return false;
      }
      if (!stopping)
      {
         stopping = true;
         deferCallbacks = true;
         (void)completeAll(Status::shutdown, CURLE_ABORTED_BY_CALLBACK);

         if (multi)
         {
            curl_multi_cleanup(multi);
            multi = nullptr;
         }
         for (CURL *easy : orphanedEasyHandles)
         {
            curl_easy_cleanup(easy);
         }
         orphanedEasyHandles.clear();
         requestedTimerDeadline = TimePoint::max();
         applySocketEvents();
         for (auto& [ticket, watch] : watches)
         {
            (void)watch;
            cancelWatch(ticket);
         }
         for (auto& [fd, socket] : sockets)
         {
            (void)fd;
            socket.mask = 0;
         }
         refreshTimer();
      }
      applySocketEvents();
      std::shared_ptr<LifetimeState> lifetime = lifetimeState;
      const bool callbacksLive = lifetime->alive;
      deliverDeferredCompletions();
      if (callbacksLive && !lifetime->alive)
      {
         return true;
      }
      return teardownSafe();
   }

   bool shutdownSafe(void) const
   {
      requireOwnerThread();
      return teardownSafe();
   }

   size_t activeTransferCount(void) const
   {
      requireOwnerThread();
      return transfers.size();
   }

   size_t activeWatcherCount(void) const
   {
      requireOwnerThread();
      return watches.size();
   }
};
