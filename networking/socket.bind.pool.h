// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <services/hash.h>
#include <types/types.containers.h>

#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

class LocalSocketBindSet
{
public:

   static constexpr size_t maximumEndpoints = 256;

   struct Endpoint
   {
      sockaddr_storage address = {};
      socklen_t length = 0;
      bool freebind = false;
   };

private:

   Vector<Endpoint> ipv4Endpoints;
   Vector<Endpoint> ipv6Endpoints;

   static bool sameAddress(const sockaddr *left,
                           socklen_t leftLength,
                           const sockaddr *right,
                           socklen_t rightLength)
   {
      if (left == nullptr || right == nullptr || left->sa_family != right->sa_family)
      {
         return false;
      }
      if (left->sa_family == AF_INET &&
          leftLength == sizeof(sockaddr_in) && rightLength == sizeof(sockaddr_in))
      {
         const sockaddr_in *left4 = reinterpret_cast<const sockaddr_in *>(left);
         const sockaddr_in *right4 = reinterpret_cast<const sockaddr_in *>(right);
         return left4->sin_port == right4->sin_port &&
                std::memcmp(&left4->sin_addr, &right4->sin_addr, sizeof(in_addr)) == 0;
      }
      if (left->sa_family == AF_INET6 &&
          leftLength == sizeof(sockaddr_in6) && rightLength == sizeof(sockaddr_in6))
      {
         const sockaddr_in6 *left6 = reinterpret_cast<const sockaddr_in6 *>(left);
         const sockaddr_in6 *right6 = reinterpret_cast<const sockaddr_in6 *>(right);
         return left6->sin6_port == right6->sin6_port &&
                left6->sin6_scope_id == right6->sin6_scope_id &&
                std::memcmp(&left6->sin6_addr, &right6->sin6_addr, sizeof(in6_addr)) == 0;
      }
      return false;
   }

public:

   bool add(const sockaddr *address, socklen_t length, bool freebind = false)
   {
      if (address == nullptr || size() >= maximumEndpoints ||
          (address->sa_family == AF_INET && length != sizeof(sockaddr_in)) ||
          (address->sa_family == AF_INET6 && length != sizeof(sockaddr_in6)) ||
          (address->sa_family != AF_INET && address->sa_family != AF_INET6))
      {
         return false;
      }
      const uint16_t port = address->sa_family == AF_INET
                                ? reinterpret_cast<const sockaddr_in *>(address)->sin_port
                                : reinterpret_cast<const sockaddr_in6 *>(address)->sin6_port;
      if (port == 0 || containsLocal(address, length))
      {
         return false;
      }
      Vector<Endpoint>& endpoints = address->sa_family == AF_INET
                                        ? ipv4Endpoints
                                        : ipv6Endpoints;
      Endpoint& endpoint = endpoints.emplace_back();
      std::memcpy(&endpoint.address, address, length);
      endpoint.length = length;
      endpoint.freebind = freebind;
      return true;
   }

   const Endpoint *at(size_t index) const
   {
      if (index < ipv4Endpoints.size())
      {
         return &ipv4Endpoints[index];
      }
      index -= ipv4Endpoints.size();
      return index < ipv6Endpoints.size() ? &ipv6Endpoints[index] : nullptr;
   }

   size_t size(void) const
   {
      return ipv4Endpoints.size() + ipv6Endpoints.size();
   }

   size_t count(sa_family_t family) const
   {
      return family == AF_INET
                 ? ipv4Endpoints.size()
                 : family == AF_INET6 ? ipv6Endpoints.size() : 0;
   }

   const Endpoint *at(sa_family_t family, size_t familyIndex) const
   {
      const Vector<Endpoint> *endpoints = family == AF_INET
                                              ? &ipv4Endpoints
                                              : family == AF_INET6 ? &ipv6Endpoints : nullptr;
      return endpoints && familyIndex < endpoints->size() ? &(*endpoints)[familyIndex] : nullptr;
   }

   bool empty(void) const
   {
      return ipv4Endpoints.empty() && ipv6Endpoints.empty();
   }

   bool containsLocal(const sockaddr *address, socklen_t length) const
   {
      if (address == nullptr)
      {
         return false;
      }
      const Vector<Endpoint> *endpoints = address->sa_family == AF_INET
                                              ? &ipv4Endpoints
                                              : address->sa_family == AF_INET6 ? &ipv6Endpoints : nullptr;
      if (endpoints == nullptr)
      {
         return false;
      }
      for (const Endpoint& endpoint : *endpoints)
      {
         if (sameAddress(reinterpret_cast<const sockaddr *>(&endpoint.address),
                         endpoint.length,
                         address,
                         length))
         {
            return true;
         }
      }
      return false;
   }
};

class LocalSocketBindPool
{
public:

   using Clock = std::chrono::steady_clock;
   using TimePoint = Clock::time_point;
   static constexpr size_t maximumActiveLeases = 1024;
   static constexpr size_t maximumTcpQuarantines = 4096;
   static constexpr std::chrono::seconds tcpQuarantineDuration = std::chrono::seconds(120);

   struct TimeSource
   {
      void *context = nullptr;
      TimePoint (*function)(void *context) = nullptr;

      TimePoint now(void) const
      {
         return function ? function(context) : Clock::now();
      }
   };

   enum class AcquireStatus : uint8_t
   {
      bound,
      exhausted,
      systemFailure
   };

   struct AcquireResult
   {
      AcquireStatus status = AcquireStatus::systemFailure;
      const LocalSocketBindSet::Endpoint *endpoint = nullptr;

      explicit operator bool(void) const
      {
         return status == AcquireStatus::bound;
      }
   };

private:

   struct Address
   {
      sa_family_t family = AF_UNSPEC;
      uint16_t port = 0;
      uint32_t scope = 0;
      uint8_t bytes[16] = {};

      bool operator==(const Address& other) const
      {
         return family == other.family && port == other.port && scope == other.scope &&
                std::memcmp(bytes, other.bytes, sizeof(bytes)) == 0;
      }
   };

   struct Tuple
   {
      Address local;
      Address remote;
      int socketType = 0;

      bool operator==(const Tuple& other) const
      {
         return socketType == other.socketType && local == other.local && remote == other.remote;
      }

      uint64_t hash(void) const
      {
         uint8_t material[2 * (sizeof(sa_family_t) + sizeof(uint16_t) +
                               sizeof(uint32_t) + 16) + sizeof(int)] = {};
         size_t offset = 0;
         const auto appendAddress = [&](const Address& address)
         {
            std::memcpy(material + offset, &address.family, sizeof(address.family));
            offset += sizeof(address.family);
            std::memcpy(material + offset, &address.port, sizeof(address.port));
            offset += sizeof(address.port);
            std::memcpy(material + offset, &address.scope, sizeof(address.scope));
            offset += sizeof(address.scope);
            std::memcpy(material + offset, address.bytes, sizeof(address.bytes));
            offset += sizeof(address.bytes);
         };
         appendAddress(local);
         appendAddress(remote);
         std::memcpy(material + offset, &socketType, sizeof(socketType));
         return Hasher::hash<Hasher::SeedPolicy::thread_shared>(material, sizeof(material));
      }
   };

   struct Lease
   {
      Tuple tuple;
   };

   const LocalSocketBindSet bindSet;
   TimeSource timeSource;
   bytell_hash_map<int, Lease> leasesByFd;
   bytell_hash_set<Tuple> activeTuples;
   bytell_hash_map<Tuple, TimePoint> tcpQuarantines;
   size_t nextIpv4 = 0;
   size_t nextIpv6 = 0;
   size_t activeTcpLeases = 0;

   static bool addressFrom(const sockaddr *address, socklen_t length, Address& out)
   {
      out = {};
      if (address == nullptr)
      {
         return false;
      }
      out.family = address->sa_family;
      if (address->sa_family == AF_INET && length == sizeof(sockaddr_in))
      {
         const sockaddr_in *address4 = reinterpret_cast<const sockaddr_in *>(address);
         out.port = address4->sin_port;
         std::memcpy(out.bytes, &address4->sin_addr, sizeof(address4->sin_addr));
         return out.port != 0;
      }
      if (address->sa_family == AF_INET6 && length == sizeof(sockaddr_in6))
      {
         const sockaddr_in6 *address6 = reinterpret_cast<const sockaddr_in6 *>(address);
         out.port = address6->sin6_port;
         out.scope = address6->sin6_scope_id;
         std::memcpy(out.bytes, &address6->sin6_addr, sizeof(address6->sin6_addr));
         return out.port != 0;
      }
      return false;
   }

   enum class BindStatus : uint8_t
   {
      bound,
      unavailable,
      systemFailure
   };

   static bool sameEndpoint(const LocalSocketBindSet::Endpoint& endpoint,
                            const sockaddr *actual,
                            socklen_t actualLength)
   {
      Address expected;
      Address observed;
      return addressFrom(reinterpret_cast<const sockaddr *>(&endpoint.address),
                         endpoint.length,
                         expected) &&
             addressFrom(actual, actualLength, observed) && expected == observed;
   }

   static BindStatus bindEndpoint(int fd, const LocalSocketBindSet::Endpoint& endpoint)
   {
      const sockaddr *local = reinterpret_cast<const sockaddr *>(&endpoint.address);
      const int enabled = 1;
      int freebindLevel = 0;
      int freebindOption = 0;
#if defined(__linux__) && defined(IP_FREEBIND) && defined(IPV6_FREEBIND)
      if (local->sa_family == AF_INET)
      {
         freebindLevel = SOL_IP;
         freebindOption = IP_FREEBIND;
      }
      else
      {
         freebindLevel = SOL_IPV6;
         freebindOption = IPV6_FREEBIND;
      }
#else
      if (endpoint.freebind)
      {
         errno = ENOTSUP;
         return BindStatus::systemFailure;
      }
#endif
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0 ||
          (endpoint.freebind &&
           setsockopt(fd, freebindLevel, freebindOption, &enabled, sizeof(enabled)) != 0))
      {
         return BindStatus::systemFailure;
      }
      if (::bind(fd, local, endpoint.length) != 0)
      {
         return errno == EADDRINUSE || errno == EADDRNOTAVAIL
                    ? BindStatus::unavailable
                    : BindStatus::systemFailure;
      }
      sockaddr_storage actual = {};
      socklen_t actualLength = sizeof(actual);
      return getsockname(fd, reinterpret_cast<sockaddr *>(&actual), &actualLength) == 0 &&
                     sameEndpoint(endpoint,
                                  reinterpret_cast<const sockaddr *>(&actual),
                                  actualLength)
                 ? BindStatus::bound
                 : BindStatus::systemFailure;
   }

   void expireTcpQuarantines(void)
   {
      const TimePoint now = timeSource.now();
      for (auto position = tcpQuarantines.begin(); position != tcpQuarantines.end();)
      {
         if (position->second <= now)
         {
            position = tcpQuarantines.erase(position);
         }
         else
         {
            ++position;
         }
      }
   }

   const LocalSocketBindSet::Endpoint *endpointFor(const Address& address) const
   {
      const size_t endpointCount = bindSet.count(address.family);
      for (size_t index = 0; index < endpointCount; ++index)
      {
         const LocalSocketBindSet::Endpoint *endpoint = bindSet.at(address.family, index);
         Address candidate;
         if (addressFrom(reinterpret_cast<const sockaddr *>(&endpoint->address),
                         endpoint->length,
                         candidate) && candidate == address)
         {
            return endpoint;
         }
      }
      return nullptr;
   }

public:

   explicit LocalSocketBindPool(LocalSocketBindSet configured = {})
       : LocalSocketBindPool(std::move(configured), TimeSource {})
   {}

   LocalSocketBindPool(LocalSocketBindSet configured, TimeSource clock)
       : bindSet(std::move(configured)),
         timeSource(clock)
   {
      leasesByFd.reserve(maximumActiveLeases);
      activeTuples.reserve(maximumActiveLeases);
      tcpQuarantines.reserve(maximumTcpQuarantines);
   }

   ~LocalSocketBindPool()
   {
      if (!drained())
      {
         std::abort();
      }
   }

   LocalSocketBindPool(const LocalSocketBindPool&) = delete;
   LocalSocketBindPool& operator=(const LocalSocketBindPool&) = delete;
   LocalSocketBindPool(LocalSocketBindPool&&) = delete;
   LocalSocketBindPool& operator=(LocalSocketBindPool&&) = delete;

   AcquireResult acquireAndBind(int fd,
                                const sockaddr *remote,
                                socklen_t remoteLength,
                                int socketType)
   {
      if (fd < 0 || (socketType != SOCK_STREAM && socketType != SOCK_DGRAM))
      {
         errno = EINVAL;
         return {AcquireStatus::systemFailure};
      }
      Address remoteAddress;
      if (!addressFrom(remote, remoteLength, remoteAddress))
      {
         errno = EAFNOSUPPORT;
         return {AcquireStatus::systemFailure};
      }
      auto existingLease = leasesByFd.find(fd);
      if (existingLease != leasesByFd.end())
      {
         const Tuple& tuple = existingLease->second.tuple;
         if (tuple.socketType == socketType && tuple.remote == remoteAddress)
         {
            return {AcquireStatus::bound, endpointFor(tuple.local)};
         }
         errno = EISCONN;
         return {AcquireStatus::systemFailure};
      }
      expireTcpQuarantines();
      if (leasesByFd.size() >= maximumActiveLeases ||
          (socketType == SOCK_STREAM &&
           tcpQuarantines.size() + activeTcpLeases >= maximumTcpQuarantines))
      {
         errno = EADDRNOTAVAIL;
         return {AcquireStatus::exhausted};
      }

      const size_t endpointCount = bindSet.count(remoteAddress.family);
      if (endpointCount == 0)
      {
         errno = EADDRNOTAVAIL;
         return {AcquireStatus::exhausted};
      }
      size_t& cursor = remoteAddress.family == AF_INET ? nextIpv4 : nextIpv6;
      for (size_t offset = 0; offset < endpointCount; ++offset)
      {
         const size_t index = (cursor + offset) % endpointCount;
         const LocalSocketBindSet::Endpoint *endpoint = bindSet.at(remoteAddress.family, index);
         const sockaddr *local = reinterpret_cast<const sockaddr *>(&endpoint->address);
         Tuple tuple;
         if (!addressFrom(local, endpoint->length, tuple.local))
         {
            errno = EINVAL;
            return {AcquireStatus::systemFailure};
         }
         tuple.remote = remoteAddress;
         tuple.socketType = socketType;
         if (activeTuples.contains(tuple) ||
             (socketType == SOCK_STREAM && tcpQuarantines.contains(tuple)))
         {
            continue;
         }
         const BindStatus bindStatus = bindEndpoint(fd, *endpoint);
         if (bindStatus != BindStatus::bound)
         {
            if (bindStatus == BindStatus::systemFailure)
            {
               return {AcquireStatus::systemFailure};
            }
            else if (socketType == SOCK_STREAM)
            {
               if (tcpQuarantines.size() + activeTcpLeases >= maximumTcpQuarantines)
               {
                  errno = EADDRNOTAVAIL;
                  return {AcquireStatus::exhausted};
               }
               tcpQuarantines.emplace(tuple, timeSource.now() + tcpQuarantineDuration);
            }
            continue;
         }
         leasesByFd.emplace(fd, Lease {tuple});
         activeTuples.emplace(tuple);
         activeTcpLeases += socketType == SOCK_STREAM ? 1 : 0;
         cursor = (index + 1) % endpointCount;
         return {AcquireStatus::bound, endpoint};
      }
      errno = EADDRNOTAVAIL;
      return {AcquireStatus::exhausted};
   }

   bool release(int fd)
   {
      auto lease = leasesByFd.find(fd);
      if (lease == leasesByFd.end())
      {
         return false;
      }
      const Tuple tuple = lease->second.tuple;
      activeTuples.erase(tuple);
      if (tuple.socketType == SOCK_STREAM)
      {
         tcpQuarantines.emplace(tuple, timeSource.now() + tcpQuarantineDuration);
         --activeTcpLeases;
      }
      leasesByFd.erase(lease);
      return true;
   }

   bool containsLocal(const sockaddr *address, socklen_t length) const
   {
      return bindSet.containsLocal(address, length);
   }

   size_t activeLeaseCount(void) const
   {
      return leasesByFd.size();
   }

   bool drained(void) const
   {
      return leasesByFd.empty() && activeTuples.empty();
   }
};
