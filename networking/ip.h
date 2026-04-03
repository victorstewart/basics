// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bitset>
#include <cstdint>
#include <cstring>

#pragma once

struct IPAddress {

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnested-anon-types"
#endif
  union {
    union {
      uint32_t v4;
      uint32_t dummy6[4];
    };
    union {
      uint8_t dummy4[4];
      uint8_t v6[16];
    };
  };
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

  bool is6 = false;

  uint64_t hash(void) const
  {
    return Hasher::hash<Hasher::SeedPolicy::thread_shared>(v6, 17);
  }

  bool equals(const IPAddress& lhs) const
  {
    return memcmp(&v6, &lhs.v6, 17) == 0;
  }

  bool isNull(void) const
  {
    uint8_t null[16] = {0};

    return (memcmp(v6, null, 16) == 0);
  }

  IPAddress create4in6(void)
  {
    IPAddress in6;
    in6.is6 = true;
    in6.v6[10] = 0xff;
    in6.v6[11] = 0xff;
    in6.v6[12] = dummy4[0];
    in6.v6[13] = dummy4[1];
    in6.v6[14] = dummy4[2];
    in6.v6[15] = dummy4[3];
    return in6;
  }

  IPAddress(const char *address, bool _is6)
      : is6(_is6)
  {
    memset(v6, 0, sizeof(v6));
    inet_pton(is6 ? AF_INET6 : AF_INET, address, v6);
  }

  explicit IPAddress(uint128_t address)
  {
    memcpy(v6, &address, 16);
    is6 = true;
  }

  IPAddress()
      : v6 {0}
  {}
};

template <typename S>
static void serialize(S&& serializer, IPAddress& address)
{
  uint8_t *v6 = address.v6;
  // uint8_t *v6 = ;
  serializer.ext(v6, bitsery::ext::FixedBinarySequence<16> {});
  serializer.value1b(address.is6);
}

struct IPPrefix {
private:

  std::bitset<128> convertToBitsetReversed(const uint8_t value[16]) const
  {
    std::bitset<128> result;

    for (int i = 0; i < 16; ++i)
    {
      for (int j = 0; j < 8; ++j)
      {
        result.set(127 - (i * 8 + (7 - j)), (value[i] >> j) & 1);
      }
    }

    return result;
  }

public:

  IPAddress network;
  uint8_t cidr;

  bool containsAddress(const IPAddress& address) const
  {
    if (address.is6 != network.is6)
    {
      return false;
    }

    uint8_t maxCidr = network.is6 ? 128 : 32;
    if (cidr > maxCidr)
    {
      return false;
    }

    if (cidr == 0)
    {
      return true;
    }

    if (network.is6) // bit operations on these big numbers do not work at least as of Clang 17.0.1 so we have to do it this bitset way
    {
      std::bitset<128> mask;
      mask.set();
      mask <<= (128 - cidr);

      return (convertToBitsetReversed(address.v6) & mask) == (convertToBitsetReversed(network.v6) & mask);
    }
    else
    {
      uint32_t mask = (cidr == 32) ? 0xffffffffu : (0xffffffffu << (32 - cidr));

      // we need to convert to host byte order before doing the comparison
      return (ntohl(address.v4) & mask) == (ntohl(network.v4) & mask);
    }
  }

  uint8_t hostBits(void) const
  {
    return uint8_t((network.is6 ? 128 : 32) - cidr);
  }

  void canonicalize(void)
  {
    if (network.is6 == false)
    {
      uint32_t hostOrder = ntohl(network.v4);
      uint32_t mask = 0;
      if (cidr > 0)
      {
        mask = (cidr == 32) ? 0xffffffffu : (0xffffffffu << (32 - cidr));
      }

      network.v4 = htonl(hostOrder & mask);
      return;
    }

    uint8_t fullBytes = uint8_t(cidr / 8);
    uint8_t trailingBits = uint8_t(cidr % 8);

    if (trailingBits > 0 && fullBytes < 16)
    {
      network.v6[fullBytes] &= uint8_t(0xffu << (8 - trailingBits));
      fullBytes += 1;
    }

    for (uint8_t index = fullBytes; index < 16; ++index)
    {
      network.v6[index] = 0;
    }
  }

  IPPrefix canonicalized(void) const
  {
    IPPrefix copy = *this;
    copy.canonicalize();
    return copy;
  }

  uint64_t hash(void) const
  {
    uint8_t bytes[18];
    memcpy(bytes, network.v6, 16);
    bytes[16] = static_cast<uint8_t>(network.is6);
    bytes[17] = cidr;
    return Hasher::hash<Hasher::SeedPolicy::thread_shared>(bytes, sizeof(bytes));
  }

  bool equals(const IPPrefix& lhs) const
  {
    return (cidr == lhs.cidr) && network.equals(lhs.network);
  }

  void assign(uint128_t address, uint8_t _cidr)
  {
    memcpy(network.v6, &address, 16);
    network.is6 = true;
    cidr = _cidr;
  }

  IPPrefix(uint128_t address, uint8_t _cidr)
      : network(address),
        cidr(_cidr)
  {}
  IPPrefix(const char *address, bool is6, uint8_t _cidr)
      : network(address, is6),
        cidr(_cidr)
  {}
  IPPrefix()
      : cidr(0)
  {}
};

template <typename S>
static void serialize(S&& serializer, IPPrefix& prefix)
{
  serializer.object(prefix.network);
  serializer.value1b(prefix.cidr);
}

// 	// 169.254.0.0/16
// 	#define IN_LINKLOCAL(i) ((*(uint32_t*)(i) & 0xffff0000) == 0xa9fe0000)

// 	// 10.0.0.0/8
// 	#define IN_PRIVATE_10(i) ((*(uint32_t*)(i) & 0xffff0000) == 0x0a000000)

// 	// 172.16.0.0/12
// 	#define IN_PRIVATE_172_16(i) ((*(uint32_t*)(i) & 0xffff0000) == 0xac100000)
// 	// 192.168.0.0/16
// 	#define IN_PRIVATE_192_168(i) ((*(uint32_t*)(i) & 0xffff0000) == 0xc0a80000)

// 	static inline bytell_hash_map<uint32_t, uint32_t> address4ToIdx;
// 	static inline bytell_hash_map<uint128_t, uint32_t> address6ToIdx;

// public:

// 	static inline struct in6_addr anycast_ipv6;
// 	static inline struct in6_addr public_ipv6;
// 	static inline struct in_addr anycast_ipv4;
// 	static inline struct in_addr public_ipv4;
// 	static inline struct in_addr private_ipv4;

// 	static uint32_t ifidxForAddress(struct sockaddr_storage *address)
// 	{
// 		if (address->ss_family == AF_INET)
// 		{
// 			struct sockaddr_in *addr_in4 = (struct sockaddr_in *)address;

// 			if (auto it = address4ToIdx.find(addr_in4->sin_addr.s_addr); it != address4ToIdx.end())
// 			{
// 				return it->second;
// 			}
// 		}
// 		else if (address->ss_family == AF_INET6)
// 		{
// 			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;

// 			uint128_t address6;
// 			memcpy(&address6, &addr_in6->sin6_addr.s6_addr, 16);

// 			if (auto it = address6ToIdx.find(address6); it != address6ToIdx.end())
// 			{
// 				return it->second;
// 			}
// 		}

// 		return 0;
// 	}

// 	static void gatherAddresses(void)
// 	{
// 		inet_pton(AF_INET6, "2602:FAC0:0001::1", &anycast_ipv6);
// 		inet_pton(AF_INET, "23.144.200.1", &anycast_ipv4);

// 		struct ifaddrs *ifap;
// 	 	getifaddrs(&ifap);

// 	 	for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next)
// 		{
// 			unsigned int ifidx = if_nametoindex(ifa->ifa_name);

// 			if (ifa->ifa_addr)
// 			{
// 				if (ifa->ifa_addr->sa_family == AF_INET6)
// 				{
// 					struct in6_addr working6 = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

// 					// unsigned char   s6_addr[16];
// 					uint128_t address6;
// 					memcpy(&address6, &working6.s6_addr, 16);

// 					address6ToIdx[address6] = ifidx;

// 					if (unlikely(IN6_IS_ADDR_UNSPECIFIED(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_LOOPBACK(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_V4MAPPED(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_V4COMPAT(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_LINKLOCAL(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_SITELOCAL(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_UNIQUELOCAL(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_6TO4(&working6))) continue;
// 					if (unlikely(IN6_IS_ADDR_MULTICAST(&working6))) continue;

// 					// compare the first 5 bytes, that's the prefix we own
// 					if (memcmp(&anycast_ipv6.s6_addr, &working6.s6_addr, 5) != 0)
// 					{
// 						public_ipv6 = working6;
// 						// public_ipv6_ifidx = ifidx;
// 					}
// 					else
// 					{
// 						// anycast_ipv6_ifidx = ifidx;
// 					}
// 				}
// 				else if (ifa->ifa_addr->sa_family == AF_INET)
// 				{
// 					struct in_addr working4 = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

// 					address4ToIdx[working4.s_addr] = ifidx;

// 					if (unlikely(IN_LOOPBACK(&working4))) continue;
// 					if (unlikely(IN_MULTICAST(working4.s_addr))) continue;
// 					if (unlikely(IN_BADCLASS(working4.s_addr))) continue;
// 					if (unlikely(IN_LINKLOCAL(&working4))) continue;
// 					if (unlikely(IN_PRIVATE_172_16(&working4))) continue;
// 					if (unlikely(IN_PRIVATE_192_168(&working4))) continue;

// 					if (IN_PRIVATE_10(&working4))
// 					{
// 						// private ipv4
// 						private_ipv4 = working4;
// 						// private_ipv4_ifidx = ifidx;
// 					}
// 					else
// 					{
// 						// compare the first 3 bytes, that's the prefix we own
// 						if (memcmp(&anycast_ipv4.s_addr, &working4.s_addr, 3) != 0)
// 						{
// 							public_ipv4 = working4;
// 							// public_ipv4_ifidx = ifidx;
// 						}
// 						else
// 						{
// 							// anycast_ipv4_ifidx = ifidx;
// 						}
// 					}
// 				}
// 				else continue;
// 			}
// 	   }

// 	   freeifaddrs(ifap);
// 	}
// };
