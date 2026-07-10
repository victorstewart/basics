// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/happy.eyeballs.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>

using Resolver = AsyncDnsResolver;

static Resolver::Address address4(const char *text, uint16_t port, uint32_t ttl = 30)
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

static Resolver::Address address6(const char *text,
                                  uint16_t port,
                                  uint32_t scope = 0,
                                  uint32_t ttl = 30)
{
   sockaddr_in6 address = {};
   address.sin6_family = AF_INET6;
   address.sin6_port = htons(port);
   address.sin6_scope_id = scope;
   inet_pton(AF_INET6, text, &address.sin6_addr);

   Resolver::Address result;
   std::memcpy(&result.storage, &address, sizeof(address));
   result.length = sizeof(address);
   result.ttlSeconds = ttl;
   return result;
}

static Resolver::Result successful(void)
{
   Resolver::Result result;
   result.status = Resolver::Status::success;
   return result;
}

static const sockaddr_in& ipv4(const HappyEyeballsPlan::Attempt& attempt)
{
   return *reinterpret_cast<const sockaddr_in *>(&attempt.address.storage);
}

static const sockaddr_in6& ipv6(const HappyEyeballsPlan::Attempt& attempt)
{
   return *reinterpret_cast<const sockaddr_in6 *>(&attempt.address.storage);
}

static void testResultValidation(TestSuite& suite)
{
   Resolver::Result failed;
   failed.status = Resolver::Status::notFound;
   HappyEyeballsPlan failure(failed);
   EXPECT_FALSE(suite, failure.valid());
   EXPECT_TRUE(suite, failure.status() == HappyEyeballsPlan::Status::resolverFailure);

   HappyEyeballsPlan empty(successful());
   EXPECT_FALSE(suite, empty.valid());
   EXPECT_TRUE(suite, empty.status() == HappyEyeballsPlan::Status::noUsableAddresses);

   Resolver::Result malformed = successful();
   Resolver::Address shortAddress = address4("192.0.2.1", 443);
   --shortAddress.length;
   malformed.addresses.push_back(shortAddress);
   malformed.addresses.push_back({});
   HappyEyeballsPlan noUsableAddresses(malformed);
   EXPECT_TRUE(suite, noUsableAddresses.status() == HappyEyeballsPlan::Status::noUsableAddresses);

   Resolver::Result excessive = successful();
   for (size_t index = 0; index <= Resolver::maximumAnswers; ++index)
   {
      excessive.addresses.push_back(address4("192.0.2.1", uint16_t(1000 + index)));
   }
   HappyEyeballsPlan invalid(excessive);
   EXPECT_TRUE(suite, invalid.status() == HappyEyeballsPlan::Status::invalidResult);
   EXPECT_EQ(suite, invalid.size(), size_t(0));
}

static void testAlternatingResolverOrder(TestSuite& suite)
{
   Resolver::Result result = successful();
   Resolver::Address malformed = address6("2001:db8::ffff", 443);
   malformed.length = sizeof(sockaddr_in);
   result.addresses.push_back(malformed);
   result.addresses.push_back(address4("192.0.2.1", 443));
   result.addresses.push_back(address4("192.0.2.2", 443));
   result.addresses.push_back(address6("2001:db8::1", 443));
   result.addresses.push_back(address6("2001:db8::2", 443));
   result.addresses.push_back(address6("2001:db8::3", 443));

   HappyEyeballsPlan plan(result);
   EXPECT_TRUE(suite, plan.valid());
   EXPECT_EQ(suite, plan.size(), size_t(5));
   EXPECT_EQ(suite, plan[0].address.family(), AF_INET);
   EXPECT_EQ(suite, plan[1].address.family(), AF_INET6);
   EXPECT_EQ(suite, plan[2].address.family(), AF_INET);
   EXPECT_EQ(suite, plan[3].address.family(), AF_INET6);
   EXPECT_EQ(suite, plan[4].address.family(), AF_INET6);
   EXPECT_EQ(suite, ipv4(plan[0]).sin_addr.s_addr, inet_addr("192.0.2.1"));
   EXPECT_EQ(suite, ipv4(plan[2]).sin_addr.s_addr, inet_addr("192.0.2.2"));
   EXPECT_EQ(suite, plan[0].delay, std::chrono::milliseconds(0));
   EXPECT_EQ(suite, plan[4].delay, std::chrono::milliseconds(250));
}

static void testDuplicateIdentityAndEndpointPreservation(TestSuite& suite)
{
   Resolver::Result result = successful();
   result.addresses.push_back(address6("fe80::1", 443, 7, 10));
   result.addresses.push_back(address6("fe80::1", 443, 7, 99));
   result.addresses.push_back(address6("fe80::1", 8443, 7));
   result.addresses.push_back(address6("fe80::1", 443, 8));
   result.addresses.push_back(address4("192.0.2.1", 443, 11));
   result.addresses.push_back(address4("192.0.2.1", 443, 99));
   result.addresses.push_back(address4("192.0.2.1", 8443));

   HappyEyeballsPlan plan(result);
   EXPECT_TRUE(suite, plan.valid());
   EXPECT_EQ(suite, plan.size(), size_t(5));
   EXPECT_EQ(suite, plan[0].address.family(), AF_INET6);
   EXPECT_EQ(suite, plan[1].address.family(), AF_INET);
   EXPECT_EQ(suite, ntohs(ipv6(plan[0]).sin6_port), uint16_t(443));
   EXPECT_EQ(suite, ipv6(plan[0]).sin6_scope_id, uint32_t(7));
   EXPECT_EQ(suite, plan[0].address.ttlSeconds, uint32_t(10));
   EXPECT_EQ(suite, ntohs(ipv4(plan[3]).sin_port), uint16_t(8443));
   EXPECT_EQ(suite, ntohs(ipv6(plan[4]).sin6_port), uint16_t(443));
   EXPECT_EQ(suite, ipv6(plan[4]).sin6_scope_id, uint32_t(8));
}

static void testAttemptTimingAndImmediateFailure(TestSuite& suite)
{
   Resolver::Result result = successful();
   result.addresses.push_back(address6("2001:db8::1", 443));
   result.addresses.push_back(address4("192.0.2.1", 443));
   result.addresses.push_back(address6("2001:db8::2", 443));

   HappyEyeballsPlan plan(result);
   auto cursor = plan.cursor();
   EXPECT_EQ(suite, cursor.remaining(), size_t(3));
   EXPECT_TRUE(suite, cursor.nextReady(std::chrono::milliseconds(0)) == &plan[0]);
   EXPECT_TRUE(suite, cursor.nextReady(std::chrono::milliseconds(249)) == nullptr);
   EXPECT_TRUE(suite, cursor.advanceAfterImmediateFailure(std::chrono::milliseconds(100)) == &plan[1]);
   EXPECT_TRUE(suite, cursor.nextReady(std::chrono::milliseconds(349)) == nullptr);
   EXPECT_TRUE(suite, cursor.nextReady(std::chrono::milliseconds(350)) == &plan[2]);
   EXPECT_TRUE(suite, cursor.advanceAfterImmediateFailure(std::chrono::milliseconds(350)) == nullptr);
   EXPECT_EQ(suite, cursor.remaining(), size_t(0));

   auto untouched = plan.cursor();
   EXPECT_TRUE(suite, untouched.advanceAfterImmediateFailure(std::chrono::milliseconds(0)) == nullptr);
   EXPECT_EQ(suite, untouched.remaining(), size_t(3));
}

static void testMaximumBound(TestSuite& suite)
{
   Resolver::Result result = successful();
   for (size_t index = 0; index < Resolver::maximumAnswers; ++index)
   {
      const uint32_t value = htonl(uint32_t(0xc0000200U + index));
      Resolver::Address address = address4("192.0.2.1", 443);
      std::memcpy(&reinterpret_cast<sockaddr_in *>(&address.storage)->sin_addr, &value, sizeof(value));
      result.addresses.push_back(address);
   }

   HappyEyeballsPlan plan(result);
   EXPECT_TRUE(suite, plan.valid());
   EXPECT_EQ(suite, plan.size(), Resolver::maximumAnswers);
   EXPECT_EQ(suite, plan[Resolver::maximumAnswers - 1].delay, std::chrono::milliseconds(250));
}

int main()
{
   TestSuite suite;
   testResultValidation(suite);
   testAlternatingResolverOrder(suite);
   testDuplicateIdentityAndEndpointPreservation(suite);
   testAttemptTimingAndImmediateFailure(suite);
   testMaximumBound(suite);
   return suite.finish("Happy Eyeballs attempt planner");
}
