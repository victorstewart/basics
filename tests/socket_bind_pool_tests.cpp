// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <networking/socket.bind.pool.h>

namespace {

struct TestClock
{
   LocalSocketBindPool::TimePoint now = {};

   static LocalSocketBindPool::TimePoint read(void *context)
   {
      return static_cast<TestClock *>(context)->now;
   }
};

static sockaddr_in loopback(uint16_t port)
{
   sockaddr_in address = {};
   address.sin_family = AF_INET;
   address.sin_port = htons(port);
   address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   return address;
}

struct ReservedTcpPorts
{
   uint16_t first = 0;
   uint16_t second = 0;
};

static ReservedTcpPorts reserveTcpPorts(void)
{
   int descriptors[2] = {socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0),
                         socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
   ReservedTcpPorts result;
   uint16_t *ports[2] = {&result.first, &result.second};
   for (size_t index = 0; index < 2 && descriptors[index] >= 0; ++index)
   {
      sockaddr_in address = loopback(0);
      socklen_t length = sizeof(address);
      if (bind(descriptors[index], reinterpret_cast<const sockaddr *>(&address), length) == 0 &&
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

static uint16_t reserveTcpPort(void)
{
   return reserveTcpPorts().first;
}

static LocalSocketBindSet oneEndpoint(uint16_t port)
{
   LocalSocketBindSet binds;
   const sockaddr_in local = loopback(port);
   binds.add(reinterpret_cast<const sockaddr *>(&local), sizeof(local));
   return binds;
}

static void testSetContract(TestSuite& suite)
{
   LocalSocketBindSet binds;
   const sockaddr_in local4 = loopback(41001);
   sockaddr_in6 local6 = {};
   local6.sin6_family = AF_INET6;
   local6.sin6_port = htons(41002);
   local6.sin6_addr = in6addr_loopback;
   EXPECT_TRUE(suite, binds.add(reinterpret_cast<const sockaddr *>(&local4), sizeof(local4)));
   EXPECT_FALSE(suite, binds.add(reinterpret_cast<const sockaddr *>(&local4), sizeof(local4)));
   EXPECT_TRUE(suite, binds.add(reinterpret_cast<const sockaddr *>(&local6), sizeof(local6), true));
   EXPECT_EQ(suite, binds.count(AF_INET), size_t(1));
   EXPECT_EQ(suite, binds.count(AF_INET6), size_t(1));
   EXPECT_TRUE(suite, binds.at(AF_INET6, 0)->freebind);
   EXPECT_TRUE(suite, binds.containsLocal(reinterpret_cast<const sockaddr *>(&local4), sizeof(local4)));
}

static void testTupleCapacityAndProtocolReuse(TestSuite& suite)
{
   const ReservedTcpPorts ports = reserveTcpPorts();
   const uint16_t firstPort = ports.first;
   const uint16_t secondPort = ports.second;
   EXPECT_TRUE(suite, firstPort != 0 && secondPort != 0 && firstPort != secondPort);
   LocalSocketBindSet binds = oneEndpoint(firstPort);
   const sockaddr_in second = loopback(secondPort);
   EXPECT_TRUE(suite, binds.add(reinterpret_cast<const sockaddr *>(&second), sizeof(second)));
   LocalSocketBindPool pool(std::move(binds));
   const sockaddr_in remote = loopback(443);
   const int first = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   const int secondFd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   const int exhausted = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, bool(pool.acquireAndBind(first,
                                         reinterpret_cast<const sockaddr *>(&remote),
                                         sizeof(remote),
                                         SOCK_STREAM)));
   EXPECT_TRUE(suite, bool(pool.acquireAndBind(secondFd,
                                         reinterpret_cast<const sockaddr *>(&remote),
                                         sizeof(remote),
                                         SOCK_STREAM)));
   const auto third = pool.acquireAndBind(exhausted,
                                          reinterpret_cast<const sockaddr *>(&remote),
                                          sizeof(remote),
                                          SOCK_STREAM);
   EXPECT_TRUE(suite, third.status == LocalSocketBindPool::AcquireStatus::exhausted);
   EXPECT_EQ(suite, pool.activeLeaseCount(), size_t(2));
   pool.release(first);
   pool.release(secondFd);
   close(first);
   close(secondFd);
   close(exhausted);
   EXPECT_TRUE(suite, pool.drained());
}

static void testRemoteTupleConcurrencyAndFdReuse(TestSuite& suite)
{
   const uint16_t port = reserveTcpPort();
   LocalSocketBindPool pool(oneEndpoint(port));
   const sockaddr_in firstRemote = loopback(443);
   const sockaddr_in secondRemote = loopback(8443);
   const int first = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   const int second = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, bool(pool.acquireAndBind(first,
                                              reinterpret_cast<const sockaddr *>(&firstRemote),
                                              sizeof(firstRemote),
                                              SOCK_STREAM)));
   EXPECT_TRUE(suite, bool(pool.acquireAndBind(second,
                                              reinterpret_cast<const sockaddr *>(&secondRemote),
                                              sizeof(secondRemote),
                                              SOCK_STREAM)));
   pool.release(first);
   pool.release(second);
   close(first);
   close(second);

   LocalSocketBindPool udpPool(oneEndpoint(port));
   int reused = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
   const int releasedNumber = reused;
   EXPECT_TRUE(suite, bool(udpPool.acquireAndBind(reused,
                                                 reinterpret_cast<const sockaddr *>(&firstRemote),
                                                 sizeof(firstRemote),
                                                 SOCK_DGRAM)));
   udpPool.release(reused);
   close(reused);
   reused = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
   if (reused != releasedNumber)
   {
      EXPECT_TRUE(suite, dup2(reused, releasedNumber) == releasedNumber);
      close(reused);
      reused = releasedNumber;
   }
   EXPECT_TRUE(suite, bool(udpPool.acquireAndBind(reused,
                                                 reinterpret_cast<const sockaddr *>(&secondRemote),
                                                 sizeof(secondRemote),
                                                 SOCK_DGRAM)));
   udpPool.release(reused);
   close(reused);
}

static void testTcpQuarantineAndUdpReuse(TestSuite& suite)
{
   const uint16_t port = reserveTcpPort();
   TestClock clock;
   LocalSocketBindPool pool(oneEndpoint(port), {&clock, TestClock::read});
   const sockaddr_in remote = loopback(53);
   int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, bool(pool.acquireAndBind(fd,
                                         reinterpret_cast<const sockaddr *>(&remote),
                                         sizeof(remote),
                                         SOCK_STREAM)));
   EXPECT_TRUE(suite, pool.release(fd));
   close(fd);
   fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, pool.acquireAndBind(fd,
                                         reinterpret_cast<const sockaddr *>(&remote),
                                         sizeof(remote),
                                         SOCK_STREAM).status ==
                          LocalSocketBindPool::AcquireStatus::exhausted);
   clock.now += LocalSocketBindPool::tcpQuarantineDuration;
   EXPECT_TRUE(suite, bool(pool.acquireAndBind(fd,
                                         reinterpret_cast<const sockaddr *>(&remote),
                                         sizeof(remote),
                                         SOCK_STREAM)));
   pool.release(fd);
   close(fd);

   LocalSocketBindPool udpPool(oneEndpoint(port));
   fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, bool(udpPool.acquireAndBind(fd,
                                            reinterpret_cast<const sockaddr *>(&remote),
                                            sizeof(remote),
                                            SOCK_DGRAM)));
   udpPool.release(fd);
   close(fd);
   fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, bool(udpPool.acquireAndBind(fd,
                                            reinterpret_cast<const sockaddr *>(&remote),
                                            sizeof(remote),
                                            SOCK_DGRAM)));
   udpPool.release(fd);
   close(fd);
}

static void testBoundedTcpQuarantine(TestSuite& suite)
{
   LocalSocketBindPool pool(oneEndpoint(reserveTcpPort()));
   for (size_t index = 0; index < LocalSocketBindPool::maximumTcpQuarantines; ++index)
   {
      const sockaddr_in remote = loopback(uint16_t(10000 + index));
      const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      EXPECT_TRUE(suite, bool(pool.acquireAndBind(fd,
                                            reinterpret_cast<const sockaddr *>(&remote),
                                            sizeof(remote),
                                            SOCK_STREAM)));
      EXPECT_TRUE(suite, pool.release(fd));
      close(fd);
   }
   const sockaddr_in remote = loopback(20000);
   const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
   EXPECT_TRUE(suite, pool.acquireAndBind(fd,
                                         reinterpret_cast<const sockaddr *>(&remote),
                                         sizeof(remote),
                                         SOCK_STREAM).status ==
                          LocalSocketBindPool::AcquireStatus::exhausted);
   close(fd);
}

} // namespace

int main()
{
   TestSuite suite;
   testSetContract(suite);
   testTupleCapacityAndProtocolReuse(suite);
   testRemoteTupleConcurrencyAndFdReuse(suite);
   testTcpQuarantineAndUdpReuse(suite);
   testBoundedTcpQuarantine(suite);
   return suite.finish("Local socket bind pool");
}
