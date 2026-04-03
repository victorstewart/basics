// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <arpa/inet.h>
#include <array>
#include <bitset>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "macros/bytes.h"

// These networking headers are not yet self-contained, so include the
// prerequisites explicitly in the order the current public surface expects.
#include "services/filesystem.h"
#include "services/numbers.h"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/private4.h"
#include "networking/socket.h"
#include "networking/msg.h"
#include "networking/message.h"
#include "networking/subnets.h"
#include "networking/arp.h"

namespace {

enum class PrimitiveTopic : uint16_t {
  first = 7,
  echo = 9,
  values = 11,
  table = 13,
};

static void testIpAddressAndPrefixHelpers(TestSuite& suite)
{
  IPAddress empty;
  EXPECT_TRUE(suite, empty.isNull());

  IPAddress ipv4("192.168.1.10", false);
  IPAddress ipv4Copy("192.168.1.10", false);
  EXPECT_FALSE(suite, ipv4.is6);
  EXPECT_TRUE(suite, ipv4.equals(ipv4Copy));
  EXPECT_EQ(suite, ipv4.hash(), ipv4Copy.hash());

  IPAddress mapped = ipv4.create4in6();
  EXPECT_TRUE(suite, mapped.is6);
  const std::array<uint8_t, 16> expectedMapped = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff,
      0xc0, 0xa8, 0x01, 0x0a};
  EXPECT_TRUE(suite, std::memcmp(mapped.v6, expectedMapped.data(), expectedMapped.size()) == 0);

  IPPrefix ipv4Prefix("192.168.1.129", false, 24);
  ipv4Prefix.canonicalize();
  EXPECT_EQ(suite, ipv4Prefix.hostBits(), uint8_t(8));
  EXPECT_EQ(suite, ipv4Prefix.network.v4, inet_addr("192.168.1.0"));
  EXPECT_TRUE(suite, ipv4Prefix.containsAddress(IPAddress("192.168.1.200", false)));
  EXPECT_FALSE(suite, ipv4Prefix.containsAddress(IPAddress("192.168.2.1", false)));

  IPPrefix zeroPrefix("0.0.0.0", false, 0);
  EXPECT_TRUE(suite, zeroPrefix.containsAddress(IPAddress("203.0.113.25", false)));
  EXPECT_FALSE(suite, zeroPrefix.containsAddress(IPAddress("2001:db8::1", true)));

  IPPrefix ipv6Prefix("2001:db8:abcd:12:3456:789a:bcde:f012", true, 64);
  IPPrefix canonicalIpv6 = ipv6Prefix.canonicalized();
  EXPECT_TRUE(suite, canonicalIpv6.network.is6);
  EXPECT_TRUE(suite, canonicalIpv6.containsAddress(IPAddress("2001:db8:abcd:12::1", true)));
  EXPECT_FALSE(suite, canonicalIpv6.containsAddress(IPAddress("2001:db8:abcd:13::1", true)));
  EXPECT_FALSE(suite, canonicalIpv6.containsAddress(IPAddress("192.168.1.1", false)));
  EXPECT_FALSE(suite, ipv4Prefix.containsAddress(IPAddress("2001:db8::1", true)));

  alignas(IPPrefix) std::array<uint8_t, sizeof(IPPrefix)> hashAStorage {};
  alignas(IPPrefix) std::array<uint8_t, sizeof(IPPrefix)> hashBStorage {};
  hashBStorage.fill(0xff);

  IPPrefix *hashA = std::construct_at(reinterpret_cast<IPPrefix *>(hashAStorage.data()));
  std::memset(hashA->network.v6, 0x00, sizeof(hashA->network.v6));
  hashA->network.v4 = inet_addr("10.1.2.0");
  hashA->network.is6 = false;
  hashA->cidr = 24;

  IPPrefix *hashB = std::construct_at(reinterpret_cast<IPPrefix *>(hashBStorage.data()));
  std::memset(hashB->network.v6, 0x00, sizeof(hashB->network.v6));
  hashB->network.v4 = inet_addr("10.1.2.0");
  hashB->network.is6 = false;
  hashB->cidr = 24;

  EXPECT_TRUE(suite, hashA->equals(*hashB));
  EXPECT_EQ(suite, hashA->hash(), hashB->hash());
  std::destroy_at(hashA);
  std::destroy_at(hashB);
}

static void testSubnetAndPrivateHelpers(TestSuite& suite)
{
  EXPECT_TRUE(suite, isRFC1918Private4(inet_addr("10.1.2.3")));
  EXPECT_TRUE(suite, isRFC1918Private4(inet_addr("172.16.5.4")));
  EXPECT_TRUE(suite, isRFC1918Private4(inet_addr("192.168.7.8")));
  EXPECT_FALSE(suite, isRFC1918Private4(inet_addr("8.8.8.8")));
  EXPECT_FALSE(suite, isRFC1918Private4(inet_addr("172.32.0.1")));

  constexpr uint128_t fixedBase = (uint128_t(0x20010db812345678ULL) << 64);
  Subnet6Pool<64, 1> pool;
  pool.setFixed(fixedBase);
  EXPECT_TRUE(suite, pool.getFixed() == fixedBase);
  EXPECT_EQ(suite, pool.count(), uint32_t(0));

  IPPrefix prefix = pool.getPrefix();
  EXPECT_TRUE(suite, prefix.network.is6);
  EXPECT_EQ(suite, prefix.cidr, uint8_t(65));
  EXPECT_EQ(suite, pool.count(), uint32_t(1));

  std::bitset<128> expectedBits = pool.fixed | (u128ToBitset(uint128_t(1)) << 63);
  IPAddress expectedNetwork(bitsetToU128(expectedBits));
  EXPECT_TRUE(suite, prefix.network.equals(expectedNetwork));

  constexpr uint128_t wrongFixedBase = (uint128_t(0x20010db812345679ULL) << 64);
  std::bitset<128> wrongBits = u128ToBitset(wrongFixedBase) | (u128ToBitset(uint128_t(1)) << 63);
  pool.relinquishSubnet(bitsetToU128(wrongBits));
  EXPECT_EQ(suite, pool.count(), uint32_t(1));

  pool.relinquishSubnet(bitsetToU128(expectedBits));
  EXPECT_EQ(suite, pool.count(), uint32_t(0));

  pool.recordFragment(1);
  EXPECT_EQ(suite, pool.count(), uint32_t(1));
}

static void testMsgHelpers(TestSuite& suite)
{
  msg<5, 32> packet;
  EXPECT_EQ(suite, packet.payloadLen(), uint32_t(0));
  EXPECT_EQ(suite, packet.addressLen(), uint32_t(0));
  EXPECT_EQ(suite, packet.payload() - packet.data, ptrdiff_t(16));

  packet.data[0] = 0xab;
  packet.setControlLen(5);
  packet.setPayloadLen(12);
  packet.setAddrLen(7);
  packet.reset();
  EXPECT_EQ(suite, packet.payloadLen(), uint32_t(0));
  EXPECT_EQ(suite, packet.addressLen(), uint32_t(0));
  EXPECT_EQ(suite, packet.data[0], uint8_t(0));

  packet.setAddrv6("2001:db8::1"_ctv, 443);
  EXPECT_EQ(suite, packet.addressLen(), uint32_t(sizeof(sockaddr_in6)));
  const sockaddr_in6 *addr6 = packet.address<sockaddr_in6>();
  EXPECT_EQ(suite, addr6->sin6_family, AF_INET6);
  EXPECT_EQ(suite, ntohs(addr6->sin6_port), uint16_t(443));

  char addressBuffer[INET6_ADDRSTRLEN] = {};
  EXPECT_TRUE(suite, inet_ntop(AF_INET6, &addr6->sin6_addr, addressBuffer, sizeof(addressBuffer)) != nullptr);
  EXPECT_EQ(suite, std::string(addressBuffer), std::string("2001:db8::1"));

  packet.prepareForRecv();
  EXPECT_EQ(suite, packet.addressLen(), uint32_t(sizeof(sockaddr_storage)));
  EXPECT_EQ(suite, packet.payloadLen(), uint32_t(32));
}

static void testMessageHelpers(TestSuite& suite)
{
  String messageBytes;
  Message::construct(messageBytes, PrimitiveTopic::first, uint32_t(0x11223344), "hello"_ctv, uint16_t(0x5566));

  Message *message = reinterpret_cast<Message *>(messageBytes.data());
  EXPECT_EQ(suite, message->topic, uint16_t(PrimitiveTopic::first));
  EXPECT_EQ(suite, message->headerSize, uint8_t(8));
  EXPECT_EQ(suite, message->size, uint32_t(messageBytes.size()));
  EXPECT_EQ(suite, message->size % 16, uint32_t(0));
  EXPECT_FALSE(suite, message->isEcho());

  uint8_t *cursor = message->args;
  uint32_t fixed32 = 0;
  Message::extractArg<ArgumentNature::fixed>(cursor, fixed32);
  EXPECT_EQ(suite, fixed32, uint32_t(0x11223344));

  String extractedView;
  Message::extractToStringView(cursor, extractedView);
  EXPECT_STRING_EQ(suite, extractedView, "hello"_ctv);

  uint16_t fixed16 = 0;
  Message::extractArg<ArgumentNature::fixed>(cursor, fixed16);
  EXPECT_EQ(suite, fixed16, uint16_t(0x5566));
  EXPECT_TRUE(suite, cursor == message->terminal());

  String echoBytes;
  Message::appendEcho(echoBytes, PrimitiveTopic::echo);
  Message *echo = reinterpret_cast<Message *>(echoBytes.data());
  EXPECT_TRUE(suite, echo->isEcho());
  EXPECT_EQ(suite, echo->payloadSize(), uint32_t(0));
  EXPECT_EQ(suite, Message::valueCounter(echo->args, echo->terminal()), uint32_t(0));
  uint8_t *emptyCursor = echo->args;
  uint32_t emptyVisits = 0;
  Message::valueHandler(emptyCursor, echo->terminal(), [&](uint8_t *, uint32_t) -> void {
    ++emptyVisits;
  });
  EXPECT_EQ(suite, emptyVisits, uint32_t(0));

  String shortLengthValue;
  Message::append<Alignment::two>(shortLengthValue, uint16_t(4));
  Message::append<Alignment::eight>(shortLengthValue, reinterpret_cast<const uint8_t *>("mini"), uint32_t(4));
  uint8_t *shortLengthCursor = shortLengthValue.data();
  String extractedShortLength;
  Message::extractToString<uint16_t>(shortLengthCursor, extractedShortLength);
  EXPECT_STRING_EQ(suite, extractedShortLength, "mini"_ctv);

  String valuesBytes;
  uint32_t valuesHeaderOffset = Message::appendHeader(valuesBytes, PrimitiveTopic::values);
  Message::appendValue(valuesBytes, reinterpret_cast<const uint8_t *>("a"), uint32_t(1));
  Message::appendValue(valuesBytes, reinterpret_cast<const uint8_t *>("bc"), uint32_t(2));
  Message::finish(valuesBytes, valuesHeaderOffset);

  Message *valuesMessage = reinterpret_cast<Message *>(valuesBytes.data());
  EXPECT_EQ(suite, Message::valueCounter(valuesMessage->args, valuesMessage->terminal()), uint32_t(2));

  std::vector<std::string> values;
  uint8_t *valueCursor = valuesMessage->args;
  Message::valueHandler(valueCursor, valuesMessage->terminal(), [&](uint8_t *value, uint32_t valueSize) -> void {
    values.emplace_back(reinterpret_cast<char *>(value), valueSize);
  });
  EXPECT_EQ(suite, values.size(), size_t(2));
  EXPECT_EQ(suite, values[0], std::string("a"));
  EXPECT_EQ(suite, values[1], std::string("bc"));

  bytell_hash_map<int, String> serializedPayload;
  serializedPayload.insert_or_assign(1, String("one"));
  serializedPayload.insert_or_assign(2, String("two"));

  String serializedMessageBytes;
  Message::constructSerialized(serializedMessageBytes, serializedPayload, PrimitiveTopic::values, uint32_t(0xabcdef01));

  Message *serializedMessage = reinterpret_cast<Message *>(serializedMessageBytes.data());
  EXPECT_EQ(suite, serializedMessage->topic, uint16_t(PrimitiveTopic::values));
  EXPECT_EQ(suite, serializedMessage->size, uint32_t(serializedMessageBytes.size()));

  uint8_t *serializedCursor = serializedMessage->args;
  uint32_t serializedTag = 0;
  Message::extractArg<ArgumentNature::fixed>(serializedCursor, serializedTag);
  EXPECT_EQ(suite, serializedTag, uint32_t(0xabcdef01));

  String serializedPayloadView;
  Message::extractToStringView(serializedCursor, serializedPayloadView);
  EXPECT_TRUE(suite, serializedCursor == serializedMessage->terminal());

  bytell_hash_map<int, String> decodedPayload;
  EXPECT_TRUE(suite, BitseryEngine::deserializeSafe(serializedPayloadView, decodedPayload));
  EXPECT_EQ(suite, decodedPayload.size(), serializedPayload.size());
  EXPECT_TRUE(suite, decodedPayload.contains(1));
  EXPECT_TRUE(suite, decodedPayload.contains(2));
  EXPECT_STRING_EQ(suite, decodedPayload.find(1)->second, "one"_ctv);
  EXPECT_STRING_EQ(suite, decodedPayload.find(2)->second, "two"_ctv);

  String tableBytes;
  uint32_t tableHeaderOffset = Message::appendHeader(tableBytes, PrimitiveTopic::table);
  Message::appendKey(tableBytes, reinterpret_cast<const uint8_t *>("alpha"), uint8_t(5));
  Message::appendValue(tableBytes, reinterpret_cast<const uint8_t *>("one"), uint32_t(3));
  Message::appendKey(tableBytes, reinterpret_cast<const uint8_t *>("beta"), uint8_t(4));
  Message::appendValue(tableBytes, reinterpret_cast<const uint8_t *>("two"), uint32_t(3));
  Message::finish(tableBytes, tableHeaderOffset);

  Message *tableMessage = reinterpret_cast<Message *>(tableBytes.data());
  std::vector<std::string> pairs;
  uint8_t *pairCursor = tableMessage->args;
  Message::keyValueHandler(pairCursor, tableMessage->terminal(), [&](uint8_t *key, uint8_t keySize, uint8_t *value, uint32_t valueSize) -> void {
    std::string entry(reinterpret_cast<char *>(key), keySize);
    entry.push_back('=');
    entry.append(reinterpret_cast<char *>(value), valueSize);
    pairs.push_back(entry);
  });
  EXPECT_EQ(suite, pairs.size(), size_t(2));
  EXPECT_EQ(suite, pairs[0], std::string("alpha=one"));
  EXPECT_EQ(suite, pairs[1], std::string("beta=two"));
}

static void testIpSocketAndArpHelpers(TestSuite& suite)
{
  IPSocket ipv4(AF_INET, SOCK_STREAM, 0, false);
  ipv4.setSaddr("0.0.0.0"_ctv, 9000);
  ipv4.setDaddr("127.0.0.1"_ctv, 8080);
  EXPECT_EQ(suite, ipv4.saddr<sockaddr_in>()->sin_family, AF_INET);
  EXPECT_EQ(suite, ntohs(ipv4.saddr<sockaddr_in>()->sin_port), uint16_t(9000));
  EXPECT_EQ(suite, ipv4.daddr4(), inet_addr("127.0.0.1"));
  EXPECT_EQ(suite, ipv4.dport(), uint16_t(8080));
  EXPECT_TRUE(suite, ipv4.daddrEqual(IPAddress("127.0.0.1", false)));

  ipv4.setDaddrFromURI("127.0.0.1", 1234);
  EXPECT_EQ(suite, ipv4.daddr4(), inet_addr("127.0.0.1"));
  EXPECT_EQ(suite, ipv4.dport(), uint16_t(1234));

  IPSocket ipv6(AF_INET6, SOCK_STREAM, 0, false);
  ipv6.setDaddr("2001:db8::1"_ctv, 8443);
  EXPECT_EQ(suite, ipv6.dport(), uint16_t(8443));
  EXPECT_TRUE(suite, ipv6.daddrEqual(IPAddress("2001:db8::1", true)));

  ARPSocket arp(false);
  arp.setInterfaceIndex(7);
  EXPECT_EQ(suite, arp.saddrLen, socklen_t(sizeof(sockaddr_ll)));
  EXPECT_EQ(suite, arp.saddr<sockaddr_ll>()->sll_family, AF_PACKET);
  EXPECT_EQ(suite, arp.saddr<sockaddr_ll>()->sll_ifindex, 7);

  ARPMessage request;
  const std::array<uint8_t, 6> ourMac = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02};
  const uint32_t gateway = inet_addr("192.168.1.1");
  const uint32_t local = inet_addr("192.168.1.10");
  ARPSocket::requestGatewayMAC(&request, 7, gateway, local, const_cast<uint8_t *>(ourMac.data()));

  EXPECT_EQ(suite, request.addressLen(), uint32_t(sizeof(sockaddr_ll)));
  EXPECT_EQ(suite, request.payloadLen(), uint32_t(14 + 28));

  const sockaddr_ll *linkAddress = request.address<sockaddr_ll>();
  EXPECT_EQ(suite, linkAddress->sll_family, AF_PACKET);
  EXPECT_EQ(suite, linkAddress->sll_ifindex, 7);
  EXPECT_EQ(suite, ntohs(linkAddress->sll_protocol), uint16_t(ETH_P_ARP));
  EXPECT_TRUE(suite, std::memcmp(linkAddress->sll_addr, ourMac.data(), ourMac.size()) == 0);

  const ethhdr *ethHeader = reinterpret_cast<const ethhdr *>(request.payload());
  EXPECT_TRUE(suite, std::memcmp(ethHeader->h_dest, "\xff\xff\xff\xff\xff\xff", 6) == 0);
  EXPECT_TRUE(suite, std::memcmp(ethHeader->h_source, ourMac.data(), ourMac.size()) == 0);
  EXPECT_EQ(suite, ntohs(ethHeader->h_proto), uint16_t(ETH_P_ARP));

  const uint8_t *arpBytes = request.payload() + 14;
  EXPECT_EQ(suite, ntohs(*reinterpret_cast<const uint16_t *>(arpBytes + 0)), uint16_t(1));
  EXPECT_EQ(suite, ntohs(*reinterpret_cast<const uint16_t *>(arpBytes + 2)), uint16_t(ETH_P_IP));
  EXPECT_EQ(suite, arpBytes[4], uint8_t(6));
  EXPECT_EQ(suite, arpBytes[5], uint8_t(4));
  EXPECT_EQ(suite, ntohs(*reinterpret_cast<const uint16_t *>(arpBytes + 6)), uint16_t(1));
  EXPECT_TRUE(suite, std::memcmp(arpBytes + 8, ourMac.data(), ourMac.size()) == 0);
  EXPECT_TRUE(suite, std::memcmp(arpBytes + 14, &local, sizeof(local)) == 0);
  EXPECT_TRUE(suite, std::memcmp(arpBytes + 24, &gateway, sizeof(gateway)) == 0);

  sockaddr_ll responseAddress = {};
  std::array<uint8_t, 64> responsePayload {};
  iovec responseIov = {
      .iov_base = responsePayload.data(),
      .iov_len = responsePayload.size(),
  };
  msghdr responseHeader = {
      .msg_name = &responseAddress,
      .msg_namelen = sizeof(responseAddress),
      .msg_iov = &responseIov,
      .msg_iovlen = 1,
      .msg_control = nullptr,
      .msg_controllen = 0,
      .msg_flags = 0,
  };

  ethhdr *responseEth = reinterpret_cast<ethhdr *>(responsePayload.data());
  responseEth->h_proto = htons(ETH_P_ARP);
  uint8_t *responseArp = responsePayload.data() + 14;
  *reinterpret_cast<uint16_t *>(responseArp + 6) = htons(2);
  const std::array<uint8_t, 6> gatewayMac = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
  std::memcpy(responseArp + 8, gatewayMac.data(), gatewayMac.size());

  std::array<uint8_t, 6> extractedGatewayMac {};
  EXPECT_FALSE(suite, ARPSocket::receivedMessage(&responseHeader, 8, extractedGatewayMac.data()));
  EXPECT_TRUE(suite, ARPSocket::receivedMessage(&responseHeader, 42, extractedGatewayMac.data()));
  EXPECT_TRUE(suite, extractedGatewayMac == gatewayMac);

  responseEth->h_proto = htons(ETH_P_IP);
  EXPECT_FALSE(suite, ARPSocket::receivedMessage(&responseHeader, 42, extractedGatewayMac.data()));
  responseEth->h_proto = htons(ETH_P_ARP);
  *reinterpret_cast<uint16_t *>(responseArp + 6) = htons(1);
  EXPECT_FALSE(suite, ARPSocket::receivedMessage(&responseHeader, 42, extractedGatewayMac.data()));
}

} // namespace

int main()
{
  TestSuite suite;

  testIpAddressAndPrefixHelpers(suite);
  testSubnetAndPrivateHelpers(suite);
  testMsgHelpers(suite);
  testMessageHelpers(suite);
  testIpSocketAndArpHelpers(suite);

  return suite.finish("networking primitive tests");
}
