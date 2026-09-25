// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <chrono>
#include <iostream>
#include <thread>
#include <linux/if_link.h>
#include <linux/net_namespace.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "macros/bytes.h"

// These networking headers are not yet self-contained, so include the
// prerequisites explicitly in the order the current public surface expects.
#include "base/flat_hash_map.hpp"
#include "base/bytell_hash_map.hpp"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/msg.h"
#include "networking/pool.h"
#include "services/filesystem.h"
#include "networking/netlink.h"
#include "networking/veth.h"
#include "networking/netkit.h"
#include "networking/guardian.h"

namespace {

static struct nlmsghdr *headerOf(NetlinkMessage& message)
{
  return reinterpret_cast<struct nlmsghdr *>(message.payload());
}

static const struct rtattr *findRtAttr(const void *data, int len, int type)
{
  const struct rtattr *attr = reinterpret_cast<const struct rtattr *>(data);
  int remaining = len;

  while (RTA_OK(attr, remaining))
  {
    if ((attr->rta_type & NLA_TYPE_MASK) == type)
    {
      return attr;
    }

    attr = RTA_NEXT(attr, remaining);
  }

  return nullptr;
}

static const struct nlattr *findNlAttr(NetlinkSocket& socket, const void *data, int len, int type)
{
  const struct nlattr *attr = reinterpret_cast<const struct nlattr *>(data);
  int remaining = len;

  while (socket.nla_ok(attr, remaining))
  {
    if ((attr->nla_type & NLA_TYPE_MASK) == type)
    {
      return attr;
    }

    attr = socket.nla_next(attr, &remaining);
  }

  return nullptr;
}

static std::string_view rtAttrString(const struct rtattr *attr)
{
  const char *data = reinterpret_cast<const char *>(RTA_DATA(attr));
  return std::string_view(data, std::strlen(data));
}

static std::string_view nlAttrString(NetlinkSocket& socket, const struct nlattr *attr)
{
  const char *data = reinterpret_cast<const char *>(socket.nla_data(attr));
  size_t size = attr->nla_len > NLA_HDRLEN ? size_t(attr->nla_len - NLA_HDRLEN) : size_t(0);
  return std::string_view(data, ::strnlen(data, size));
}

static struct nlmsghdr *appendFrame(NetlinkMessage& message, uint16_t type, uint16_t flags, uint32_t seq, const void *payload, uint32_t payloadLen)
{
  uint32_t offset = message.payloadLen();
  uint8_t *cursor = message.payload() + offset;
  auto *header = reinterpret_cast<struct nlmsghdr *>(cursor);

  header->nlmsg_len = NLMSG_LENGTH(payloadLen);
  header->nlmsg_type = type;
  header->nlmsg_flags = flags;
  header->nlmsg_seq = seq;
  header->nlmsg_pid = 0;

  if (payloadLen > 0)
  {
    std::memcpy(NLMSG_DATA(header), payload, payloadLen);
  }

  uint32_t alignedLen = NLMSG_ALIGN(header->nlmsg_len);
  std::memset(cursor + header->nlmsg_len, 0, alignedLen - header->nlmsg_len);
  message.setPayloadLen(offset + alignedLen);

  return header;
}

static void testLookupAndUpdateRequestBuilders(TestSuite& suite)
{
  NetlinkSocket socket;

  NetlinkMessage getInterfaceRequest;
  socket.getInterface(&getInterfaceRequest, 7, "demo0"_ctv);

  struct nlmsghdr *getInterfaceHeader = headerOf(getInterfaceRequest);
  EXPECT_EQ(suite, getInterfaceHeader->nlmsg_type, uint16_t(RTM_GETLINK));
  EXPECT_EQ(suite, getInterfaceHeader->nlmsg_flags, uint16_t(NLM_F_REQUEST));
  EXPECT_EQ(suite, getInterfaceHeader->nlmsg_seq, uint32_t(7));

  auto *getInterfaceInfo = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(getInterfaceHeader));
  EXPECT_EQ(suite, getInterfaceInfo->ifi_family, uint8_t(AF_UNSPEC));

  const struct rtattr *ifnameAttr = findRtAttr(IFLA_RTA(getInterfaceInfo),
                                               int(getInterfaceHeader->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg))),
                                               IFLA_IFNAME);
  EXPECT_TRUE(suite, ifnameAttr != nullptr);
  if (ifnameAttr != nullptr)
  {
    EXPECT_EQ(suite, rtAttrString(ifnameAttr), std::string_view("demo0"));
  }

  NetlinkMessage moveRequest;
  int netnsfd = 42;
  socket.moveInterfaceToNamespace(&moveRequest, 9, "demo0"_ctv, netnsfd);

  struct nlmsghdr *moveHeader = headerOf(moveRequest);
  EXPECT_EQ(suite, moveHeader->nlmsg_type, uint16_t(RTM_SETLINK));
  EXPECT_EQ(suite, moveHeader->nlmsg_flags, uint16_t(NLM_F_REQUEST | NLM_F_ACK));
  EXPECT_EQ(suite, moveHeader->nlmsg_seq, uint32_t(9));

  auto *moveInfo = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(moveHeader));
  const int moveAttrLen = int(moveHeader->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));
  const struct rtattr *moveNameAttr = findRtAttr(IFLA_RTA(moveInfo), moveAttrLen, IFLA_IFNAME);
  const struct rtattr *moveNetnsAttr = findRtAttr(IFLA_RTA(moveInfo), moveAttrLen, IFLA_NET_NS_FD);
  EXPECT_TRUE(suite, moveNameAttr != nullptr);
  EXPECT_TRUE(suite, moveNetnsAttr != nullptr);
  if (moveNameAttr != nullptr)
  {
    EXPECT_EQ(suite, rtAttrString(moveNameAttr), std::string_view("demo0"));
  }
  if (moveNetnsAttr != nullptr)
  {
    EXPECT_EQ(suite, *reinterpret_cast<const int *>(RTA_DATA(moveNetnsAttr)), netnsfd);
  }

  NetlinkMessage bringUpRequest;
  socket.bringUpInterface(&bringUpRequest, 11, 27);

  struct nlmsghdr *bringUpHeader = headerOf(bringUpRequest);
  EXPECT_EQ(suite, bringUpHeader->nlmsg_type, uint16_t(RTM_NEWLINK));
  EXPECT_EQ(suite, bringUpHeader->nlmsg_flags, uint16_t(NLM_F_REQUEST | NLM_F_ACK));
  auto *bringUpInfo = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(bringUpHeader));
  EXPECT_EQ(suite, bringUpInfo->ifi_index, int(27));
  EXPECT_EQ(suite, bringUpInfo->ifi_flags, unsigned(IFF_UP));
  EXPECT_EQ(suite, bringUpInfo->ifi_change, unsigned(IFF_UP));
}

static void testRouteRequestBuilders(TestSuite& suite)
{
  NetlinkSocket socket;

  NetlinkMessage ipv4DirectRequest;
  IPPrefix ipv4Subnet("10.123.45.0", false, 24);
  IPAddress nullGateway;
  IPAddress nullPrefsrc;
  socket.addRoute(&ipv4DirectRequest, 13, 5, ipv4Subnet, nullGateway, nullPrefsrc);

  struct nlmsghdr *ipv4Header = headerOf(ipv4DirectRequest);
  auto *ipv4Route = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(ipv4Header));
  EXPECT_EQ(suite, ipv4Header->nlmsg_type, uint16_t(RTM_NEWROUTE));
  EXPECT_EQ(suite, ipv4Route->rtm_family, uint8_t(AF_INET));
  EXPECT_EQ(suite, ipv4Route->rtm_scope, uint8_t(RT_SCOPE_LINK));
  EXPECT_EQ(suite, ipv4Route->rtm_dst_len, uint8_t(24));

  int ipv4AttrLen = int(ipv4Header->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
  const struct rtattr *ipv4DstAttr = findRtAttr(RTM_RTA(ipv4Route), ipv4AttrLen, RTA_DST);
  const struct rtattr *ipv4GatewayAttr = findRtAttr(RTM_RTA(ipv4Route), ipv4AttrLen, RTA_GATEWAY);
  const struct rtattr *ipv4OifAttr = findRtAttr(RTM_RTA(ipv4Route), ipv4AttrLen, RTA_OIF);
  EXPECT_TRUE(suite, ipv4DstAttr != nullptr);
  EXPECT_TRUE(suite, ipv4GatewayAttr == nullptr);
  EXPECT_TRUE(suite, ipv4OifAttr != nullptr);
  if (ipv4OifAttr != nullptr)
  {
    EXPECT_EQ(suite, *reinterpret_cast<const int *>(RTA_DATA(ipv4OifAttr)), 5);
  }

  NetlinkMessage ipv6DirectRequest;
  IPPrefix ipv6Subnet("fd00::", true, 64);
  socket.addRoute(&ipv6DirectRequest, 15, 6, ipv6Subnet, nullGateway, nullPrefsrc);

  struct nlmsghdr *ipv6Header = headerOf(ipv6DirectRequest);
  auto *ipv6Route = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(ipv6Header));
  EXPECT_EQ(suite, ipv6Route->rtm_family, uint8_t(AF_INET6));
  EXPECT_EQ(suite, ipv6Route->rtm_scope, uint8_t(RT_SCOPE_UNIVERSE));

  NetlinkMessage gatewayRequest;
  IPAddress gateway("10.123.45.1", false);
  IPAddress prefsrc("10.123.45.2", false);
  socket.addRoute(&gatewayRequest, 17, 7, ipv4Subnet, gateway, prefsrc);

  struct nlmsghdr *gatewayHeader = headerOf(gatewayRequest);
  auto *gatewayRoute = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(gatewayHeader));
  EXPECT_EQ(suite, gatewayRoute->rtm_scope, uint8_t(RT_SCOPE_UNIVERSE));

  int gatewayAttrLen = int(gatewayHeader->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
  const struct rtattr *gatewayAttr = findRtAttr(RTM_RTA(gatewayRoute), gatewayAttrLen, RTA_GATEWAY);
  const struct rtattr *prefsrcAttr = findRtAttr(RTM_RTA(gatewayRoute), gatewayAttrLen, RTA_PREFSRC);
  EXPECT_TRUE(suite, gatewayAttr != nullptr);
  EXPECT_TRUE(suite, prefsrcAttr != nullptr);
  if (gatewayAttr != nullptr)
  {
    EXPECT_EQ(suite, *reinterpret_cast<const uint32_t *>(RTA_DATA(gatewayAttr)), gateway.v4);
  }
  if (prefsrcAttr != nullptr)
  {
    EXPECT_EQ(suite, *reinterpret_cast<const uint32_t *>(RTA_DATA(prefsrcAttr)), prefsrc.v4);
  }
}

static void testLinkCreationBuilders(TestSuite& suite)
{
  NetlinkSocket socket;

  NetlinkMessage vethRequest;
  socket.createVethPair(&vethRequest, 19, "host0"_ctv, "peer0"_ctv, 1234);

  struct nlmsghdr *vethHeader = headerOf(vethRequest);
  EXPECT_EQ(suite, vethHeader->nlmsg_type, uint16_t(RTM_NEWLINK));
  EXPECT_EQ(suite, vethHeader->nlmsg_flags, uint16_t(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK));

  auto *vethInfo = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(vethHeader));
  int vethAttrLen = int(vethHeader->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));
  const struct rtattr *hostNameAttr = findRtAttr(IFLA_RTA(vethInfo), vethAttrLen, IFLA_IFNAME);
  const struct rtattr *linkInfoAttr = findRtAttr(IFLA_RTA(vethInfo), vethAttrLen, IFLA_LINKINFO);
  EXPECT_TRUE(suite, hostNameAttr != nullptr);
  EXPECT_TRUE(suite, linkInfoAttr != nullptr);
  if (hostNameAttr != nullptr)
  {
    EXPECT_EQ(suite, rtAttrString(hostNameAttr), std::string_view("host0"));
  }
  if (linkInfoAttr != nullptr)
  {
    const void *linkInfoPayload = RTA_DATA(linkInfoAttr);
    int linkInfoPayloadLen = int(RTA_PAYLOAD(linkInfoAttr));
    const struct nlattr *kindAttr = findNlAttr(socket, linkInfoPayload, linkInfoPayloadLen, IFLA_INFO_KIND);
    const struct nlattr *infoDataAttr = findNlAttr(socket, linkInfoPayload, linkInfoPayloadLen, IFLA_INFO_DATA);
    EXPECT_TRUE(suite, kindAttr != nullptr);
    EXPECT_TRUE(suite, infoDataAttr != nullptr);
    if (kindAttr != nullptr)
    {
      EXPECT_EQ(suite, nlAttrString(socket, kindAttr), std::string_view("veth"));
    }
    if (infoDataAttr != nullptr)
    {
      const void *infoDataPayload = socket.nla_data(infoDataAttr);
      int infoDataPayloadLen = int(infoDataAttr->nla_len - NLA_HDRLEN);
      const struct nlattr *peerAttr = findNlAttr(socket, infoDataPayload, infoDataPayloadLen, VETH_INFO_PEER);
      EXPECT_TRUE(suite, peerAttr != nullptr);
      if (peerAttr != nullptr)
      {
        const uint8_t *peerPayload = reinterpret_cast<const uint8_t *>(socket.nla_data(peerAttr));
        auto *peerInfo = reinterpret_cast<const struct ifinfomsg *>(peerPayload);
        EXPECT_EQ(suite, peerInfo->ifi_family, uint8_t(AF_UNSPEC));

        int peerAttrLen = int(peerAttr->nla_len - NLA_HDRLEN - NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        const void *peerAttrPayload = peerPayload + NLMSG_ALIGN(sizeof(struct ifinfomsg));
        const struct nlattr *peerNameAttr = findNlAttr(socket, peerAttrPayload, peerAttrLen, IFLA_IFNAME);
        const struct nlattr *peerNetnsAttr = findNlAttr(socket, peerAttrPayload, peerAttrLen, IFLA_NET_NS_PID);
        EXPECT_TRUE(suite, peerNameAttr != nullptr);
        EXPECT_TRUE(suite, peerNetnsAttr != nullptr);
        if (peerNameAttr != nullptr)
        {
          EXPECT_EQ(suite, nlAttrString(socket, peerNameAttr), std::string_view("peer0"));
        }
        if (peerNetnsAttr != nullptr)
        {
          EXPECT_EQ(suite, *reinterpret_cast<const int *>(socket.nla_data(peerNetnsAttr)), 1234);
        }
      }
    }
  }

  NetlinkMessage netkitRequest;
  socket.createNetkitPair(&netkitRequest,
                          21,
                          NETKIT_L3,
                          "kit0"_ctv,
                          "kit1"_ctv,
                          5678,
                          NETKIT_SCRUB_NONE,
                          NETKIT_SCRUB_NONE);

  struct nlmsghdr *netkitHeader = headerOf(netkitRequest);
  EXPECT_EQ(suite, netkitHeader->nlmsg_type, uint16_t(RTM_NEWLINK));
  EXPECT_EQ(suite, netkitHeader->nlmsg_flags, uint16_t(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK));

  auto *netkitInfo = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(netkitHeader));
  int netkitAttrLen = int(netkitHeader->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));
  const struct rtattr *netkitLinkInfoAttr = findRtAttr(IFLA_RTA(netkitInfo), netkitAttrLen, IFLA_LINKINFO);
  EXPECT_TRUE(suite, netkitLinkInfoAttr != nullptr);
  if (netkitLinkInfoAttr != nullptr)
  {
    const void *netkitPayload = RTA_DATA(netkitLinkInfoAttr);
    int netkitPayloadLen = int(RTA_PAYLOAD(netkitLinkInfoAttr));
    const struct nlattr *kindAttr = findNlAttr(socket, netkitPayload, netkitPayloadLen, IFLA_INFO_KIND);
    const struct nlattr *infoDataAttr = findNlAttr(socket, netkitPayload, netkitPayloadLen, IFLA_INFO_DATA);
    EXPECT_TRUE(suite, kindAttr != nullptr);
    EXPECT_TRUE(suite, infoDataAttr != nullptr);
    if (kindAttr != nullptr)
    {
      EXPECT_EQ(suite, nlAttrString(socket, kindAttr), std::string_view("netkit"));
    }
    if (infoDataAttr != nullptr)
    {
      const void *infoDataPayload = socket.nla_data(infoDataAttr);
      int infoDataPayloadLen = int(infoDataAttr->nla_len - NLA_HDRLEN);
      const struct nlattr *modeAttr = findNlAttr(socket, infoDataPayload, infoDataPayloadLen, IFLA_NETKIT_MODE);
      const struct nlattr *scrubAttr = findNlAttr(socket, infoDataPayload, infoDataPayloadLen, IFLA_NETKIT_SCRUB);
      const struct nlattr *peerScrubAttr = findNlAttr(socket, infoDataPayload, infoDataPayloadLen, IFLA_NETKIT_PEER_SCRUB);
      const struct nlattr *peerInfoAttr = findNlAttr(socket, infoDataPayload, infoDataPayloadLen, IFLA_NETKIT_PEER_INFO);
      EXPECT_TRUE(suite, modeAttr != nullptr);
      EXPECT_TRUE(suite, scrubAttr != nullptr);
      EXPECT_TRUE(suite, peerScrubAttr != nullptr);
      EXPECT_TRUE(suite, peerInfoAttr != nullptr);
      if (modeAttr != nullptr)
      {
        EXPECT_EQ(suite, *reinterpret_cast<const uint32_t *>(socket.nla_data(modeAttr)), uint32_t(NETKIT_L3));
      }
      if (scrubAttr != nullptr)
      {
        EXPECT_EQ(suite, *reinterpret_cast<const uint32_t *>(socket.nla_data(scrubAttr)), uint32_t(NETKIT_SCRUB_NONE));
      }
      if (peerScrubAttr != nullptr)
      {
        EXPECT_EQ(suite, *reinterpret_cast<const uint32_t *>(socket.nla_data(peerScrubAttr)), uint32_t(NETKIT_SCRUB_NONE));
      }
      if (peerInfoAttr != nullptr)
      {
        const uint8_t *peerPayload = reinterpret_cast<const uint8_t *>(socket.nla_data(peerInfoAttr));
        int peerAttrLen = int(peerInfoAttr->nla_len - NLA_HDRLEN - NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        const void *peerAttrPayload = peerPayload + NLMSG_ALIGN(sizeof(struct ifinfomsg));
        const struct nlattr *peerNameAttr = findNlAttr(socket, peerAttrPayload, peerAttrLen, IFLA_IFNAME);
        const struct nlattr *peerNetnsAttr = findNlAttr(socket, peerAttrPayload, peerAttrLen, IFLA_NET_NS_PID);
        EXPECT_TRUE(suite, peerNameAttr != nullptr);
        EXPECT_TRUE(suite, peerNetnsAttr != nullptr);
        if (peerNameAttr != nullptr)
        {
          EXPECT_EQ(suite, nlAttrString(socket, peerNameAttr), std::string_view("kit1"));
        }
        if (peerNetnsAttr != nullptr)
        {
          EXPECT_EQ(suite, *reinterpret_cast<const int *>(socket.nla_data(peerNetnsAttr)), 5678);
        }
      }
    }
  }
}

static void testHandleMessageParsing(TestSuite& suite)
{
  NetlinkSocket socket;

  NetlinkMessage ackMessage;
  struct nlmsgerr ack = {};
  appendFrame(ackMessage, NLMSG_ERROR, 0, 31, &ack, sizeof(ack));

  uint32_t ackOffset = 0;
  uint32_t ackRetrySeq = UINT32_MAX;
  int ackCalls = 0;
  socket.handleMessage(reinterpret_cast<struct msghdr *>(&ackMessage), ackOffset, ackRetrySeq,
                       [&](uint16_t nlmsgType, uint32_t nlmsgSeq, void *nlmsgData, uint32_t nlmsgLen) -> void {
                         ++ackCalls;
                         EXPECT_EQ(suite, nlmsgType, uint16_t(NLMSG_ERROR));
                         EXPECT_EQ(suite, nlmsgSeq, uint32_t(31));
                         EXPECT_TRUE(suite, nlmsgData == nullptr);
                         EXPECT_EQ(suite, nlmsgLen, uint32_t(NLMSG_LENGTH(sizeof(struct nlmsgerr))));
                       });
  EXPECT_EQ(suite, ackCalls, 1);
  EXPECT_EQ(suite, ackRetrySeq, uint32_t(UINT32_MAX));
  EXPECT_EQ(suite, ackOffset, uint32_t(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nlmsgerr)))));

  NetlinkMessage errorMessage;
  struct nlmsgerr error = {};
  error.error = -EPERM;
  appendFrame(errorMessage, NLMSG_ERROR, 0, 33, &error, sizeof(error));

  uint32_t errorOffset = 0;
  uint32_t errorRetrySeq = UINT32_MAX;
  int errorCalls = 0;
  socket.handleMessage(reinterpret_cast<struct msghdr *>(&errorMessage), errorOffset, errorRetrySeq,
                       [&](uint16_t, uint32_t, void *, uint32_t) -> void {
                         ++errorCalls;
                       });
  EXPECT_EQ(suite, errorCalls, 0);
  EXPECT_EQ(suite, errorRetrySeq, uint32_t(33));
  EXPECT_EQ(suite, errorOffset, uint32_t(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nlmsgerr)))));

  NetlinkMessage multipartMessage;
  struct ifinfomsg ifinfo = {};
  ifinfo.ifi_index = 99;
  appendFrame(multipartMessage, RTM_NEWLINK, NLM_F_MULTI, 35, &ifinfo, sizeof(ifinfo));
  appendFrame(multipartMessage, NLMSG_DONE, NLM_F_MULTI, 35, nullptr, 0);

  uint32_t multipartOffset = 0;
  uint32_t multipartRetrySeq = UINT32_MAX;
  int multipartCalls = 0;
  socket.handleMessage(reinterpret_cast<struct msghdr *>(&multipartMessage), multipartOffset, multipartRetrySeq,
                       [&](uint16_t nlmsgType, uint32_t nlmsgSeq, void *nlmsgData, uint32_t) -> void {
                         ++multipartCalls;
                         EXPECT_EQ(suite, nlmsgType, uint16_t(RTM_NEWLINK));
                         EXPECT_EQ(suite, nlmsgSeq, uint32_t(35));
                         auto *parsed = reinterpret_cast<struct ifinfomsg *>(nlmsgData);
                         EXPECT_EQ(suite, parsed->ifi_index, int(99));
                       });
  EXPECT_EQ(suite, multipartCalls, 1);
  EXPECT_EQ(suite, multipartRetrySeq, uint32_t(UINT32_MAX));
  EXPECT_EQ(suite, multipartOffset, multipartMessage.payloadLen());

  NetlinkMessage malformedMessage;
  appendFrame(malformedMessage, RTM_NEWLINK, 0, 37, nullptr, 0);
  headerOf(malformedMessage)->nlmsg_len = sizeof(struct nlmsghdr) - 1;
  int malformedCalls = 0;
  EXPECT_FALSE(suite, NetlinkSocket::visitCheckedMessages(
                          reinterpret_cast<struct msghdr *>(&malformedMessage),
                          malformedMessage.payloadLen(),
                          [&](struct nlmsghdr *) { ++malformedCalls; }));
  EXPECT_EQ(suite, malformedCalls, 0);
}

static void queueAsyncAckRequest(NetlinkStream& stream, uint16_t type = RTM_NEWLINK, uint16_t flags = NLM_F_ACK)
{
  stream.generateRequest([=](NetlinkMessage *request) -> void {
    appendFrame(*request, type, uint16_t(NLM_F_REQUEST | flags), 0, nullptr, 0);
  });
}

static void testAsyncFlushBoundsAndDelayedOutOfOrderAcks(TestSuite& suite)
{
  NetlinkStream bounded;
  queueAsyncAckRequest(bounded);
  queueAsyncAckRequest(bounded);
  int boundedStatus = 0;
  NetlinkStream::AsyncFlushOptions boundedOptions = {};
  boundedOptions.maxRequests = 1;
  const auto boundedHandle = bounded.flushAsync([&](int status) { boundedStatus = status; }, {}, boundedOptions);
  EXPECT_FALSE(suite, boundedHandle.valid());
  EXPECT_EQ(suite, boundedStatus, -E2BIG);

  int descriptors[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0)
  {
    return;
  }

  NetlinkStream stream;
  stream.socket.close();
  stream.socket.fd = descriptors[0];
  stream.socket.isFixedFile = false;
  stream.socket.isNonBlocking = true;
  queueAsyncAckRequest(stream);
  queueAsyncAckRequest(stream, RTM_GETLINK, NLM_F_DUMP);

  struct Scenario final : RingInterface {
    TestSuite& suite;
    TimeoutPacket sample;
    TimeoutPacket earlyCompletionProbe;
    TimeoutPacket guard;
    uint32_t samples = 0;
    uint32_t completions = 0;
    int completionStatus = -1;
    bool completedEarly = false;
    bool guardFired = false;
    uint32_t responseMessages = 0;
    std::chrono::steady_clock::time_point lastSample = std::chrono::steady_clock::now();
    std::vector<int64_t> sampleIntervalsUs;

    explicit Scenario(TestSuite& value) : suite(value)
    {
      sample.setTimeoutMs(2);
      earlyCompletionProbe.setTimeoutMs(20);
      guard.setTimeoutMs(1000);
      sample.originator = this;
      earlyCompletionProbe.originator = this;
      guard.originator = this;
    }

    void timeoutHandler(TimeoutPacket *packet, int result) override
    {
      if (result != -ETIME)
      {
        return;
      }
      if (packet == &sample)
      {
        const auto now = std::chrono::steady_clock::now();
        sampleIntervalsUs.push_back(std::chrono::duration_cast<std::chrono::microseconds>(now - lastSample).count());
        lastSample = now;
        ++samples;
        if (completions == 0 || samples < 30)
        {
          Ring::queueTimeout(&sample);
        }
        else
        {
          Ring::exit = true;
        }
        return;
      }
      if (packet == &earlyCompletionProbe)
      {
        completedEarly = completions != 0;
        return;
      }
      if (packet == &guard)
      {
        guardFired = true;
        Ring::exit = true;
      }
    }
  } scenario(suite);

  std::thread peer([peerFD = descriptors[1]] {
    uint32_t sequences[2] = {};
    for (uint32_t index = 0; index < 2; ++index)
    {
      uint8_t bytes[4096] = {};
      ssize_t received = -1;
      for (uint32_t attempts = 0; attempts < 1000 && received < 0; ++attempts)
      {
        received = recv(peerFD, bytes, sizeof(bytes), 0);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      }
      if (received >= ssize_t(sizeof(struct nlmsghdr)))
      {
        sequences[index] = reinterpret_cast<const struct nlmsghdr *>(bytes)->nlmsg_seq;
      }
    }

    // This is a wall-clock peer delay.  The test records only actual Ring timer
    // callbacks; it does not treat the injected delay as CPU work.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    NetlinkMessage dumpReply;
    struct ifinfomsg link = {};
    link.ifi_index = 41;
    appendFrame(dumpReply, RTM_NEWLINK, NLM_F_MULTI, sequences[1], &link, sizeof(link));
    appendFrame(dumpReply, NLMSG_DONE, NLM_F_MULTI, sequences[1], nullptr, 0);
    (void)send(peerFD, dumpReply.payload(), dumpReply.payloadLen(), 0);
    NetlinkMessage ackReply;
    struct nlmsgerr ack = {};
    appendFrame(ackReply, NLMSG_ERROR, 0, sequences[0], &ack, sizeof(ack));
    (void)send(peerFD, ackReply.payload(), ackReply.payloadLen(), 0);
    close(peerFD);
  });

  RingDispatcher dispatcher;
  RingDispatcher::installMultiplexee(&scenario, &scenario);
  Ring::interfacer = &dispatcher;
  Ring::lifecycler = &dispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&scenario.sample);
  Ring::queueTimeout(&scenario.earlyCompletionProbe);
  Ring::queueTimeout(&scenario.guard);

  const auto handle = stream.flushAsync([&](int status) {
    ++scenario.completions;
    scenario.completionStatus = status;
    if (scenario.samples >= 30)
    {
      Ring::exit = true;
    }
  }, [&](uint16_t type, uint32_t sequence, void *data, uint32_t) {
    if (type == RTM_NEWLINK && sequence != 0 && data != nullptr)
    {
      ++scenario.responseMessages;
    }
  });
  EXPECT_TRUE(suite, handle.valid());
  Ring::start();
  Ring::shutdownForExec();
  peer.join();
  RingDispatcher::eraseMultiplexee(&scenario);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  close(descriptors[0]);
  stream.socket.fd = -1;

  EXPECT_FALSE(suite, scenario.guardFired);
  EXPECT_FALSE(suite, scenario.completedEarly);
  EXPECT_EQ(suite, scenario.completions, uint32_t(1));
  EXPECT_EQ(suite, scenario.completionStatus, 0);
  EXPECT_EQ(suite, scenario.responseMessages, uint32_t(1));
  EXPECT_TRUE(suite, scenario.samples >= 30);
  if (scenario.sampleIntervalsUs.size() >= 30)
  {
    std::cout << "{\"netlink_async_raw_us\":[";
    for (size_t i = 0; i < scenario.sampleIntervalsUs.size(); ++i)
    {
      if (i) std::cout << ',';
      std::cout << scenario.sampleIntervalsUs[i];
    }
    std::cout << "]}\n";
    std::sort(scenario.sampleIntervalsUs.begin(), scenario.sampleIntervalsUs.end());
    const size_t percentile95 = (scenario.sampleIntervalsUs.size() * 95 + 99) / 100 - 1;
    EXPECT_TRUE(suite, scenario.sampleIntervalsUs[percentile95] <= 3000);
    EXPECT_TRUE(suite, scenario.sampleIntervalsUs.back() <= 20'000);
    std::cout << "{\"netlink_async\":{\"samples\":" << scenario.sampleIntervalsUs.size()
              << ",\"p95_us\":" << scenario.sampleIntervalsUs[percentile95]
              << ",\"max_us\":" << scenario.sampleIntervalsUs.back() << "}}\n";
  }
}

static void testSynchronousFlushBaselineStallsDelayedAck(TestSuite& suite)
{
  int descriptors[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0) return;
  NetlinkStream stream;
  stream.socket.close();
  stream.socket.fd = descriptors[0];
  const int socketFlags = fcntl(descriptors[0], F_GETFL, 0);
  EXPECT_TRUE(suite, socketFlags >= 0);
  if (socketFlags >= 0) EXPECT_EQ(suite, fcntl(descriptors[0], F_SETFL, socketFlags & ~O_NONBLOCK), 0);
  stream.socket.isNonBlocking = false;
  queueAsyncAckRequest(stream);
  std::thread peer([fd = descriptors[1]] {
    uint8_t request[4096] = {};
    while (recv(fd, request, sizeof(request), 0) < ssize_t(sizeof(struct nlmsghdr)))
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    NetlinkMessage reply;
    struct nlmsgerr ack = {};
    appendFrame(reply, NLMSG_ERROR, 0, reinterpret_cast<struct nlmsghdr *>(request)->nlmsg_seq, &ack, sizeof(ack));
    (void)send(fd, reply.payload(), reply.payloadLen(), 0);
    close(fd);
  });
  const auto begin = std::chrono::steady_clock::now();
  const bool completed = stream.flushDiscardChecked();
  const auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - begin).count();
  peer.join();
  close(descriptors[0]);
  stream.socket.fd = -1;
  EXPECT_TRUE(suite, completed);
  EXPECT_TRUE(suite, elapsedUs >= 80'000);
  std::cout << "{\"netlink_sync_baseline\":{\"timer_samples\":0,\"blocked_us\":" << elapsedUs << "}}\n";
}

static void testAsyncFlushCancellationAndTimeout(TestSuite& suite)
{
  struct Scenario final : RingInterface {
    TimeoutPacket guard;
    uint32_t callbacks = 0;
    int status = 0;
    bool guardFired = false;

    Scenario()
    {
      guard.setTimeoutMs(500);
      guard.originator = this;
    }

    void timeoutHandler(TimeoutPacket *packet, int result) override
    {
      if (packet == &guard && result == -ETIME)
      {
        guardFired = true;
        Ring::exit = true;
      }
    }
  } scenario;

  int descriptors[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0) return;
  NetlinkStream stream;
  stream.socket.close();
  stream.socket.fd = descriptors[0];
  stream.socket.isNonBlocking = true;
  queueAsyncAckRequest(stream);

  RingDispatcher dispatcher;
  RingDispatcher::installMultiplexee(&scenario, &scenario);
  Ring::interfacer = &dispatcher;
  Ring::lifecycler = &dispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&scenario.guard);
  auto handle = stream.flushAsync([&](int status) {
    ++scenario.callbacks;
    scenario.status = status;
    Ring::exit = true;
  }, {}, {.timeoutMs = 1000});
  EXPECT_TRUE(suite, handle.valid());
  handle.cancel();
  Ring::start();
  Ring::shutdownForExec();
  RingDispatcher::eraseMultiplexee(&scenario);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  close(descriptors[0]);
  close(descriptors[1]);
  stream.socket.fd = -1;
  EXPECT_FALSE(suite, scenario.guardFired);
  EXPECT_EQ(suite, scenario.callbacks, uint32_t(1));
  EXPECT_EQ(suite, scenario.status, -ECANCELED);

  descriptors[0] = descriptors[1] = -1;
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0) return;
  Scenario timeoutScenario;
  NetlinkStream timeoutStream;
  timeoutStream.socket.close();
  timeoutStream.socket.fd = descriptors[0];
  timeoutStream.socket.isNonBlocking = true;
  queueAsyncAckRequest(timeoutStream);
  RingDispatcher timeoutDispatcher;
  RingDispatcher::installMultiplexee(&timeoutScenario, &timeoutScenario);
  Ring::interfacer = &timeoutDispatcher;
  Ring::lifecycler = &timeoutDispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&timeoutScenario.guard);
  const auto timeoutHandle = timeoutStream.flushAsync([&](int status) {
    ++timeoutScenario.callbacks;
    timeoutScenario.status = status;
    Ring::exit = true;
  }, {}, {.timeoutMs = 20});
  EXPECT_TRUE(suite, timeoutHandle.valid());
  Ring::start();
  Ring::shutdownForExec();
  RingDispatcher::eraseMultiplexee(&timeoutScenario);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  close(descriptors[0]);
  close(descriptors[1]);
  timeoutStream.socket.fd = -1;
  EXPECT_FALSE(suite, timeoutScenario.guardFired);
  EXPECT_EQ(suite, timeoutScenario.callbacks, uint32_t(1));
  EXPECT_EQ(suite, timeoutScenario.status, -ETIMEDOUT);
}

static void testAsyncFlushNegativeAck(TestSuite& suite)
{
  int descriptors[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0) return;
  NetlinkStream stream;
  stream.socket.close();
  stream.socket.fd = descriptors[0];
  stream.socket.isNonBlocking = true;
  queueAsyncAckRequest(stream);

  struct Scenario final : RingInterface {
    TimeoutPacket guard;
    bool guardFired = false;
    Scenario() { guard.setTimeoutMs(500); guard.originator = this; }
    void timeoutHandler(TimeoutPacket *packet, int result) override
    {
      if (packet == &guard && result == -ETIME) { guardFired = true; Ring::exit = true; }
    }
  } scenario;
  std::thread peer([fd = descriptors[1]] {
    uint8_t request[4096] = {};
    for (;;)
    {
      ssize_t received = recv(fd, request, sizeof(request), 0);
      if (received >= ssize_t(sizeof(struct nlmsghdr)))
      {
        NetlinkMessage reply;
        struct nlmsgerr error = {};
        error.error = -EPERM;
        appendFrame(reply, NLMSG_ERROR, 0, reinterpret_cast<struct nlmsghdr *>(request)->nlmsg_seq, &error, sizeof(error));
        (void)send(fd, reply.payload(), reply.payloadLen(), 0);
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    close(fd);
  });
  uint32_t callbacks = 0;
  int status = 0;
  RingDispatcher dispatcher;
  RingDispatcher::installMultiplexee(&scenario, &scenario);
  Ring::interfacer = &dispatcher;
  Ring::lifecycler = &dispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&scenario.guard);
  const auto handle = stream.flushAsync([&](int result) { ++callbacks; status = result; Ring::exit = true; });
  EXPECT_TRUE(suite, handle.valid());
  Ring::start();
  Ring::shutdownForExec();
  peer.join();
  RingDispatcher::eraseMultiplexee(&scenario);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  close(descriptors[0]);
  stream.socket.fd = -1;
  EXPECT_FALSE(suite, scenario.guardFired);
  EXPECT_EQ(suite, callbacks, uint32_t(1));
  EXPECT_EQ(suite, status, -EPERM);
}

static void testAsyncFlushDumpTerminalErrors(TestSuite& suite)
{
  const auto run = [&](int doneError, bool interrupted, int expected) {
    int descriptors[2] = {-1, -1};
    EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return;
    NetlinkStream stream;
    stream.socket.close();
    stream.socket.fd = descriptors[0];
    stream.socket.isNonBlocking = true;
    queueAsyncAckRequest(stream, RTM_GETLINK, NLM_F_DUMP);
    struct Stopper final : RingInterface {
      TimeoutPacket guard;
      Stopper() { guard.setTimeoutMs(500); guard.originator = this; }
      void timeoutHandler(TimeoutPacket *packet, int result) override { if (packet == &guard && result == -ETIME) Ring::exit = true; }
    } stopper;
    std::thread peer([fd = descriptors[1], doneError, interrupted] {
      uint8_t request[4096] = {};
      while (recv(fd, request, sizeof(request), 0) < ssize_t(sizeof(struct nlmsghdr)))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      NetlinkMessage reply;
      const int error = doneError;
      appendFrame(reply, NLMSG_DONE, interrupted ? NLM_F_DUMP_INTR : 0,
                  reinterpret_cast<struct nlmsghdr *>(request)->nlmsg_seq,
                  doneError == 0 ? nullptr : &error, doneError == 0 ? 0 : sizeof(error));
      (void)send(fd, reply.payload(), reply.payloadLen(), 0);
      close(fd);
    });
    uint32_t callbacks = 0;
    int status = 0;
    RingDispatcher dispatcher;
    RingDispatcher::installMultiplexee(&stopper, &stopper);
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    Ring::queueTimeout(&stopper.guard);
    const auto handle = stream.flushAsync([&](int result) { ++callbacks; status = result; Ring::exit = true; });
    EXPECT_TRUE(suite, handle.valid());
    Ring::start();
    Ring::shutdownForExec();
    peer.join();
    RingDispatcher::eraseMultiplexee(&stopper);
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    close(descriptors[0]);
    stream.socket.fd = -1;
    EXPECT_EQ(suite, callbacks, uint32_t(1));
    EXPECT_EQ(suite, status, expected);
  };
  run(-EIO, false, -EIO);
  run(0, true, -EINTR);
}

static void testAsyncFlushStreamDestructionDrainsOutstandingCQEs(TestSuite& suite)
{
  int descriptors[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0) return;
  struct Stopper final : RingInterface {
    TimeoutPacket guard;
    Stopper() { guard.setTimeoutMs(40); guard.originator = this; }
    void timeoutHandler(TimeoutPacket *packet, int result) override { if (packet == &guard && result == -ETIME) Ring::exit = true; }
  } stopper;
  bool callbackFired = false;
  RingDispatcher dispatcher;
  RingDispatcher::installMultiplexee(&stopper, &stopper);
  Ring::interfacer = &dispatcher;
  Ring::lifecycler = &dispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&stopper.guard);
  {
    NetlinkStream stream;
    stream.socket.close();
    stream.socket.fd = descriptors[0];
    stream.socket.isNonBlocking = true;
    queueAsyncAckRequest(stream);
    const auto handle = stream.flushAsync([&](int) { callbackFired = true; }, {}, {.timeoutMs = 1000});
    EXPECT_TRUE(suite, handle.valid());
  }
  Ring::start();
  Ring::shutdownForExec();
  RingDispatcher::eraseMultiplexee(&stopper);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  close(descriptors[1]);
  EXPECT_FALSE(suite, callbackFired);
}

static void testReadonlyLoopbackGetInfoAsyncMatchesSync(TestSuite& suite)
{
  const unsigned int loopbackIndex = if_nametoindex("lo");
  if (loopbackIndex == 0) return;
  NetDevice synchronous;
  synchronous.name = "lo"_ctv;
  synchronous.socket.configure();
  synchronous.getInfo();
  EXPECT_EQ(suite, synchronous.ifidx, uint32_t(loopbackIndex));

  NetDevice asynchronous;
  asynchronous.name = "lo"_ctv;
  asynchronous.socket.configure();
  struct Stopper final : RingInterface {
    TimeoutPacket guard;
    Stopper() { guard.setTimeoutMs(2000); guard.originator = this; }
    void timeoutHandler(TimeoutPacket *packet, int result) override { if (packet == &guard && result == -ETIME) Ring::exit = true; }
  } stopper;
  int callbacks = 0;
  int status = -1;
  RingDispatcher dispatcher;
  RingDispatcher::installMultiplexee(&stopper, &stopper);
  Ring::interfacer = &dispatcher;
  Ring::lifecycler = &dispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&stopper.guard);
  const auto handle = asynchronous.getInfoAsync([&](int result) { ++callbacks; status = result; Ring::exit = true; });
  EXPECT_TRUE(suite, handle.valid());
  Ring::start();
  Ring::shutdownForExec();
  RingDispatcher::eraseMultiplexee(&stopper);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  EXPECT_EQ(suite, callbacks, 1);
  EXPECT_EQ(suite, status, 0);
  EXPECT_EQ(suite, asynchronous.ifidx, synchronous.ifidx);
  EXPECT_EQ(suite, asynchronous.mtu, synchronous.mtu);
}

static void testAsyncResponseCanDestroyItsStream(TestSuite& suite)
{
  int descriptors[2] = {-1, -1};
  EXPECT_EQ(suite, socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors), 0);
  if (descriptors[0] < 0 || descriptors[1] < 0) return;
  struct Stopper final : RingInterface {
    TimeoutPacket guard;
    Stopper() { guard.setTimeoutMs(100); guard.originator = this; }
    void timeoutHandler(TimeoutPacket *, int result) override { if (result == -ETIME) Ring::exit = true; }
  } stopper;
  RingDispatcher dispatcher;
  RingDispatcher::installMultiplexee(&stopper, &stopper);
  Ring::interfacer = &dispatcher;
  Ring::lifecycler = &dispatcher;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 8, 2, -1, -1, 8);
  Ring::queueTimeout(&stopper.guard);
  auto stream = std::make_unique<NetlinkStream>();
  stream->socket.close();
  stream->socket.fd = descriptors[0];
  queueAsyncAckRequest(*stream, RTM_GETLINK, 0);
  uint32_t responses = 0, completions = 0;
  const auto handle = stream->flushAsync([&](int) { ++completions; },
      [&](uint16_t, uint32_t, void *, uint32_t) { ++responses; stream.reset(); });
  std::thread peer([fd = descriptors[1]] {
    uint8_t bytes[4096] = {};
    ssize_t size = -1;
    for (unsigned attempt = 0; attempt < 100 && size < 0; ++attempt)
    {
      size = recv(fd, bytes, sizeof(bytes), 0);
      if (size < 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (size >= ssize_t(sizeof(nlmsghdr)))
    {
      NetlinkMessage reply;
      ifinfomsg info = {};
      appendFrame(reply, RTM_NEWLINK, 0, reinterpret_cast<nlmsghdr *>(bytes)->nlmsg_seq, &info, sizeof(info));
      (void)send(fd, reply.payload(), reply.payloadLen(), 0);
    }
    close(fd);
  });
  Ring::start();
  Ring::shutdownForExec();
  peer.join();
  RingDispatcher::eraseMultiplexee(&stopper);
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  EXPECT_EQ(suite, responses, uint32_t(1));
  EXPECT_EQ(suite, completions, uint32_t(0));
  EXPECT_TRUE(suite, stream == nullptr);
}

static void testWrapperHelpers(TestSuite& suite)
{
  VethPair vethPair;
  vethPair.setNames("demo"_ctv);
  EXPECT_STRING_EQ(suite, vethPair.host.name, "demo_veth0"_ctv);
  EXPECT_STRING_EQ(suite, vethPair.peer.name, "demo_veth1"_ctv);

  NetkitPair netkitPair;
  netkitPair.setNames("demo"_ctv);
  EXPECT_STRING_EQ(suite, netkitPair.host.name, "demo_netkit0"_ctv);
  EXPECT_STRING_EQ(suite, netkitPair.peer.name, "demo_netkit1"_ctv);
}

static void testGuardianBootHonorsDisableEnv(TestSuite& suite)
{
  const char *previousValue = std::getenv("BASICS_DISABLE_GUARDIAN_TERMINATE_SIGNALS");
  std::string savedValue = previousValue ? std::string(previousValue) : std::string();

  struct sigaction previousPipeAction = {};
  struct sigaction previousSegvAction = {};
  sigaction(SIGPIPE, nullptr, &previousPipeAction);
  sigaction(SIGSEGV, nullptr, &previousSegvAction);

  setenv("BASICS_DISABLE_GUARDIAN_TERMINATE_SIGNALS", "1", 1);
  Guardian::boot();

  struct sigaction pipeAction = {};
  struct sigaction segvAction = {};
  sigaction(SIGPIPE, nullptr, &pipeAction);
  sigaction(SIGSEGV, nullptr, &segvAction);

  EXPECT_TRUE(suite, pipeAction.sa_handler == SIG_IGN);
  EXPECT_TRUE(suite, segvAction.sa_sigaction == previousSegvAction.sa_sigaction);
  EXPECT_EQ(suite, segvAction.sa_flags, previousSegvAction.sa_flags);

  sigaction(SIGPIPE, &previousPipeAction, nullptr);
  sigaction(SIGSEGV, &previousSegvAction, nullptr);

  if (previousValue != nullptr)
  {
    setenv("BASICS_DISABLE_GUARDIAN_TERMINATE_SIGNALS", savedValue.c_str(), 1);
  }
  else
  {
    unsetenv("BASICS_DISABLE_GUARDIAN_TERMINATE_SIGNALS");
  }
}

} // namespace

int main()
{
  TestSuite suite;

  testLookupAndUpdateRequestBuilders(suite);
  testRouteRequestBuilders(suite);
  testLinkCreationBuilders(suite);
  testHandleMessageParsing(suite);
  testAsyncFlushBoundsAndDelayedOutOfOrderAcks(suite);
  testSynchronousFlushBaselineStallsDelayedAck(suite);
  testAsyncFlushCancellationAndTimeout(suite);
  testAsyncFlushNegativeAck(suite);
  testAsyncFlushDumpTerminalErrors(suite);
  testAsyncFlushStreamDestructionDrainsOutstandingCQEs(suite);
  testReadonlyLoopbackGetInfoAsyncMatchesSync(suite);
  testAsyncResponseCanDestroyItsStream(suite);
  testWrapperHelpers(suite);
  testGuardianBootHonorsDisableEnv(suite);

  return suite.finish("netlink tests");
}
