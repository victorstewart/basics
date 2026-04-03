// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cerrno>
#include <csignal>
#include <cstdlib>
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
  socket.createNetkitPair(&netkitRequest, 21, NETKIT_L3, "kit0"_ctv, "kit1"_ctv, 5678);

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
      const struct nlattr *peerInfoAttr = findNlAttr(socket, infoDataPayload, infoDataPayloadLen, IFLA_NETKIT_PEER_INFO);
      EXPECT_TRUE(suite, modeAttr != nullptr);
      EXPECT_TRUE(suite, peerInfoAttr != nullptr);
      if (modeAttr != nullptr)
      {
        EXPECT_EQ(suite, *reinterpret_cast<const uint32_t *>(socket.nla_data(modeAttr)), uint32_t(NETKIT_L3));
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
  testWrapperHelpers(suite);
  testGuardianBootHonorsDisableEnv(suite);

  return suite.finish("netlink tests");
}
