// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <climits>
#include <cerrno>
#include <functional>
#include <memory>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <linux/if.h> // needed for IF_OPER_UNKNOWN values
#include <linux/if_link.h>
#include <linux/net_namespace.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <networking/msg.h>
#include <networking/pool.h>
#include <networking/socket.h>
#include <networking/ring.h>
#include <networking/multiplexer.h>
#include <ebpf/program.h>

#pragma once

using NetlinkMessage = Message32KB;

class NetlinkSocket : public SocketBase {
private:

  // struct nlmsghdr {
  // __u32 nlmsg_len;    /* Length of message including header */
  // __u16 nlmsg_type;   /* Type of message content */
  // __u16 nlmsg_flags;  /* Additional flags */
  // __u32 nlmsg_seq;    /* Sequence number */
  // __u32 nlmsg_pid;    /* Sender port ID */
  // };

  struct nl_req {

    uint8_t payload[8096];
    struct nlmsghdr *h;

    uint32_t len(void)
    {
      return h->nlmsg_len;
    }

    template <typename T>
    T *appendStruct(void)
    {
      h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len);

      if (h->nlmsg_len + NLMSG_ALIGN(sizeof(T)) > sizeof(payload))
      {
        return nullptr;
      }

      T *object = reinterpret_cast<T *>(payload + h->nlmsg_len);
      h->nlmsg_len += NLMSG_ALIGN(sizeof(T));

      return object;
    }

    struct rtattr *appendAttribute(int type, const void *data, uint32_t data_len)
    {
      struct rtattr *rta = appendStruct<struct rtattr>();

      if (!rta)
      {
        return nullptr;
      }

      rta->rta_type = type;
      rta->rta_len = RTA_LENGTH(data_len);

      // Check if there's enough space for the data
      if (h->nlmsg_len + RTA_ALIGN(data_len) > sizeof(payload))
      {
        return nullptr;
      }

      // Copy the data into the payload
      memcpy(RTA_DATA(rta), data, data_len);

      // Update the length of the Netlink message
      h->nlmsg_len += RTA_ALIGN(data_len);

      return rta;
    }

    template <typename Creator>
    struct nlattr *appendAttributeTree(int type, Creator&& creator)
    {
      uint32_t starting_len = h->nlmsg_len;

      struct nlattr *nla = appendStruct<struct nlattr>();
      if (!nla)
      {
        return nullptr;
      }

      nla->nla_type = type | NLA_F_NESTED;
      // nla->nla_len = NLMSG_ALIGN(sizeof(struct nlattr));

      creator();

      nla->nla_len = h->nlmsg_len - starting_len;

      return nla;
    }

    nl_req()
    {
      h = (struct nlmsghdr *)payload;
      h->nlmsg_len = NLMSG_LENGTH(0);
    }
  };

public:

  NetlinkSocket()
      : SocketBase(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, false)
  {
    saddrLen = sizeof(struct sockaddr_nl);

    struct sockaddr_nl *addr = saddr<struct sockaddr_nl>();
    addr->nl_family = AF_NETLINK;
    addr->nl_pid = getpid();

    createSocket();
  }

  void configure(void)
  {
    int one = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));

    bind();
  }

  // NetlinkStream keeps this raw descriptor outside SocketBase's fixed-file
  // lifecycle.  Make explicit manual close idempotent so ResourceState can
  // safely perform its no-Ring fallback retirement.
  void close(void)
  {
    if (isFixedFile == false && fd >= 0)
    {
      ::close(fd);
      fd = -1;
    }
  }

  template <typename Consumer>
  static void parseAttributes(void *data, int len, Consumer&& consumer)
  {
    struct rtattr *rta = (struct rtattr *)data;

    while (RTA_OK(rta, len))
    {
      consumer(rta->rta_type, RTA_DATA(rta));
      rta = RTA_NEXT(rta, len);
    }
  }

  void getRoutes(NetlinkMessage *request, uint32_t seq)
  {
    struct nl_req *nlreq = new (request->data) nl_req();

    // asks for all (NLM_F_DUMP) ipv4 routes from the kernel's routing table
    nlreq->h->nlmsg_type = RTM_GETROUTE;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlreq->h->nlmsg_seq = seq;

    struct rtmsg *rtm = nlreq->appendStruct<struct rtmsg>();
    rtm->rtm_family = AF_INET; // doesn't actually matter whether we try ipv4 or ipv6, we only care about ultimately getting the gateway MAC

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void getMACAddress(NetlinkMessage *request, uint32_t seq, int ifidx)
  {

    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_GETLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_PACKET;
    ifm->ifi_index = ifidx;

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void getAddresses(NetlinkMessage *request, uint32_t seq, int ifidx)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_GETADDR;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlreq->h->nlmsg_seq = seq;

    struct ifaddrmsg *ifa = nlreq->appendStruct<struct ifaddrmsg>();
    ifa->ifa_index = ifidx;

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void addIPtoInterface(NetlinkMessage *request, uint32_t seq, const IPPrefix& prefix, int ifidx)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWADDR;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifaddrmsg *ifa = nlreq->appendStruct<struct ifaddrmsg>();
    ifa->ifa_family = prefix.network.is6 ? AF_INET6 : AF_INET;
    ifa->ifa_prefixlen = prefix.cidr;
    ifa->ifa_flags = IFA_F_PERMANENT;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_index = ifidx;

    // ifa->ifa_flags
    // IFA_F_NODAD -> disables Duplicate Address Detection (DAD)
    // IFA_F_NOPREFIXROUTE: This flag prevents the automatic creation of a route for the address prefix.
    // IFA_F_OPTIMISTIC: This flag marks the address as "optimistic" during Duplicate Address Detection, meaning it can be used before DAD procedure is complete, with some restrictions.

    if (prefix.network.is6)
    {
      nlreq->appendAttribute(IFA_ADDRESS, prefix.network.v6, sizeof(struct in6_addr));
    }
    else
    {
      nlreq->appendAttribute(IFA_LOCAL, prefix.network.v6, sizeof(struct in_addr));
    }

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void addIPtoInterface(NetlinkMessage *request, uint32_t seq, StringType auto&& address, uint8_t cidr, bool is6, int ifidx)
  {
    IPPrefix prefix;
    prefix.cidr = cidr;
    prefix.network.is6 = is6;

    if (is6)
    {
      inet_pton(AF_INET6, address.c_str(), prefix.network.v6);
    }
    else
    {
      inet_pton(AF_INET, address.c_str(), prefix.network.v6);
    }

    addIPtoInterface(request, seq, prefix, ifidx);
  }

  void removeIPFromInterface(NetlinkMessage *request, uint32_t seq, StringType auto&& address, uint8_t cidr, bool is6, int ifidx)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_DELADDR; // Netlink message type for deleting an address
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; // Request with acknowledgment
    nlreq->h->nlmsg_seq = seq;

    struct ifaddrmsg *ifa = nlreq->appendStruct<struct ifaddrmsg>();
    ifa->ifa_family = is6 ? AF_INET6 : AF_INET; // Address family: IPv4 or IPv6
    ifa->ifa_prefixlen = cidr; // Subnet prefix length
    ifa->ifa_index = ifidx; // Interface index

    if (is6)
    {
      struct in6_addr addr6;
      inet_pton(AF_INET6, address.c_str(), &addr6);
      nlreq->appendAttribute(IFA_ADDRESS, &addr6, sizeof(struct in6_addr));
    }
    else
    {
      struct in_addr addr4;
      inet_pton(AF_INET, address.c_str(), &addr4);
      nlreq->appendAttribute(IFA_ADDRESS, &addr4, sizeof(struct in_addr));
    }

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void getInterface(NetlinkMessage *request, uint32_t seq, StringType auto&& ifname)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_GETLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;

    nlreq->appendAttribute(IFLA_IFNAME, ifname.c_str(), ifname.size() + 1);

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void addRoute(NetlinkMessage *request, uint32_t seq, int ifidx, const IPPrefix& subnet, const IPAddress& gateway, const IPAddress& prefsrc)
  {
    bool is6 = subnet.network.is6;

    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWROUTE;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct rtmsg *rtm = nlreq->appendStruct<struct rtmsg>();
    rtm->rtm_family = is6 ? AF_INET6 : AF_INET;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_protocol = RTPROT_STATIC;

    // IPv6 direct routes use universe scope; IPv4 on-link routes use link scope.
    // Gateway routes for both families use universe scope.
    if (gateway.isNull())
    {
      rtm->rtm_scope = is6 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    }
    else
    {
      rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    }

    if (subnet.cidr > 0)
    {
      nlreq->appendAttribute(RTA_DST, subnet.network.v6, is6 ? 16 : 4);
      rtm->rtm_dst_len = subnet.cidr;
    }

    if (gateway.isNull() == false)
    {
      nlreq->appendAttribute(RTA_GATEWAY, gateway.v6, is6 ? 16 : 4);
    }

    if (prefsrc.isNull() == false) // this won't add for some reason... claims the address isn't attached to the interface? forget it for now
    {
      nlreq->appendAttribute(RTA_PREFSRC, prefsrc.v6, is6 ? 16 : 4);
    }

    nlreq->appendAttribute(RTA_OIF, &ifidx, sizeof(int));

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void moveInterfaceToNamespace(NetlinkMessage *request, uint32_t seq, StringType auto&& ifname, int netnsfd)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_SETLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;

    nlreq->appendAttribute(IFLA_IFNAME, ifname.c_str(), ifname.size() + 1);
    nlreq->appendAttribute(IFLA_NET_NS_FD, &netnsfd, 4);

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void createVethPair(NetlinkMessage *request, uint32_t seq, StringType auto&& hostname, StringType auto&& peername, int peerpid)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *host_ifm = nlreq->appendStruct<struct ifinfomsg>();
    host_ifm->ifi_family = AF_UNSPEC;

    nlreq->appendAttribute(IFLA_IFNAME, hostname.c_str(), hostname.size() + 1);

    // veth MTU must be within these inclusive bounds..
    // #define ETH_MIN_MTU	68		/* Min IPv4 MTU per RFC791	*/
    // #define ETH_MAX_MTU	0xFFFFU		/* 65535, same as IP_MAX_MTU	*/

    nlreq->appendAttributeTree(IFLA_LINKINFO, [&](void) -> void {
      nlreq->appendAttribute(IFLA_INFO_KIND, "veth", 5);

      nlreq->appendAttributeTree(IFLA_INFO_DATA, [&](void) -> void {
        nlreq->appendAttributeTree(VETH_INFO_PEER, [&](void) -> void {
          struct ifinfomsg *peer_ifm = nlreq->appendStruct<struct ifinfomsg>();
          peer_ifm->ifi_family = AF_UNSPEC;

          nlreq->appendAttribute(IFLA_IFNAME, peername.c_str(), peername.size() + 1);

          if (peerpid > -1)
          {
            nlreq->appendAttribute(IFLA_NET_NS_PID, &peerpid, sizeof(peerpid));
          }
        });
      });
    });

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void destroyNetDevice(NetlinkMessage *request, uint32_t seq, int ifidx)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_DELLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = ifidx;

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void bringUpInterface(NetlinkMessage *request, uint32_t seq, int ifidx)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = ifidx;
    ifm->ifi_flags = IFF_UP;
    ifm->ifi_change = IFF_UP; // | IFF_MULTICAST;

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void setInterfaceMTU(NetlinkMessage *request, uint32_t seq, int ifidx, uint32_t mtu)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = ifidx;

    nlreq->appendAttribute(IFLA_MTU, &mtu, sizeof(mtu));

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void setInterfacePacketBudget(NetlinkMessage *request, uint32_t seq, int ifidx, uint32_t mtu, uint32_t gsoMaxSegs = 0)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = ifidx;

    nlreq->appendAttribute(IFLA_MTU, &mtu, sizeof(mtu));
    nlreq->appendAttribute(IFLA_GSO_MAX_SIZE, &mtu, sizeof(mtu));
    nlreq->appendAttribute(IFLA_GRO_MAX_SIZE, &mtu, sizeof(mtu));
    nlreq->appendAttribute(IFLA_GSO_IPV4_MAX_SIZE, &mtu, sizeof(mtu));
    nlreq->appendAttribute(IFLA_GRO_IPV4_MAX_SIZE, &mtu, sizeof(mtu));

    if (gsoMaxSegs > 0)
    {
      nlreq->appendAttribute(IFLA_GSO_MAX_SEGS, &gsoMaxSegs, sizeof(gsoMaxSegs));
    }

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  // mode == NETKIT_L2 or NETKIT_L3
  void createNetkitPair(NetlinkMessage *request,
                        uint32_t seq,
                        uint32_t mode,
                        StringType auto&& hostname,
                        StringType auto&& peername,
                        int peerpid,
                        uint32_t scrub = NETKIT_SCRUB_DEFAULT,
                        uint32_t peerScrub = NETKIT_SCRUB_DEFAULT)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_NEWLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;

    nlreq->appendAttribute(IFLA_IFNAME, hostname.c_str(), hostname.size() + 1);

    nlreq->appendAttributeTree(IFLA_LINKINFO, [&](void) -> void {
      nlreq->appendAttribute(IFLA_INFO_KIND, "netkit", 7);

      nlreq->appendAttributeTree(IFLA_INFO_DATA, [&](void) -> void {
        nlreq->appendAttribute(IFLA_NETKIT_MODE, &mode, sizeof(mode));

        int policydrop = NETKIT_DROP;
        int policypass = NETKIT_PASS;

        nlreq->appendAttribute(IFLA_NETKIT_PEER_POLICY, &policypass, sizeof(policypass));
        nlreq->appendAttribute(IFLA_NETKIT_POLICY, &policypass, sizeof(policypass));
        nlreq->appendAttribute(IFLA_NETKIT_SCRUB, &scrub, sizeof(scrub));
        nlreq->appendAttribute(IFLA_NETKIT_PEER_SCRUB, &peerScrub, sizeof(peerScrub));

        nlreq->appendAttributeTree(IFLA_NETKIT_PEER_INFO, [&](void) -> void {
          struct ifinfomsg *peer_ifm = nlreq->appendStruct<struct ifinfomsg>();
          peer_ifm->ifi_family = AF_UNSPEC;

          nlreq->appendAttribute(IFLA_IFNAME, peername.c_str(), peername.size() + 1);

          if (peerpid > -1)
          {
            nlreq->appendAttribute(IFLA_NET_NS_PID, &peerpid, sizeof(peerpid));
          }
        });
      });
    });

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void modifyXDPProgOnInterface(NetlinkMessage *request, uint32_t seq, int ifidx, int xdpfd, uint32_t xdpflags)
  {
    struct nl_req *nlreq = new (request->data) nl_req();
    nlreq->h->nlmsg_type = RTM_SETLINK;
    nlreq->h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlreq->h->nlmsg_seq = seq;

    struct ifinfomsg *ifm = nlreq->appendStruct<struct ifinfomsg>();
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = ifidx;

    nlreq->appendAttributeTree(IFLA_XDP, [&](void) -> void {
      if (xdpfd > -1)
      {
        nlreq->appendAttribute(IFLA_XDP_FD, &xdpfd, sizeof(int));
        nlreq->appendAttribute(IFLA_XDP_FLAGS, &xdpflags, sizeof(uint32_t));
      }
    });

    request->setPayloadLen(nlreq->h->nlmsg_len);
    request->setAddrLen(0);
  }

  void attachXDPProgToInterface(NetlinkMessage *request, uint32_t seq, int ifidx, int xdpfd, uint32_t xdpflags)
  {
    modifyXDPProgOnInterface(request, seq, ifidx, xdpfd, xdpflags);
  }

  void detachXDPProgFromInterface(NetlinkMessage *request, uint32_t seq, int ifidx, uint32_t xdpflags)
  {
    modifyXDPProgOnInterface(request, seq, ifidx, -1, xdpflags & XDP_FLAGS_MODES);
  }

  template <typename Handler>
  static bool visitCheckedMessages(struct msghdr *msg, uint32_t bytes, Handler&& handler)
  {
    if (msg == nullptr || msg->msg_iov == nullptr || msg->msg_iovlen == 0 ||
        bytes > msg->msg_iov[0].iov_len)
    {
      return false;
    }

    uint32_t offset = 0;
    while (offset < bytes)
    {
      if (bytes - offset < sizeof(struct nlmsghdr))
      {
        return false;
      }

      struct nlmsghdr *header = reinterpret_cast<struct nlmsghdr *>(
          static_cast<uint8_t *>(msg->msg_iov[0].iov_base) + offset);
      if (header->nlmsg_len < sizeof(struct nlmsghdr) || header->nlmsg_len > bytes - offset)
      {
        return false;
      }

      const uint32_t aligned = NLMSG_ALIGN(header->nlmsg_len);
      if (aligned > bytes - offset)
      {
        return false;
      }

      handler(header);
      offset += aligned;
    }

    return true;
  }

  template <typename Handler>
  void handleMessage(struct msghdr *msg, uint32_t& offset, uint32_t& retrySeq, Handler&& handler, bool printAll = false)
  {
    // there will not be any interleaving of response frames across requests

    struct nlmsghdr *h = (struct nlmsghdr *)((uint8_t *)(msg->msg_iov[0].iov_base) + offset);

    bool isMulti = (h->nlmsg_flags & NLM_F_MULTI);
    if (offset > msg->msg_iov[0].iov_len)
    {
      return;
    }

    size_t remaining = msg->msg_iov[0].iov_len - offset;
    if (remaining > size_t(INT_MAX))
    {
      return;
    }

    int len = int(remaining);

    while (len >= int(sizeof(struct nlmsghdr)) &&
           h->nlmsg_len >= sizeof(struct nlmsghdr) &&
           h->nlmsg_len <= uint32_t(INT_MAX) &&
           int(h->nlmsg_len) <= len)
    {
      if (printAll)
      {
        printNetlinkMessage(h);
      }

      offset += h->nlmsg_len;

      switch (h->nlmsg_type)
      {
        case NLMSG_ERROR: // if the request we malformed, also should never happen
          {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

            if (err->error == 0) // ACK
            {
              handler(h->nlmsg_type, h->nlmsg_seq, nullptr, h->nlmsg_len);
            }
            else
            {
              // EEXIST/EADDRINUSE are expected for idempotent route/address setup under churn.
              if (printAll == false && err->error != -EEXIST && err->error != -EADDRINUSE)
              {
                printNetlinkMessage(h);
              }
              retrySeq = h->nlmsg_seq;
            }
          }
        case NLMSG_DONE:
          {
            return;
          }
        default:
          break;
      }

      // will probably never happen but..
      if (h->nlmsg_flags & NLM_F_DUMP_INTR)
      {
        retrySeq = h->nlmsg_seq;
        return;
      }

      // [&] (uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len)
      handler(h->nlmsg_type, h->nlmsg_seq, NLMSG_DATA(h), h->nlmsg_len); // maybe we should do - NLMSG_LENGTH(0)?

      if (isMulti == false)
      {
        return;
      }

      int alignedLen = NLMSG_ALIGN(h->nlmsg_len);
      len -= alignedLen;
      h = reinterpret_cast<struct nlmsghdr *>(reinterpret_cast<uint8_t *>(h) + alignedLen);
    }
  }

  template <typename Handler>
  void unsafeHandleMessage(struct msghdr *msg, uint32_t& offset, Handler&& handler, bool printAll = false)
  {
    uint32_t retrySeq = UINT32_MAX;
    handleMessage(msg, offset, retrySeq, std::forward<Handler>(handler));
  }

  template <typename Handler>
  void unsafeHandleMessage(struct msghdr *msg, Handler&& handler, bool printAll = false)
  {
    uint32_t retrySeq = UINT32_MAX;
    uint32_t offset = 0;
    handleMessage(msg, offset, retrySeq, std::forward<Handler>(handler), printAll);
  }

  int nla_ok(const struct nlattr *nla, int remaining)
  {
    return remaining > 0 &&
           nla->nla_len >= sizeof(struct nlattr) &&
           sizeof(struct nlattr) <= (unsigned int)remaining &&
           nla->nla_len <= remaining;
  }

  struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
  {
    struct nlattr *next_nla = NULL;
    if (nla->nla_len >= sizeof(struct nlattr) &&
        nla->nla_len <= *remaining)
    {
      next_nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
      *remaining = *remaining - NLA_ALIGN(nla->nla_len);
    }
    return next_nla;
  }

  void *nla_data(const struct nlattr *nla)
  {
    return (void *)((char *)nla + sizeof(struct nlattr));
  }

  void printIflaAttributes(uint8_t *attrs, uint32_t len)
  {
    // struct rtattr {
    // unsigned short rta_len;    /* Length of option */
    // unsigned short rta_type;   /* Type of option */
    // /* Data follows */
    // };


    struct rtattr *attr = reinterpret_cast<struct rtattr *>(attrs);
    int attrlen = len;

    for (; RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen))
    {

      switch (attr->rta_type)
      {
        case IFLA_UNSPEC:
          {
            break;
          }
        case IFLA_ADDRESS:
          {
            break;
          }
        case IFLA_BROADCAST:
          {
            break;
          }
        case IFLA_IFNAME:
          {
            break;
          }
        case IFLA_MTU:
          {
            break;
          }
        case IFLA_LINK:
          {
            break;
          }
        case IFLA_QDISC:
          {
            break;
          }
        case IFLA_LINK_NETNSID:
          {
            break;
          }
        case IFLA_TARGET_NETNSID:
          {
            // alias for IFLA_IF_NETNSID
            break;
          }
        case IFLA_STATS:
          {
            break;
          }
        case IFLA_TXQLEN:
          {
            break;
          }
        case IFLA_NUM_TX_QUEUES:
          {
            break;
          }
        case IFLA_GSO_MAX_SIZE:
          {
            break;
          }
        case IFLA_GRO_MAX_SIZE:
          {
            break;
          }
        case IFLA_GSO_IPV4_MAX_SIZE:
          {
            break;
          }
        case IFLA_GRO_IPV4_MAX_SIZE:
          {
            break;
          }
        case IFLA_TSO_MAX_SIZE:
          {
            break;
          }
        case IFLA_TSO_MAX_SEGS:
          {
            break;
          }
        case IFLA_NUM_RX_QUEUES:
          {
            break;
          }
        case IFLA_AF_SPEC:
          {
            break;
          }
        case IFLA_OPERSTATE:
          {
            switch (*(uint8_t *)RTA_DATA(attr))
            {
              case IF_OPER_UNKNOWN:
                {
                  break;
                }
              case IF_OPER_NOTPRESENT:
                {
                  break;
                }
              case IF_OPER_DOWN:
                {
                  break;
                }
              case IF_OPER_LOWERLAYERDOWN:
                {
                  break;
                }
              case IF_OPER_TESTING:
                {
                  break;
                }
              case IF_OPER_DORMANT:
                {
                  break;
                }
              case IF_OPER_UP:
                {
                  break;
                }
              default:
                {
                  break;
                }
            }

            break;
          }
        case IFLA_PERM_ADDRESS:
          {
            break;
          }
        case IFLA_LINKMODE:
          {
            switch (*(uint8_t *)RTA_DATA(attr))
            {
              case IF_LINK_MODE_DEFAULT:
                {
                  break;
                }
              case IF_LINK_MODE_DORMANT:
                {
                  break;
                }
              case IF_LINK_MODE_TESTING:
                {
                  break;
                }
              default:
                {
                  break;
                }
            }

            break;
          }
        case IFLA_MIN_MTU:
          {
            break;
          }
        case IFLA_MAX_MTU:
          {
            break;
          }
        case IFLA_GROUP:
          {
            break;
          }
        case IFLA_PROMISCUITY:
          {
            break;
          }
        case IFLA_ALLMULTI:
          {
            break;
          }
        case IFLA_GSO_MAX_SEGS:
          {
            break;
          }
        case IFLA_CARRIER:
          {
            break;
          }
        case IFLA_CARRIER_CHANGES:
          {
            break;
          }
        case IFLA_CARRIER_UP_COUNT:
          {
            break;
          }
        case IFLA_CARRIER_DOWN_COUNT:
          {
            break;
          }
        case IFLA_PROTO_DOWN:
          {
            break;
          }
        case IFLA_MAP:
          {
            // rtnl_link_ifmap
            break;
          }
        case IFLA_STATS64:
          {
            // rtnl_link_stats64
            break;
          }
        case IFLA_LINKINFO:
          {
            break;
          }
        case IFLA_XDP:
          {

            struct nlattr *nla = (struct nlattr *)RTA_DATA(attr);
            int nla_len = RTA_PAYLOAD(attr);

            for (; nla_ok(nla, nla_len); nla = nla_next(nla, &nla_len))
            {
              switch (nla->nla_type)
              {
                case IFLA_XDP_ATTACHED:
                  {

                    switch (*(uint8_t *)nla_data(nla))
                    {
                      case XDP_ATTACHED_NONE:
                        {
                          break;
                        }
                      case XDP_ATTACHED_MULTI:
                        {
                          break;
                        }
                      case XDP_ATTACHED_DRV:
                        {
                          break;
                        }
                      case XDP_ATTACHED_SKB:
                        {
                          break;
                        }
                      case XDP_ATTACHED_HW:
                        {
                          break;
                        }
                      default:
                        {
                          break;
                        }
                    }

                    break;
                  }
                case IFLA_XDP_PROG_ID:
                  {
                    break;
                  }
                default:
                  {
                    break;
                  }
              }
            }

            break;
          }
        case IFLA_PARENT_DEV_NAME:
          {
            break;
          }
        case IFLA_PARENT_DEV_BUS_NAME:
          {
            break;
          }
        default:
          {
            break;
          }
      }
    }
  }

  void printIfinfomsg(struct ifinfomsg *ifm)
  {


    switch (ifm->ifi_family)
    {
      case AF_UNSPEC:
        {
          break;
        }
      case IFLA_ADDRESS:
        {
          break;
        }
      case IFLA_BROADCAST:
        {
          break;
        }
      case IFLA_IFNAME:
        {
          break;
        }
      case IFLA_MTU:
        {
          break;
        }
      case IFLA_LINK:
        {
          break;
        }
      default:
        {
          break;
        }
    }



    if (ifm->ifi_flags > 0)
    {
      if (ifm->ifi_flags & IFF_UP)
      {
      }
      if (ifm->ifi_flags & IFF_BROADCAST)
      {
      }
      if (ifm->ifi_flags & IFF_DEBUG)
      {
      }
      if (ifm->ifi_flags & IFF_LOOPBACK)
      {
      }
      if (ifm->ifi_flags & IFF_POINTOPOINT)
      {
      }
      if (ifm->ifi_flags & IFF_RUNNING)
      {
      }
      if (ifm->ifi_flags & IFF_NOARP)
      {
      }
      if (ifm->ifi_flags & IFF_PROMISC)
      {
      }
      if (ifm->ifi_flags & IFF_NOTRAILERS)
      {
      }
      if (ifm->ifi_flags & IFF_ALLMULTI)
      {
      }
      if (ifm->ifi_flags & IFF_MASTER)
      {
      }
      if (ifm->ifi_flags & IFF_SLAVE)
      {
      }
      if (ifm->ifi_flags & IFF_MULTICAST)
      {
      }
      if (ifm->ifi_flags & IFF_PORTSEL)
      {
      }
      if (ifm->ifi_flags & IFF_AUTOMEDIA)
      {
      }
      if (ifm->ifi_flags & IFF_DYNAMIC)
      {
      }

    }

  }

  void printIfaAttributes(uint8_t *attrs, uint32_t len)
  {

    struct rtattr *attr = reinterpret_cast<struct rtattr *>(attrs);
    int attrlen = len;

    for (; RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen))
    {

      switch (attr->rta_type)
      {
        case IFA_UNSPEC:
          {
            break;
          }
        case IFA_ADDRESS:
          {
            break;
          }
        case IFA_LOCAL:
          {
            break;
          }
        case IFA_LABEL:
          {
            break;
          }
        case IFA_BROADCAST:
          {
            break;
          }
        case IFA_ANYCAST:
          {
            break;
          }
        case IFA_CACHEINFO:
          {
            // struct ifa_cacheinfo
            break;
          }
        case IFA_MULTICAST:
          {
            break;
          }
        case IFA_FLAGS:
          {
            uint32_t ifa_flags = *(uint32_t *)RTA_DATA(attr);
            if (ifa_flags & IFF_UP)
            {
            }
            if (ifa_flags & IFF_BROADCAST)
            {
            }
            if (ifa_flags & IFF_DEBUG)
            {
            }
            if (ifa_flags & IFF_LOOPBACK)
            {
            }
            if (ifa_flags & IFF_POINTOPOINT)
            {
            }
            if (ifa_flags & IFF_RUNNING)
            {
            }
            if (ifa_flags & IFF_NOARP)
            {
            }
            if (ifa_flags & IFF_PROMISC)
            {
            }
            if (ifa_flags & IFF_NOTRAILERS)
            {
            }
            if (ifa_flags & IFF_ALLMULTI)
            {
            }
            if (ifa_flags & IFF_MASTER)
            {
            }
            break;
          }
        case IFA_RT_PRIORITY:
          {
            break;
          }
        case IFA_TARGET_NETNSID:
          {
            break;
          }
        case IFA_PROTO:
          {
            switch (*(uint8_t *)RTA_DATA(attr))
            {
              case IFAPROT_UNSPEC:
                {
                  break;
                }
              case IFAPROT_KERNEL_LO: // loopback
                {
                  break;
                }
              case IFAPROT_KERNEL_RA: // set by kernel from router announcement
                {
                  break;
                }
              case IFAPROT_KERNEL_LL: // link-local set by kernel
                {
                  break;
                }
              default:
                {
                  break;
                }
            }

            break;
          }
        default:
          {
            break;
          }
      }
    }
  }

  void printIfaddrmsg(struct ifaddrmsg *ifa)
  {


    switch (ifa->ifa_family)
    {
      case AF_INET:
        {
          break;
        }
      case AF_INET6:
        {
          break;
        }
      default:
        {
          break;
        }
    }


    if (ifa->ifa_flags > 0)
    {
      if (ifa->ifa_flags & IFF_UP)
      {
      }
      if (ifa->ifa_flags & IFF_BROADCAST)
      {
      }
      if (ifa->ifa_flags & IFF_DEBUG)
      {
      }
      if (ifa->ifa_flags & IFF_LOOPBACK)
      {
      }
      if (ifa->ifa_flags & IFF_POINTOPOINT)
      {
      }
      if (ifa->ifa_flags & IFF_RUNNING)
      {
      }
      if (ifa->ifa_flags & IFF_NOARP)
      {
      }
      if (ifa->ifa_flags & IFF_PROMISC)
      {
      }
      if (ifa->ifa_flags & IFF_NOTRAILERS)
      {
      }
      if (ifa->ifa_flags & IFF_ALLMULTI)
      {
      }
      if (ifa->ifa_flags & IFF_MASTER)
      {
      }
    }


    switch (ifa->ifa_scope)
    {
      case RT_SCOPE_UNIVERSE:
        {
          break;
        }
      case RT_SCOPE_SITE:
        {
          break;
        }
      case RT_SCOPE_LINK:
        {
          break;
        }
      case RT_SCOPE_HOST:
        {
          break;
        }
      case RT_SCOPE_NOWHERE:
        {
          break;
        }
    }

  }

  void printNetnsaAttributes(uint8_t *attrs, uint32_t len)
  {

    struct rtattr *attr = reinterpret_cast<struct rtattr *>(attrs);
    int attrlen = len;

    for (; RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen))
    {

      switch (attr->rta_type)
      {
        case NETNSA_FD:
          {
            break;
          }
        case NETNSA_PID:
          {
            break;
          }
        case NETNSA_NSID:
          {
            break;
          }
        case NETNSA_TARGET_NSID:
          {
            break;
          }
        default:
          {
            break;
          }
      }
    }
  }

  void printNetlinkMessage(struct nlmsghdr *h)
  {
    // struct nlmsghdr {
    // 	__u32 nlmsg_len;    /* Length of message including header */
    //    __u16 nlmsg_type;   /* Type of message content */
    //    __u16 nlmsg_flags;  /* Additional flags */
    //    __u32 nlmsg_seq;    /* Sequence number */
    //    __u32 nlmsg_pid;    /* Sender port ID */
    // };


    bool isNew = false;
    bool isAck = false;


    switch (h->nlmsg_type)
    {
      case NLMSG_NOOP:
        {
          break;
        }
      case NLMSG_ERROR:
        {
          struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
          isAck = true;

          if (err->error == 0)
          {
          }
          else
          {

            if (h->nlmsg_flags & NLM_F_ACK_TLVS)
            {
            }
          }

          break;
        }
      case NLMSG_DONE:
        {
          break;
        }
      case RTM_NEWLINK:
        {
          isNew = true;

          struct ifinfomsg *ifm = (struct ifinfomsg *)NLMSG_DATA(h);
          printIfinfomsg(ifm);
          printIflaAttributes((uint8_t *)ifm + sizeof(struct ifinfomsg), h->nlmsg_len - sizeof(struct ifinfomsg));
          break;
        }
      case RTM_NEWADDR:
        {
          isNew = true;

          struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(h);
          printIfaddrmsg(ifa);
          printIfaAttributes((uint8_t *)ifa + sizeof(struct ifaddrmsg), h->nlmsg_len - sizeof(struct ifaddrmsg));
          break;
        }
      case RTM_NEWROUTE:
        {
          isNew = true;
          break;
        }
      case RTM_NEWNSID:
        {

          struct rtgenmsg *rtg = (struct rtgenmsg *)NLMSG_DATA(h);
          // printRtgenmsg(rtg);
          printNetnsaAttributes((uint8_t *)rtg + sizeof(struct rtgenmsg), h->nlmsg_len - sizeof(struct rtgenmsg));
          break;
        }
      case RTM_DELADDR:
        {
          break;
        }
      case RTM_GETADDR:
        {
          break;
        }
      case RTM_DELROUTE:
        {
          break;
        }
      case RTM_GETROUTE:
        {
          break;
        }
      case RTM_DELLINK:
        {
          break;
        }
      case RTM_GETLINK:
        {
          break;
        }
      case RTM_GETNSID:
        {
          break;
        }
      default:
        {
          break;
        }
    }

    if (h->nlmsg_flags > 0)
    {

      if (h->nlmsg_flags & NLM_F_REQUEST)
      {
      }
      if (h->nlmsg_flags & NLM_F_MULTI)
      {
      }
      if (h->nlmsg_flags & NLM_F_ACK)
      {
      }
      if (h->nlmsg_flags & NLM_F_ECHO)
      {
      }
      if (h->nlmsg_flags & NLM_F_DUMP_INTR)
      {
      }
      if (h->nlmsg_flags & NLM_F_DUMP_FILTERED)
      {
      }

      if (isNew)
      {
        if (h->nlmsg_flags & NLM_F_REPLACE)
        {
        }
        if (h->nlmsg_flags & NLM_F_EXCL)
        {
        }
        if (h->nlmsg_flags & NLM_F_CREATE)
        {
        }
        if (h->nlmsg_flags & NLM_F_APPEND)
        {
        }
      }
      else if (isAck)
      {
        if (h->nlmsg_flags & NLM_F_CAPPED)
        {
        }
        if (h->nlmsg_flags & NLM_F_ACK_TLVS)
        {
        }
      }

      // if (isGet)
      // {
      // }
      // else if (isDelete)
      // {
      // }

    }

  }
};

class NetlinkStream {
public:

  struct AsyncFlushOptions {
    uint32_t maxRequests = 16;
    uint64_t timeoutMs = 10'000;
    bool forceAsync = true;
  };

  using AsyncCompletion = std::function<void(int)>;
  using AsyncResponseHandler = std::function<void(uint16_t, uint32_t, void *, uint32_t)>;

private:
  struct ResourceState {
    // One stream response plus a bounded async batch and its receive buffer.
    // Sixteen bounded requests, the synchronous response buffer, and one
    // transaction receive buffer.
    Pool<NetlinkMessage> messagePool {18};
    NetlinkSocket socket;

    ~ResourceState()
    {
      socket.close();
    }
  };

  class AsyncResourceClose : public RingInterface {
  private:
    std::shared_ptr<ResourceState> resource;

    explicit AsyncResourceClose(std::shared_ptr<ResourceState> value)
        : resource(std::move(value))
    {}

  public:
    static void begin(std::shared_ptr<ResourceState> resource)
    {
      AsyncResourceClose *owner = new AsyncResourceClose(std::move(resource));
      RingDispatcher::installMultiplexee(&owner->resource->socket, owner);
      Ring::queueClose(&owner->resource->socket, true);
    }

    void closeHandler(void *) override
    {
      RingDispatcher::eraseMultiplexee(&resource->socket);
      delete this;
    }
  };

  class AsyncFlush;
  struct AsyncFlushControl {
    AsyncFlush *flush = nullptr;
    bool completed = false;
    void cancel();
  };
  std::shared_ptr<ResourceState> resources;

public:
  class AsyncFlushHandle {
  private:
    std::shared_ptr<AsyncFlushControl> control;
    explicit AsyncFlushHandle(std::shared_ptr<AsyncFlushControl> value) : control(std::move(value)) {}
    friend class NetlinkStream;

  public:
    AsyncFlushHandle() = default;
    bool valid() const { return control != nullptr && control->completed == false; }
    void cancel() const { if (control) control->cancel(); }
  };

  Pool<NetlinkMessage>& messagePool;
  Vector<NetlinkMessage *> pendingRequests;
  bool requestAdmissionFailed = false;

  NetlinkSocket& socket;

  NetlinkMessage *response = nullptr;
  uint32_t responseCursor = 0;
  uint32_t nPendingResponses = 0;

private:
  AsyncFlush *activeFlush = nullptr;
  uint32_t nextAsyncSequence = 0;

public:

  template <typename Requester>
  bool generateRequest(Requester&& requester)
  {
    if (activeFlush != nullptr)
    {
      return false;
    }
    NetlinkMessage *request = messagePool.get();
    if (request == nullptr)
    {
      requestAdmissionFailed = true;
      return false;
    }

    requester(request);

    pendingRequests.push_back(request);
    return true;
  }

  template <typename Handler>
  void readResponse(Handler&& handler) // read one response
  {
    if (activeFlush != nullptr)
    {
      return;
    }
    if (responseCursor == 0)
    {
      response->setPayloadMax();

      int result = socket.recvmsg(reinterpret_cast<struct msghdr *>(response));

      if (result > 0)
      {
        response->setPayloadLen(result);
      }
      else
      {
        return;
      }
    }

    // more data to consume... we also need to wait for the done if its a multi
    socket.unsafeHandleMessage(reinterpret_cast<struct msghdr *>(response), responseCursor, std::forward<Handler>(handler));

    if (responseCursor == response->payloadLen())
    {
      response->reset();
      responseCursor = 0;
    }

    --nPendingResponses;
  }

  void flush(void)
  {
    if (activeFlush != nullptr)
    {
      return;
    }
    for (NetlinkMessage *request : pendingRequests)
    {
      if (socket.sendmsg(reinterpret_cast<struct msghdr *>(request)) < 0)
      {
      }
      else
      {
        ++nPendingResponses;
      }

      request->reset();
      messagePool.relinquish(request);
    }

    pendingRequests.clear();
  }

  bool flushChecked(void)
  {
    if (activeFlush != nullptr)
    {
      return false;
    }
    bool ok = true;

    for (NetlinkMessage *request : pendingRequests)
    {
      if (socket.sendmsg(reinterpret_cast<struct msghdr *>(request)) < 0)
      {
        ok = false;
      }
      else
      {
        ++nPendingResponses;
      }

      request->reset();
      messagePool.relinquish(request);
    }

    pendingRequests.clear();
    return ok;
  }

  void discardResponses(void)
  {
    while (nPendingResponses > 0)
    {
      readResponse([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t len) -> void {
      });
    }
  }

  template <typename Handler>
  bool readResponseChecked(Handler&& handler) // read one response and surface netlink errors
  {
    if (activeFlush != nullptr)
    {
      return false;
    }
    if (responseCursor == 0)
    {
      response->setPayloadMax();

      int result = socket.recvmsg(reinterpret_cast<struct msghdr *>(response));

      if (result > 0)
      {
        response->setPayloadLen(result);
      }
      else
      {
        return false;
      }
    }

    uint32_t retrySeq = UINT32_MAX;
    socket.handleMessage(reinterpret_cast<struct msghdr *>(response), responseCursor, retrySeq, std::forward<Handler>(handler));

    if (responseCursor == response->payloadLen())
    {
      response->reset();
      responseCursor = 0;
    }

    --nPendingResponses;
    return (retrySeq == UINT32_MAX);
  }

  bool discardResponsesChecked(void)
  {
    bool ok = true;

    while (nPendingResponses > 0)
    {
      if (readResponseChecked([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t len) -> void {
          }) == false)
      {
        ok = false;
      }
    }

    return ok;
  }

  void flushDiscard(void)
  {
    flush();
    discardResponses();
  }

  bool flushDiscardChecked(void)
  {
    bool sent = flushChecked();
    bool received = discardResponsesChecked();
    return sent && received;
  }

  AsyncFlushHandle flushAsync(AsyncCompletion completion,
                              AsyncResponseHandler responseHandler,
                              AsyncFlushOptions options);

  AsyncFlushHandle flushAsync(AsyncCompletion completion,
                              AsyncResponseHandler responseHandler = {})
  {
    return flushAsync(std::move(completion), std::move(responseHandler), AsyncFlushOptions{});
  }

  NetlinkStream()
      : resources(std::make_shared<ResourceState>()),
        messagePool(resources->messagePool),
        socket(resources->socket)
  {
    response = messagePool.get();
  }

  ~NetlinkStream();
};

class NetlinkStream::AsyncFlush : public RingInterface {
private:
  static bool isDumpRequest(const struct nlmsghdr *header)
  {
    if ((header->nlmsg_flags & NLM_F_DUMP) != NLM_F_DUMP)
    {
      return false;
    }

    // NLM_F_ROOT/MATCH reuse the NEW-operation REPLACE/EXCL bit positions.
    // Only RTNL GET requests therefore use them as a multipart dump request.
    switch (header->nlmsg_type)
    {
      case RTM_GETLINK:
      case RTM_GETADDR:
      case RTM_GETROUTE:
      case RTM_GETNEIGH:
      case RTM_GETRULE:
      case RTM_GETQDISC:
      case RTM_GETTCLASS:
      case RTM_GETTFILTER:
      case RTM_GETACTION:
      case RTM_GETNEIGHTBL:
      case RTM_GETNSID:
        return true;
      default:
        return false;
    }
  }

  NetlinkStream *origin;
  std::shared_ptr<ResourceState> resources;
  std::shared_ptr<AsyncFlushControl> control;
  AsyncCompletion completion;
  AsyncResponseHandler responseHandler;
  AsyncFlushOptions options;
  Vector<NetlinkMessage *> requests;
  NetlinkMessage *receiveBuffer = nullptr;
  struct ResponseExpectation {
    bool requiresDone = false;
    bool requiresAck = false;
  };
  bytell_hash_map<uint32_t, ResponseExpectation> waitingForDone;
  bytell_hash_set<uint32_t> settledSequences;
  Vector<uint64_t> tickets;
  TimeoutPacket timer;
  bool timerArmed = false;
  bool timerCancellationRequested = false;
  bool resourceCloseQueued = false;
  bool resourceCloseComplete = false;
  uint32_t sendsOutstanding = 0;
  uint64_t receiveTicket = 0;
  int status = 0;
  bool delivering = false;
  bool dispatchingResponse = false;

  void fail(int result)
  {
    if (status != 0)
    {
      return;
    }
    status = result < 0 ? result : -EPROTO;

    for (uint64_t ticket : tickets)
    {
      Ring::queueCancelMsghdr(ticket);
    }
    if (receiveTicket != 0)
    {
      Ring::queueCancelMsghdr(receiveTicket);
    }
    cancelTimer();
  }

  void cancelTimer()
  {
    if (timerArmed && timerCancellationRequested == false)
    {
      timerCancellationRequested = true;
      Ring::queueCancelTimeout(&timer);
    }
  }

  void maybeDeliver()
  {
    if (delivering || dispatchingResponse || sendsOutstanding != 0 || receiveTicket != 0 || timerArmed)
    {
      return;
    }
    if (origin == nullptr && resourceCloseQueued == false && resources->socket.fd >= 0)
    {
      resourceCloseQueued = true;
      RingDispatcher::installMultiplexee(&resources->socket, this);
      Ring::queueClose(&resources->socket, true);
      return;
    }
    if (resourceCloseQueued && resourceCloseComplete == false)
    {
      return;
    }
    if (status == 0 && waitingForDone.empty() == false)
    {
      return;
    }

    delivering = true;
    control->flush = nullptr;
    control->completed = true;
    RingDispatcher::eraseMultiplexee(this);
    RingDispatcher::eraseMultiplexee(&resources->socket);
    for (NetlinkMessage *request : requests)
    {
      request->reset();
      resources->messagePool.relinquish(request);
    }
    if (receiveBuffer)
    {
      receiveBuffer->reset();
      resources->messagePool.relinquish(receiveBuffer);
      receiveBuffer = nullptr;
    }
    if (origin && origin->activeFlush == this)
    {
      origin->activeFlush = nullptr;
    }
    AsyncCompletion delivered = std::move(completion);
    const int result = status;
    delete this;
    if (delivered)
    {
      delivered(result);
    }
  }

  void queueReceive()
  {
    if (status != 0 || receiveTicket != 0 || waitingForDone.empty())
    {
      maybeDeliver();
      return;
    }

    receiveBuffer->setPayloadMax();
    receiveTicket = Ring::queueRecvmsg(&resources->socket,
                                        reinterpret_cast<struct msghdr *>(receiveBuffer),
                                        this,
                                        options.forceAsync);
    if (receiveTicket == 0)
    {
      fail(-EBADF);
      maybeDeliver();
    }
  }

  void onResponse(struct msghdr *msg, int result)
  {
    receiveTicket = 0;
    if (result <= 0)
    {
      fail(result == 0 ? -ECONNRESET : result);
      maybeDeliver();
      return;
    }

    bool protocolError = false;
    dispatchingResponse = true;
    const bool wellFormed = NetlinkSocket::visitCheckedMessages(
        msg,
        uint32_t(result),
        [&](struct nlmsghdr *header) {
          if (protocolError || status != 0)
          {
            return;
          }
          auto waiting = waitingForDone.find(header->nlmsg_seq);
          if (waiting == waitingForDone.end())
          {
            if (header->nlmsg_type == NLMSG_ERROR &&
                settledSequences.contains(header->nlmsg_seq) &&
                header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)) &&
                static_cast<const struct nlmsgerr *>(NLMSG_DATA(header))->error == 0)
            {
              return;
            }
            protocolError = true;
            return;
          }

          if (header->nlmsg_type == NLMSG_ERROR)
          {
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
            {
              protocolError = true;
              return;
            }
            const auto *error = static_cast<const struct nlmsgerr *>(NLMSG_DATA(header));
            if (error->error != 0)
            {
              fail(error->error);
              return;
            }
            if (waiting->second.requiresDone == false)
            {
              settledSequences.insert(header->nlmsg_seq);
              waitingForDone.erase(waiting);
            }
            return;
          }

          if (header->nlmsg_type == NLMSG_DONE)
          {
            if (header->nlmsg_flags & NLM_F_DUMP_INTR)
            {
              fail(-EINTR);
              return;
            }
            if (waiting->second.requiresDone == false)
            {
              protocolError = true;
              return;
            }
            if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(int)))
            {
              const int doneError = *static_cast<const int *>(NLMSG_DATA(header));
              if (doneError < 0)
              {
                fail(doneError);
                return;
              }
            }
            settledSequences.insert(header->nlmsg_seq);
            waitingForDone.erase(waiting);
            return;
          }

          if (header->nlmsg_flags & NLM_F_DUMP_INTR)
          {
            fail(-EINTR);
            return;
          }

          if (responseHandler)
          {
            responseHandler(header->nlmsg_type,
                            header->nlmsg_seq,
                            NLMSG_DATA(header),
                            header->nlmsg_len);
          }
          if (waiting->second.requiresDone == false && waiting->second.requiresAck == false)
          {
            settledSequences.insert(header->nlmsg_seq);
            waitingForDone.erase(waiting);
          }
        });
    dispatchingResponse = false;

    if (wellFormed == false || protocolError)
    {
      fail(-EPROTO);
    }
    if (status != 0 || waitingForDone.empty())
    {
      cancelTimer();
      maybeDeliver();
      return;
    }
    queueReceive();
  }

  void armTimer()
  {
    if (options.timeoutMs == 0)
    {
      return;
    }
    timer.clear();
    timer.setTimeoutMs(options.timeoutMs);
    timer.originator = this;
    Ring::queueTimeout(&timer);
    timerArmed = true;
  }

public:
  AsyncFlush(NetlinkStream *owner,
             std::shared_ptr<ResourceState> resourceValues,
             Vector<NetlinkMessage *> requestValues,
             std::shared_ptr<AsyncFlushControl> state,
             AsyncCompletion completionValue,
             AsyncResponseHandler responseValue,
             AsyncFlushOptions optionsValue)
      : origin(owner),
        resources(std::move(resourceValues)),
        control(std::move(state)),
        completion(std::move(completionValue)),
        responseHandler(std::move(responseValue)),
        options(optionsValue),
        requests(std::move(requestValues))
  {}

  void begin()
  {
    receiveBuffer = resources->messagePool.get();
    if (receiveBuffer == nullptr)
    {
      status = -ENOBUFS;
      maybeDeliver();
      return;
    }
    RingDispatcher::installMultiplexee(this, this);
    armTimer();

    for (NetlinkMessage *request : requests)
    {
      if (request->payloadLen() < sizeof(struct nlmsghdr))
      {
        fail(-EINVAL);
        break;
      }
      struct nlmsghdr *header = reinterpret_cast<struct nlmsghdr *>(request->data);
      if (header->nlmsg_len < sizeof(struct nlmsghdr) || header->nlmsg_len > request->payloadLen())
      {
        fail(-EINVAL);
        break;
      }
      ++origin->nextAsyncSequence;
      if (origin->nextAsyncSequence == 0)
      {
        ++origin->nextAsyncSequence;
      }
      header->nlmsg_seq = origin->nextAsyncSequence;
      waitingForDone.insert_or_assign(header->nlmsg_seq, ResponseExpectation {
          .requiresDone = isDumpRequest(header),
          .requiresAck = (header->nlmsg_flags & NLM_F_ACK) != 0
      });
      ++sendsOutstanding;
      uint64_t ticket = Ring::queueSendmsg(&resources->socket,
                                            reinterpret_cast<struct msghdr *>(request),
                                            this,
                                            options.forceAsync);
      if (ticket == 0)
      {
        --sendsOutstanding;
        fail(-EBADF);
        break;
      }
      tickets.push_back(ticket);
    }
    if (status != 0)
    {
      maybeDeliver();
    }
  }

  void cancel()
  {
    fail(-ECANCELED);
    maybeDeliver();
  }

  void detach()
  {
    completion = {};
    responseHandler = {};
    if (origin && origin->activeFlush == this)
    {
      origin->activeFlush = nullptr;
    }
    origin = nullptr;
    fail(-ECANCELED);
    maybeDeliver();
  }

  void sendmsgHandler(void *, struct msghdr *msg, int result) override
  {
    if (sendsOutstanding > 0)
    {
      --sendsOutstanding;
    }
    if (result < 0)
    {
      fail(result);
    }
    else if (msg == nullptr || msg->msg_iov == nullptr || msg->msg_iovlen == 0 ||
             uint64_t(result) != msg->msg_iov[0].iov_len)
    {
      fail(-EIO);
    }
    if (sendsOutstanding == 0)
    {
      if (status == 0)
      {
        queueReceive();
      }
      else
      {
        maybeDeliver();
      }
    }
  }

  void recvmsgHandler(void *, struct msghdr *msg, int result) override
  {
    onResponse(msg, result);
  }

  void timeoutHandler(TimeoutPacket *, int result) override
  {
    timerArmed = false;
    timerCancellationRequested = false;
    if (result == -ETIME && status == 0)
    {
      fail(-ETIMEDOUT);
    }
    maybeDeliver();
  }

  void closeHandler(void *) override
  {
    resourceCloseComplete = true;
    maybeDeliver();
  }
};

inline void NetlinkStream::AsyncFlushControl::cancel()
{
  if (flush && completed == false)
  {
    flush->cancel();
  }
}

inline NetlinkStream::AsyncFlushHandle NetlinkStream::flushAsync(
    AsyncCompletion completion,
    AsyncResponseHandler responseHandler,
    AsyncFlushOptions options)
{
  if (activeFlush != nullptr)
  {
    if (completion) completion(-EBUSY);
    return {};
  }
  if (nPendingResponses != 0 || responseCursor != 0)
  {
    if (completion) completion(-EBUSY);
    return {};
  }
  if (requestAdmissionFailed)
  {
    if (completion) completion(-ENOBUFS);
    return {};
  }
  if (options.maxRequests == 0 || options.maxRequests > 16 || pendingRequests.size() > options.maxRequests)
  {
    if (completion) completion(-E2BIG);
    return {};
  }
  if (pendingRequests.empty())
  {
    if (completion) completion(0);
    return {};
  }

  if (socket.fd < 0)
  {
    if (completion) completion(-EBADF);
    return {};
  }

  Vector<NetlinkMessage *> requests = std::move(pendingRequests);
  pendingRequests.clear();

  auto control = std::make_shared<AsyncFlushControl>();
  AsyncFlush *flush = new AsyncFlush(this, resources, std::move(requests), control, std::move(completion), std::move(responseHandler), options);
  control->flush = flush;
  activeFlush = flush;
  flush->begin();
  return AsyncFlushHandle(std::move(control));
}

inline NetlinkStream::~NetlinkStream()
{
  if (activeFlush)
  {
    activeFlush->detach();
  }
  else if (resources && resources->socket.fd >= 0 &&
           Ring::getRingFD() > 0 && Ring::shuttingDown == false)
  {
    AsyncResourceClose::begin(std::move(resources));
  }
}

class NetDevice : public NetlinkStream {
private:

  bytell_hash_map<int, BPFProgram *> bpf_progs;
  uint32_t xdp_flags = 0;

public:

  String name;
  uint32_t ifidx;
  uint32_t mtu = 0;
  uint8_t mac[6];

  template <StringType T, StringType X, typename MapOfMapsSeeder>
  BPFProgram *attachXDP(T&& progpath, X&& progname, uint32_t xdp_flags, MapOfMapsSeeder&& seeder)
  {
    BPFProgram *prog = nullptr;

    if (bpf_progs.contains(BPF_XDP) == false)
    {
      prog = new BPFProgram();
      if (prog->load(std::forward<T>(progpath), std::forward<X>(progname), std::forward<MapOfMapsSeeder>(seeder)) == false)
      {
        delete prog;
        return nullptr;
      }

      generateRequest([&](NetlinkMessage *request) -> void {
        socket.attachXDPProgToInterface(request, 0, ifidx, prog->prog_fd, xdp_flags);
      });

      if (flushDiscardChecked() == false)
      {
        delete prog;
        return nullptr;
      }

      this->xdp_flags = (xdp_flags & XDP_FLAGS_MODES);
      bpf_progs[BPF_XDP] = prog;
    }

    return prog;
  }

  template <StringType T, StringType X>
  BPFProgram *attachXDP(T&& progpath, X&& progname, uint32_t xdp_flags)
  {
    return attachXDP(std::forward<T>(progpath), std::forward<X>(progname), xdp_flags, [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
    });
  }

  void detachXDP(void)
  {
    if (auto it = bpf_progs.find(BPF_XDP); it != bpf_progs.end())
    {
      BPFProgram *prog = it->second;
      delete prog;

      bpf_progs.erase(it);

      int result = bpf_xdp_detach(ifidx, xdp_flags, nullptr);
      if (result != 0)
      {
        basics_log("NetDevice::detachXDP failed ifidx=%u flags=%u result=%d errno=%d\n",
          ifidx,
          xdp_flags,
          result,
          errno);
      }
      xdp_flags = 0;
    }
  }

  // we have to pass the progpath because the kernel doesn't buffer the full ELF file when loading it
  // we can only get the full info from the .o file
  BPFProgram *loadPreattachedProgram(enum bpf_attach_type progtype, StringType auto&& progpath)
  {
      uint32_t prog_id = 0;
      if (progtype == BPF_XDP)
      {
        static constexpr uint32_t xdpQueryModes[] = {
          XDP_FLAGS_DRV_MODE,
          XDP_FLAGS_SKB_MODE,
          0
        };

        bool foundXDP = false;
        for (uint32_t queryFlags : xdpQueryModes)
        {
          prog_id = 0;
          if (bpf_xdp_query_id(ifidx, queryFlags, &prog_id) == 0 && prog_id != 0)
          {
            xdp_flags = (queryFlags & XDP_FLAGS_MODES);
            foundXDP = true;
            break;
          }
        }

        if (foundXDP == false)
        {
          basics_log("NetDevice::loadPreattachedProgram XDP query failed ifidx=%u errno=%d\n",
            ifidx,
            errno);
          return nullptr;
        }
      }
      else
      {
        uint32_t prog_cnt = 1;

        struct bpf_prog_query_opts opts = {};
        opts.sz = sizeof(opts);
        opts.prog_ids = &prog_id;
        opts.prog_cnt = prog_cnt;

        if (bpf_prog_query_opts(ifidx, progtype, &opts) != 0 || prog_id == 0)
        {
          return nullptr;
        }
      }

    BPFProgram *prog = new BPFProgram();
    if (prog->loadPreattached(progtype, ifidx, prog_id, progpath) == false)
    {
      delete prog;
      return nullptr;
    }
    bpf_progs[progtype] = prog;

    return prog;
  }

  template <StringType T, StringType X>
  BPFProgram *attachBPF(enum bpf_attach_type progtype, T&& progpath, X&& progname)
  {
    return attachBPF(progtype, std::forward<T>(progpath), std::forward<X>(progname), [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
    });
  }

  template <StringType T, StringType X, typename MapSeeder>
  BPFProgram *attachBPF(enum bpf_attach_type progtype, T&& progpath, X&& progname, MapSeeder&& seeder)
  {
    BPFProgram *prog = nullptr;

    if (bpf_progs.contains(progtype) == false)
    {
      prog = new BPFProgram();
      if (prog->loadAttach(progtype, ifidx, std::forward<T>(progpath), std::forward<X>(progname), std::forward<MapSeeder>(seeder)) == false)
      {
        delete prog;
        return nullptr;
      }
      bpf_progs[progtype] = prog;
    }
    else
    {
      prog = bpf_progs[progtype];
    }

    return prog;
  }

  void detachBPF(enum bpf_attach_type progtype)
  {
    if (auto it = bpf_progs.find(progtype); it != bpf_progs.end())
    {
      BPFProgram *prog = it->second;
      prog->detach();

      delete prog;

      bpf_progs.erase(it);
    }
  }

  void bringUp(void)
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.bringUpInterface(request, 0, ifidx);
    });

    flushDiscard();
  }

  NetlinkStream::AsyncFlushHandle bringUpAsync(NetlinkStream::AsyncCompletion completion,
                                               NetlinkStream::AsyncFlushOptions options = {})
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.bringUpInterface(request, 0, ifidx);
    });
    return flushAsync(std::move(completion), {}, options);
  }

  bool setMTU(uint32_t value)
  {
    if (ifidx == 0 || value == 0)
    {
      return false;
    }

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.setInterfaceMTU(request, 0, ifidx, value);
    });

    if (flushDiscardChecked() == false)
    {
      return false;
    }

    mtu = value;
    return true;
  }

  bool setPacketBudget(uint32_t mtuValue, uint32_t gsoMaxSegs = 0)
  {
    if (ifidx == 0 || mtuValue == 0)
    {
      return false;
    }

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.setInterfacePacketBudget(request, 0, ifidx, mtuValue, gsoMaxSegs);
    });

    if (flushDiscardChecked() == false)
    {
      return false;
    }

    mtu = mtuValue;
    return true;
  }

  NetlinkStream::AsyncFlushHandle setPacketBudgetAsync(
      uint32_t mtuValue,
      uint32_t gsoMaxSegs,
      NetlinkStream::AsyncCompletion completion,
      NetlinkStream::AsyncFlushOptions options = {})
  {
    if (ifidx == 0 || mtuValue == 0)
    {
      if (completion) completion(-EINVAL);
      return {};
    }

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.setInterfacePacketBudget(request, 0, ifidx, mtuValue, gsoMaxSegs);
    });
    return flushAsync(
        [this, mtuValue, completion = std::move(completion)](int result) mutable {
          if (result == 0)
          {
            mtu = mtuValue;
          }
          if (completion) completion(result);
        },
        {},
        options);
  }

  NetlinkStream::AsyncFlushHandle setPacketBudgetAsync(
      uint32_t mtuValue,
      NetlinkStream::AsyncCompletion completion,
      uint32_t gsoMaxSegs = 0,
      NetlinkStream::AsyncFlushOptions options = {})
  {
    return setPacketBudgetAsync(mtuValue, gsoMaxSegs, std::move(completion), options);
  }

  void addIP(StringType auto&& address, uint8_t cidr, int ip_version)
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.addIPtoInterface(request, 0, address, cidr, ip_version == AF_INET6, ifidx);
    });

    flushDiscard();
  }

  void addIP(const IPPrefix& prefix)
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.addIPtoInterface(request, 0, prefix, ifidx);
    });

    flushDiscard();
  }

  void removeIP(StringType auto&& address, uint8_t cidr, int ip_version)
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.removeIPFromInterface(request, 0, address, cidr, ip_version == AF_INET6, ifidx);
    });

    flushDiscard(); // Send the request and discard the response
  }

  void addIndirectRoute(StringType auto&& networkAddr, uint8_t cidr, int ip_version, IPAddress& gateway, IPAddress& prefsrc)
  {
    IPPrefix network;
    network.network.is6 = (ip_version == AF_INET6);

    if (networkAddr.size() > 0)
    {
      int result = inet_pton(ip_version, networkAddr.c_str(), network.network.v6);
      network.cidr = cidr;
    }

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.addRoute(request, 0, ifidx, network, gateway, prefsrc);
    });

    flushDiscard();
  }

  void addIndirectRoute(StringType auto&& networkAddr, uint8_t cidr, int ip_version, StringType auto&& gatewayAddr, StringType auto&& prefSrcAddr)
  {
    IPAddress gateway;

    if (gatewayAddr.size() > 0)
    {
      inet_pton(ip_version, gatewayAddr.c_str(), gateway.v6);
      gateway.is6 = (ip_version == AF_INET6);
    }

    IPAddress prefsrc;

    if (prefSrcAddr.size() > 0)
    {
      inet_pton(ip_version, prefSrcAddr.c_str(), prefsrc.v6);
      prefsrc.is6 = (ip_version == AF_INET6);
    }

    addIndirectRoute(networkAddr, cidr, ip_version, gateway, prefsrc);
  }

  void addIndirectRoute(StringType auto&& networkAddr, uint8_t cidr, int ip_version, StringType auto&& gatewayAddr)
  {
    addIndirectRoute(networkAddr, cidr, ip_version, gatewayAddr, ""_ctv);
  }

  void addDirectRoute(StringType auto&& network, uint8_t cidr, int ip_version)
  {
    addIndirectRoute(network, cidr, ip_version, ""_ctv);
  }

  void addDefaultRoutes(void)
  {
    addDirectRoute(""_ctv, 0, AF_INET6);
    addDirectRoute(""_ctv, 0, AF_INET);
  }

  void getInfo(void)
  {
    ifidx = 0;
    mtu = 0;
    memset(mac, 0, sizeof(mac));

    if (name.size() > 0)
    {
      generateRequest([&](NetlinkMessage *request) -> void {
        socket.getInterface(request, 0, name);
      });

      if (flushChecked() == false)
      {
        return;
      }

      readResponseChecked([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) -> void {
        if (nlmsg_data)
        {
          struct ifinfomsg *ifm = (struct ifinfomsg *)nlmsg_data;
          ifidx = ifm->ifi_index;

          NetlinkSocket::parseAttributes(IFLA_RTA(ifm), nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)), [&](int type, void *data) -> void {
            if (type == IFLA_ADDRESS)
            {
              memcpy(mac, data, 6);
            }
            else if (type == IFLA_MTU)
            {
              mtu = *reinterpret_cast<uint32_t *>(data);
            }
          });
        }
      });
    }
  }

  NetlinkStream::AsyncFlushHandle getInfoAsync(NetlinkStream::AsyncCompletion completion,
                                               NetlinkStream::AsyncFlushOptions options = {})
  {
    ifidx = 0;
    mtu = 0;
    memset(mac, 0, sizeof(mac));
    if (name.size() == 0)
    {
      if (completion) completion(-EINVAL);
      return {};
    }

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.getInterface(request, 0, name);
    });
    return flushAsync(
        std::move(completion),
        [this](uint16_t, uint32_t, void *data, uint32_t length) {
          if (data == nullptr || length < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
          {
            return;
          }
          struct ifinfomsg *ifm = static_cast<struct ifinfomsg *>(data);
          ifidx = ifm->ifi_index;
          NetlinkSocket::parseAttributes(IFLA_RTA(ifm),
              int(length - NLMSG_LENGTH(sizeof(struct ifinfomsg))),
              [this](int type, void *attribute) {
                if (type == IFLA_ADDRESS)
                {
                  memcpy(mac, attribute, sizeof(mac));
                }
                else if (type == IFLA_MTU)
                {
                  mtu = *static_cast<uint32_t *>(attribute);
                }
              });
        },
        options);
  }

  bool moveSocketToNamespace(int netnsfd, int hostnetnsfd)
  {
    if (setns(netnsfd, CLONE_NEWNET) != 0)
    {
      return false;
    }

    socket.recreateSocket();
    const bool recreated = socket.fd >= 0;
    if (recreated)
    {
      socket.configure();
    }
    if (setns(hostnetnsfd, CLONE_NEWNET) != 0)
    {
      // Continuing on the peer namespace would make subsequent Ring work run
      // against the wrong network namespace.
      std::abort();
    }
    return recreated;
  }

  void thisNamespace(void)
  {
    socket.recreateSocket();
    socket.configure();
  }
};

class NetDevicePair : public NetlinkStream {
public:

  NetDevice host;
  NetDevice peer;

  bool areActive(void)
  {
    return (host.name.size() > 0); // if no names, not being used
  }

  virtual void setNames(const String& container_name) = 0; // do this before cloning

  virtual void createPair(int peernsfd) = 0;

  void getInfo(void)
  {
    host.ifidx = 0;
    peer.ifidx = 0;

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.getInterface(request, 0, host.name);
    });

    if (flushChecked() == false)
    {
      return;
    }

    readResponseChecked([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) -> void {
      if (nlmsg_data)
      {
        struct ifinfomsg *ifm = (struct ifinfomsg *)nlmsg_data;
        host.ifidx = ifm->ifi_index;

        NetlinkSocket::parseAttributes(IFLA_RTA(ifm), nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)), [&](int type, void *data) -> void {
          if (type == IFLA_LINK_NETNSID)
          {
            // it's a complete lie: you can't actually set the target namespace and operate from the host

            // peer.netnsid = *(uint32_t *)data;
          }
          else if (type == IFLA_LINK)
          {
            peer.ifidx = *(uint32_t *)data;
          }
        });
      }
    });
  }

  NetlinkStream::AsyncFlushHandle getInfoAsync(NetlinkStream::AsyncCompletion completion,
                                               NetlinkStream::AsyncFlushOptions options = {})
  {
    host.ifidx = 0;
    peer.ifidx = 0;
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.getInterface(request, 0, host.name);
    });
    return flushAsync(
        std::move(completion),
        [this](uint16_t, uint32_t, void *data, uint32_t length) {
          if (data == nullptr || length < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
          {
            return;
          }
          struct ifinfomsg *ifm = static_cast<struct ifinfomsg *>(data);
          host.ifidx = ifm->ifi_index;
          NetlinkSocket::parseAttributes(IFLA_RTA(ifm),
              int(length - NLMSG_LENGTH(sizeof(struct ifinfomsg))),
              [this](int type, void *attribute) {
                if (type == IFLA_LINK)
                {
                  peer.ifidx = *static_cast<uint32_t *>(attribute);
                }
              });
        },
        options);
  }

  void destroyPair(void)
  {
    if (host.ifidx > 0)
    {
      generateRequest([&](NetlinkMessage *request) -> void {
        socket.destroyNetDevice(request, 0, host.ifidx);
      });

      flushDiscard();
    }

    host.ifidx = 0;
    peer.ifidx = 0;
  }

  ~NetDevicePair()
  {
    destroyPair();
  }
};
