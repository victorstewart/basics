// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <networking/netlink.h>
#include <networking/arp.h>
#include <networking/private4.h>
#include <poll.h>
#include <fstream>
#include <sstream>

#pragma once

class EthDevice : public NetDevice {
public:

  uint8_t gateway_mac[6]; // this is the private 4 gateway mac... we could specify this better

  void setDevice(StringType auto&& device_name)
  {
    name.assign(device_name);

    getInfo();
  }

  uint32_t getPrivate4(void) // RFC1918 private IPv4
  {
    uint32_t private4 = 0;

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.getAddresses(request, 0, ifidx);
    });

    flush();

    readResponse([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) -> void {
      if (nlmsg_type == RTM_NEWADDR && nlmsg_data)
      {
        struct ifaddrmsg *ifa = reinterpret_cast<struct ifaddrmsg *>(nlmsg_data);

        NetlinkSocket::parseAttributes((uint8_t *)ifa + sizeof(struct ifaddrmsg), nlmsg_len - sizeof(struct ifaddrmsg),
                                       [&](int type, void *data) -> void {
                                         if (type == IFA_LOCAL && ifa->ifa_family == AF_INET)
                                         {
                                           uint32_t ipv4 = *reinterpret_cast<uint32_t *>(data);

                                           // Check if the address belongs to an RFC1918 private IPv4 subnet.
                                           if (::isRFC1918Private4(ipv4))
                                           {
                                             private4 = ipv4;
                                           }
                                         }
                                       });
      }
    });

    return private4;
  }

  IPAddress getGlobal6(void)
  {
    IPAddress global6;

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.getAddresses(request, 0, ifidx);
    });

    flush();

    readResponse([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) -> void {
      (void)nlmsg_seq;

      if (global6.isNull() == false)
      {
        return;
      }

      if (nlmsg_type == RTM_NEWADDR && nlmsg_data)
      {
        struct ifaddrmsg *ifa = reinterpret_cast<struct ifaddrmsg *>(nlmsg_data);

        NetlinkSocket::parseAttributes((uint8_t *)ifa + sizeof(struct ifaddrmsg), nlmsg_len - sizeof(struct ifaddrmsg),
                                       [&](int type, void *data) -> void {
                                         if (type != IFA_LOCAL || ifa->ifa_family != AF_INET6)
                                         {
                                           return;
                                         }

                                         uint8_t *ipv6 = reinterpret_cast<uint8_t *>(data);

                                         if ((ipv6[0] == 0xfe && (ipv6[1] & 0xc0) == 0x80) // link-local fe80::/10
                                             || ((ipv6[0] & 0xfe) == 0xfc) // unique-local fc00::/7
                                             || (memcmp(ipv6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0))
                                         {
                                           return;
                                         }

                                         memcpy(global6.v6, ipv6, 16);
                                         global6.is6 = true;
                                       });
      }
    });

    return global6;
  }

  IPAddress getPrivate6(void)
  {
    IPAddress private6;

    generateRequest([&](NetlinkMessage *request) -> void {
      socket.getAddresses(request, 0, ifidx);
    });

    flush();

    readResponse([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) -> void {
      (void)nlmsg_seq;

      if (private6.isNull() == false)
      {
        return;
      }

      if (nlmsg_type == RTM_NEWADDR && nlmsg_data)
      {
        struct ifaddrmsg *ifa = reinterpret_cast<struct ifaddrmsg *>(nlmsg_data);

        NetlinkSocket::parseAttributes((uint8_t *)ifa + sizeof(struct ifaddrmsg), nlmsg_len - sizeof(struct ifaddrmsg),
                                       [&](int type, void *data) -> void {
                                         if (type != IFA_LOCAL || ifa->ifa_family != AF_INET6)
                                         {
                                           return;
                                         }

                                         uint8_t *ipv6 = reinterpret_cast<uint8_t *>(data);

                                         if ((ipv6[0] & 0xfe) != 0xfc)
                                         {
                                           return;
                                         }

                                         memcpy(private6.v6, ipv6, 16);
                                         private6.is6 = true;
                                       });
      }
    });

    return private6;
  }

  uint32_t getPrivate4Gateway(uint32_t private4)
  {
    uint32_t gateway4 = 0;
    uint32_t defaultGateway4 = 0;
    bool foundSpecific = false;

    generateRequest([&](NetlinkMessage *request) {
      socket.getRoutes(request, 0);
    });

    flush();

    readResponse([&](uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) {
      if (nlmsg_type == RTM_NEWROUTE && nlmsg_data)
      {
        struct rtmsg *rtm = reinterpret_cast<struct rtmsg *>(nlmsg_data);

        // Check if the route is IPv4 and belongs to the main routing table
        if (rtm->rtm_family == AF_INET && rtm->rtm_table == RT_TABLE_MAIN)
        {
          uint32_t gatewayBinary;

          uint32_t dstBinary = 0;
          uint32_t dstMask = 0;
          uint32_t ifaceIndex = 0;
          bool hasGateway = false;

          NetlinkSocket::parseAttributes((uint8_t *)rtm + sizeof(struct rtmsg), nlmsg_len - sizeof(struct rtmsg),
                                         [&](int type, void *data) {
                                           switch (type)
                                           {
                                             case RTA_DST:
                                               {
                                                 dstBinary = *reinterpret_cast<uint32_t *>(data);
                                                 dstMask = htonl(~((1 << (32 - rtm->rtm_dst_len)) - 1));
                                                 break;
                                               }
                                             case RTA_OIF:
                                               {
                                                 ifaceIndex = *reinterpret_cast<uint32_t *>(data);
                                                 break;
                                               }
                                             case RTA_GATEWAY:
                                               {
                                                 gatewayBinary = *reinterpret_cast<uint32_t *>(data);
                                                 hasGateway = true;
                                                 break;
                                               }
                                           }
                                         });

          if (!hasGateway || ifaceIndex != ifidx)
          {
            return;
          }

          // Prefer the most specific route covering our private IPv4.
          if (rtm->rtm_dst_len > 0 && (private4 & dstMask) == (dstBinary & dstMask))
          {
            gateway4 = gatewayBinary;
            foundSpecific = true;
            return;
          }

          // Keep default route as fallback.
          if (rtm->rtm_dst_len == 0 && defaultGateway4 == 0)
          {
            defaultGateway4 = gatewayBinary;
          }
        }
      }
    });

    if (!foundSpecific && defaultGateway4 != 0)
    {
      gateway4 = defaultGateway4;
    }

    if (gateway4 == 0)
    {
      std::ifstream routeFile("/proc/net/route");
      std::string line;
      const char *ifname = name.c_str();

      if (routeFile.is_open() == false)
      {
        return 0;
      }

      // Skip header line.
      std::getline(routeFile, line);

      while (std::getline(routeFile, line))
      {
        std::istringstream stream(line);
        std::string ifaceName;
        std::string destinationHex;
        std::string gatewayHex;

        if (!(stream >> ifaceName >> destinationHex >> gatewayHex))
        {
          continue;
        }

        if (ifname == nullptr || ifaceName != ifname || destinationHex != "00000000")
        {
          continue;
        }

        unsigned long gatewayHostOrder = std::strtoul(gatewayHex.c_str(), nullptr, 16);
        gateway4 = uint32_t(gatewayHostOrder);
        break;
      }
    }

    return gateway4;
  }

  bool getGatewayMac(uint32_t our4, uint32_t gateway4)
  {
    if (our4 == 0 || gateway4 == 0)
    {
      memset(gateway_mac, 0, sizeof(gateway_mac));
      return false;
    }

    ARPSocket arpSocket;
    arpSocket.setInterfaceIndex(ifidx);
    arpSocket.setNonBlocking();

    Message32KB message;
    bool success = false;

    for (int attempt = 0; attempt < 5 && !success; attempt += 1)
    {
      arpSocket.requestGatewayMAC(&message, ifidx, gateway4, our4, mac);
      arpSocket.sendmsg(reinterpret_cast<struct msghdr *>(&message));

      struct pollfd descriptor = {};
      descriptor.fd = arpSocket.fd;
      descriptor.events = POLLIN;

      int pollResult = poll(&descriptor, 1, 250);
      if (pollResult <= 0)
      {
        continue;
      }

      message.prepareForRecv();
      int result = arpSocket.recvmsg(reinterpret_cast<struct msghdr *>(&message));
      if (result <= 0)
      {
        continue;
      }

      success = arpSocket.receivedMessage(reinterpret_cast<struct msghdr *>(&message), result, gateway_mac);
    }

    if (success == false)
    {
      memset(gateway_mac, 0, sizeof(gateway_mac));
    }

    arpSocket.close();

    return success;
  }

  bool getGatewayMac(StringType auto&& our_ip4, StringType auto&& gateway_ip4)
  {
    uint32_t our4;
    inet_pton(AF_INET, our_ip4.c_str(), &our4);

    uint32_t gateway4;
    inet_pton(AF_INET, gateway_ip4.c_str(), &gateway4);

    return getGatewayMac(our4, gateway4);
  }

  bool getGatewayMac(void)
  {
    uint32_t private4 = getPrivate4();
    uint32_t private4Gateway = getPrivate4Gateway(private4);

    return getGatewayMac(private4, private4Gateway);
  }

  // bool getULA(IPAddress& ula)
  // {
  // 	bool result = false;

  // 	generateRequest([&] (NetlinkMessage *request) -> void {
  // socket.getAddresses(request, 0, ifidx);
  // });

  // flush();

  // readResponse([&] (uint16_t nlmsg_type, uint32_t nlmsg_seq, void *nlmsg_data, uint32_t nlmsg_len) -> void {

  // if (nlmsg_type == RTM_NEWADDR && nlmsg_data)
  // {
  //    struct ifaddrmsg *ifa = reinterpret_cast<struct ifaddrmsg *>(nlmsg_data);

  // NetlinkSocket::parseAttributes((uint8_t *)ifa + sizeof(struct ifaddrmsg), nlmsg_len - sizeof(struct ifaddrmsg),
  // 	[&] (int type, void *data) -> void {

  // 	if (type == IFA_ADDRESS && ifa->ifa_family == AF_INET6)
  // 	{
  // 		struct in6_addr *ipv6 = reinterpret_cast<struct in6_addr *>(data);
  // 						uint8_t first_byte = ipv6->s6_addr[0]; // First byte of the IPv6 address

  // 						// Mask first 7 bits and check if it matches ULA prefix
  // 						if ((first_byte & 0xfe) == 0xfc)
  // 						{
  // 							result = true;
  // 							memcpy(ula.v6, ipv6, 16);
  // 						}
  //               }
  //         });
  //      }
  //   });

  // return result;
  // }
};
