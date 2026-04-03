// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#pragma once

using ARPMessage = Message32KB;

class ARPSocket : public SocketBase {
private:

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define IPV4_LENGTH 4
#define MAC_LENGTH 6
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

  struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
  };

public:

  explicit ARPSocket(bool shouldCreate = true)
      : SocketBase(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP), shouldCreate)
  {}

  void setInterfaceIndex(int ifidx)
  {
    saddrLen = sizeof(struct sockaddr_ll);

    struct sockaddr_ll *addr = saddr<struct sockaddr_ll>();
    addr->sll_family = AF_PACKET;
    addr->sll_ifindex = ifidx;

    if (fd != -1)
    {
      bind();
    }
  }

  static void requestGatewayMAC(ARPMessage *request, int ifidx, uint32_t gateway4, uint32_t interface4, uint8_t interfaceMAC[MAC_LENGTH])
  {
    request->setAddrLen(sizeof(struct sockaddr_ll));
    request->setPayloadLen(ETH2_HEADER_LEN + sizeof(struct arp_header));

    struct sockaddr_ll *lladdr = request->address<struct sockaddr_ll>();
    lladdr->sll_family = AF_PACKET;
    lladdr->sll_protocol = htons(ETH_P_ARP);
    lladdr->sll_ifindex = ifidx;
    lladdr->sll_hatype = htons(ARPHRD_ETHER);
    lladdr->sll_pkttype = (PACKET_BROADCAST);
    lladdr->sll_halen = MAC_LENGTH;
    lladdr->sll_addr[6] = 0x00;
    lladdr->sll_addr[7] = 0x00;
    memcpy(lladdr->sll_addr, interfaceMAC, MAC_LENGTH);

    struct ethhdr *ehdr = (struct ethhdr *)request->payload();
    struct arp_header *arphdr = (struct arp_header *)(request->payload() + ETH2_HEADER_LEN);

    // Broadcast
    memset(ehdr->h_dest, 0xff, MAC_LENGTH);

    // Target MAC zero
    memset(arphdr->target_mac, 0x00, MAC_LENGTH);

    // Set source mac to our MAC address
    memcpy(ehdr->h_source, interfaceMAC, MAC_LENGTH);
    memcpy(arphdr->sender_mac, interfaceMAC, MAC_LENGTH);

    // Setting protocol of the packet
    ehdr->h_proto = htons(ETH_P_ARP);

    // Creating ARP request
    arphdr->hardware_type = htons(HW_TYPE);
    arphdr->protocol_type = htons(ETH_P_IP);
    arphdr->hardware_len = MAC_LENGTH;
    arphdr->protocol_len = IPV4_LENGTH;
    arphdr->opcode = htons(ARP_REQUEST);

    // Copy IP addresses to arphdr
    memcpy(arphdr->sender_ip, &interface4, sizeof(uint32_t));
    memcpy(arphdr->target_ip, &gateway4, sizeof(uint32_t));
  }

  static bool receivedMessage(struct msghdr *msg, int result, uint8_t gatewayMAC[MAC_LENGTH]) // result == number of bytes received
  {
    if (result < (ETH2_HEADER_LEN + static_cast<int>(sizeof(arp_header))))
    {
      return false;
    }

    struct ethhdr *ehdr = (struct ethhdr *)msg->msg_iov[0].iov_base;

    // not an ARP packet
    if (ntohs(ehdr->h_proto) != PROTO_ARP)
    {
      return false;
    }

    struct arp_header *arphdr = (struct arp_header *)((uint8_t *)msg->msg_iov[0].iov_base + ETH2_HEADER_LEN);

    // not an ARP reply
    if (ntohs(arphdr->opcode) != ARP_REPLY)
    {
      return false;
    }

    // this should match the gatewayAddress
    // arphdr->sender_ip

    memcpy(gatewayMAC, arphdr->sender_mac, MAC_LENGTH);
    return true;
  }
};
