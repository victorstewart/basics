// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#pragma once

class ICMPSocket : public SocketBase {
private:

public:

  void configure(void)
  {
    int on = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)); // we manually provide ip header, and receive ip response header
  }

  ICMPSocket()
      : SocketBase(AF_INET, SOCK_RAW, IPPROTO_ICMP)
  {}
};