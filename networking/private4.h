// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <arpa/inet.h>
#include <cstdint>

#pragma once

static inline bool isRFC1918Private4(uint32_t ipv4)
{
  uint32_t ipv4_host_order = ntohl(ipv4);

  if ((ipv4_host_order & 0xFF000000) == 0x0A000000) // 10.0.0.0/8
  {
    return true;
  }

  if ((ipv4_host_order & 0xFFF00000) == 0xAC100000) // 172.16.0.0/12
  {
    return true;
  }

  if ((ipv4_host_order & 0xFFFF0000) == 0xC0A80000) // 192.168.0.0/16
  {
    return true;
  }

  return false;
}
