// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <networking/netlink.h>

#pragma once

class VethPair : public NetDevicePair {
public:

  void setNames(const String& container_name)
  {
    host.name.snprintf<"{}_veth0"_ctv>(container_name);
    peer.name.snprintf<"{}_veth1"_ctv>(container_name);
  }

  void createPair(int peernsfd)
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.createVethPair(request, 0, host.name, peer.name, peernsfd);
    });

    flushDiscard();

    getInfo();
  }
};