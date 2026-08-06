// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

class NetkitPair : public NetDevicePair {
public:

  void setNames(const String& container_name)
  {
    host.name.snprintf<"{}_netkit0"_ctv>(container_name);
    peer.name.snprintf<"{}_netkit1"_ctv>(container_name);
  }

  void createPair(int peerpid)
  {
    createPair(peerpid, NETKIT_SCRUB_DEFAULT, NETKIT_SCRUB_DEFAULT);
  }

  void createPair(int peerpid, uint32_t scrub, uint32_t peerScrub)
  {
    generateRequest([&](NetlinkMessage *request) -> void {
      socket.createNetkitPair(request, 0, NETKIT_L3, host.name, peer.name, peerpid, scrub, peerScrub);
    });

    flushDiscard();
  }
};
