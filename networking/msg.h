// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

template <uint32_t CONTROL_LEN, uint32_t PAYLOAD_LEN>
struct msg {
private:

  constexpr static size_t PADDING_LEN = (16 - (CONTROL_LEN % 16)) % 16;

public:

  struct msghdr hdr = {};
  struct iovec iov = {};
  struct sockaddr_storage addr = {};
  uint8_t data[CONTROL_LEN + PADDING_LEN + PAYLOAD_LEN] = {0};

  template <typename Handler>
  void addControlMessage(Handler&& handler)
  {
  }

  void setControlLen(uint32_t len)
  {
    hdr.msg_controllen = len;
  }

  void setPayloadLen(uint32_t len)
  {
    iov.iov_len = len;
  }

  uint32_t payloadLen(void)
  {
    return iov.iov_len;
  }

  void setAddrv6(StringType auto&& address, uint16_t port)
  {
    setAddrLen(sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *in6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(port);
    inet_pton(AF_INET6, address.c_str(), &in6->sin6_addr);
  }

  void setAddrLen(uint32_t len)
  {
    hdr.msg_namelen = len;
  }

  uint32_t addressLen(void)
  {
    return hdr.msg_namelen;
  }

  template <typename T>
  T *address(void)
  {
    return reinterpret_cast<T *>(&addr);
  }

  uint8_t *payload(void)
  {
    return static_cast<uint8_t *>(iov.iov_base);
  }

  void reset(void)
  {
    memset(data, 0, sizeof(data));
    memset(&addr, 0, sizeof(struct sockaddr_storage));

    setAddrLen(0);
    setControlLen(0);
    setPayloadLen(0);
  }

  void setPayloadMax(void)
  {
    setPayloadLen(PAYLOAD_LEN);
  }

  void setAddressMax(void)
  {
    setAddrLen(sizeof(struct sockaddr_storage));
  }

  void prepareForRecv(void)
  {
    setAddressMax();
    setPayloadMax();
  }

  msg()
  {
    hdr.msg_name = &addr;

    hdr.msg_control = data;

    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    iov.iov_base = data + CONTROL_LEN + PADDING_LEN;
  }
};

using Message32KB = msg<0, 32_KB>;
