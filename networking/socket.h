// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <services/bitsery.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <sys/un.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/tcp.h> // TCP_NODELAY
#include <fcntl.h>
#include <sys/sendfile.h>
#include <unistd.h> // unlink
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>

#define SOL_TCP 6
#define SOL_UDP 17

#pragma once

class SocketBase {
protected:

  int domain;
  int type;
  int protocol;

  virtual void configureSocket(void) {}

public:

  struct sockaddr_storage saddr_storage {}; // 128 bytes
  socklen_t saddrLen = 0; // 4 bytes

  struct sockaddr_storage daddr_storage {}; // 128 bytes
  socklen_t daddrLen = 0; // 4 bytes

  Timeout timeout; // 16 bytes

  union {

    int fd = -1;
    int fslot; // fixed/registered file slot
  };

  bool pendingSend = false;
  bool pendingRecv = false;
  uint32_t pendingSendBytes = 0;
  uint8_t ioGeneration = 1;
  bool isFixedFile = false;
  bool isNonBlocking = false;

  uint8_t bumpIoGeneration(void)
  {
    ++ioGeneration;
    if (ioGeneration == 0)
    {
      ioGeneration = 1;
    }

    return ioGeneration;
  }

  void setNonBlocking(void)
  {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    isNonBlocking = true;
  }

  template <typename T>
  T *saddr(void)
  {
    return (T *)&saddr_storage;
  }

  template <typename T>
  const T *saddr(void) const
  {
    return (const T *)&saddr_storage;
  }

  template <typename T>
  T *daddr(void)
  {
    return (T *)&daddr_storage;
  }

  template <typename T>
  const T *daddr(void) const
  {
    return (const T *)&daddr_storage;
  }

  void bind(void)
  {
    ::bind(fd, saddr<struct sockaddr>(), saddrLen);
  }

  int connect(void)
  {
    return ::connect(fd, daddr<struct sockaddr>(), daddrLen);
  }

  void close(void)
  {
    ::close(fd);
  }

  template <typename T> requires (sizeof(T) == 1)
  ssize_t send(const T *buffer, size_t len, int flags = 0) const
  {
    size_t nBytesSent = 0;

    do
    {
      ssize_t result = ::send(fd, buffer + nBytesSent, len - nBytesSent, flags);

      if (result <= 0)
      {
        return result;
      }
      else
      {
        nBytesSent += static_cast<size_t>(result);
      }

    } while (nBytesSent < len);

    return static_cast<ssize_t>(nBytesSent);
  }

  ssize_t send(StringType auto&& buffer, int flags = 0) const
  {
    return send(buffer.data(), buffer.size(), flags);
  }

  ssize_t sendmsg(const struct msghdr *msg, int flags = 0)
  {
    return ::sendmsg(fd, msg, flags);
  }

  void bindToDevice(String& devname)
  {
    struct ifreq ifr = {};
    memcpy(ifr.ifr_name, devname.c_str(), devname.size() + 1);

    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));
  }

  template <typename T> requires (sizeof(T) == 1)
  ssize_t recv(T *buffer, size_t len, int flags = 0)
  {
    return ::recv(fd, buffer, len, flags);
  }

  ssize_t recv(StringDescendent auto&& buffer, int flags = 0)
  {
    ssize_t result = recv(buffer.pTail(), buffer.remainingCapacity(), flags);

    if (result > 0)
    {
      buffer.advance(result);
    }

    return result;
  }

  ssize_t recvmsg(struct msghdr *msg, int flags = 0)
  {
    return ::recvmsg(fd, msg, flags);
  }

  void setConnected(void)
  {
    pendingSend = false;
    pendingRecv = false;
    pendingSendBytes = 0;
  }

  void setDisconnected(void)
  {
    pendingSend = true;
    pendingRecv = true;
    pendingSendBytes = 0;
    bumpIoGeneration();
  }

  virtual void bindThenListen(void)
  {
    if (::bind(fd, saddr<struct sockaddr>(), saddrLen) != 0)
    {
      std::abort();
    }

    if (::listen(fd, SOMAXCONN) != 0)
    {
      std::abort();
    }
  }

  virtual void reset(void)
  {
    pendingSend = false;
    pendingRecv = false;
    pendingSendBytes = 0;
    bumpIoGeneration();

    // we don't reset the fd to -1 because it's always
    // explicitly set to a value post-accept AND queueClose
    // needs the fd to unset it in the io_uring fixes files
    memset(&saddr_storage, 0, sizeof(struct sockaddr_storage));
    saddrLen = 0;
  }

  virtual void createSocket(void)
  {
    fd = socket(domain, type, protocol);
    configureSocket();
    if (isNonBlocking)
    {
      setNonBlocking();
    }
  }

  virtual void recreateSocket(void)
  {
    if (isFixedFile == false && fd != -1)
    {
      ::close(fd); // fixed-file sockets track slot in this union field, not a process fd
    }
    createSocket();
    // A recreated socket starts life as a process fd; fixed-file state is
    // only valid again after Ring::installFDIntoFixedFileSlot succeeds.
    isFixedFile = false;
  }

  SocketBase() = default;

  SocketBase(int _domain, int _type, int _protocol, bool shouldCreate = true)
      : domain(_domain),
        type(_type),
        protocol(_protocol)
  {
    if (shouldCreate)
    {
      createSocket();
    }
  }
};

class UnixSocket : public virtual SocketBase {
public:

  bool isPair = false;

  void setSocketPath(const char *path)
  {
    isPair = false;

    struct sockaddr_un *addr = daddr<struct sockaddr_un>();
    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path, path);
    daddrLen = strlen(addr->sun_path) + sizeof(addr->sun_family);
  }

  void bindThenListen(void)
  {
    const char *socketPath = saddr<struct sockaddr_un>()->sun_path;
    unlink(socketPath);

    if (::bind(fd, saddr<struct sockaddr>(), saddrLen) != 0)
    {
      int err = errno;
      if (err == EADDRINUSE)
      {
        // A stale unix-path listener from a prior process generation can survive
        // briefly during restart; unlink and retry once for this unix endpoint.
        unlink(socketPath);
        if (::bind(fd, saddr<struct sockaddr>(), saddrLen) == 0)
        {
          err = 0;
        }
        else
        {
          err = errno;
        }
      }

      if (err != 0)
      {
        std::abort();
      }
    }

    if (::listen(fd, SOMAXCONN) != 0)
    {
      std::abort();
    }
  }

  void recreateSocket(void)
  {
    if (isPair == false)
    {
      SocketBase::recreateSocket();
    }
  }

  UnixSocket()
      : SocketBase(AF_UNIX, SOCK_STREAM, 0, false)
  {}
};

class IPSocket : public virtual SocketBase {
public:

  static struct addrinfo *getAddressFromURI(const char *uri, uint16_t domain)
  {
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = domain;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_V4MAPPED;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    getaddrinfo(uri, NULL, &hints, &result);

    return result;
  }

  void setIPv6(struct sockaddr_storage *storage, socklen_t *len, const struct in6_addr *address6, uint16_t port)
  {
    *len = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *sin6 = reinterpret_cast<struct sockaddr_in6 *>(storage);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_flowinfo = 0;
    sin6->sin6_port = htons(port);
    sin6->sin6_addr = *address6;

    // in6addr_any, which (by default) allows connections to be established from any IPv4 or IPv6 client
    //  If the client is an IPv4 client, the address is shown as an IPv4–mapped IPv6 address.
    // in6addr_any;
  }

  void setIPv4(struct sockaddr_storage *storage, socklen_t *len, const struct in_addr *address4, uint16_t port)
  {
    *len = sizeof(struct sockaddr_in);

    struct sockaddr_in *sin4 = reinterpret_cast<struct sockaddr_in *>(storage);
    sin4->sin_family = AF_INET;
    sin4->sin_port = htons(port);
    sin4->sin_addr = *address4;
  }

  void setSaddr(const struct in_addr *address4, uint16_t port = 0)
  {
    setIPv4(&saddr_storage, &saddrLen, address4, port);
  }

  void setDaddr(const struct in_addr *address4, uint16_t port)
  {
    setIPv4(&daddr_storage, &daddrLen, address4, port);
  }

  void setSaddr(const struct in6_addr *address6, uint16_t port = 0)
  {
    setIPv6(&saddr_storage, &saddrLen, address6, port);
  }

  void setDaddr(const struct in6_addr *address6, uint16_t port)
  {
    setIPv6(&daddr_storage, &daddrLen, address6, port);
  }

  void setSaddr(uint32_t address4, uint16_t port = 0)
  {
    setSaddr(reinterpret_cast<const struct in_addr *>(&address4), port);
  }

  void setDaddr(uint32_t address4, uint16_t port)
  {
    setDaddr(reinterpret_cast<const struct in_addr *>(&address4), port);
  }

  void setSaddr(uint128_t address6, uint16_t port = 0)
  {
    setSaddr(reinterpret_cast<const struct in6_addr *>(&address6), port);
  }

  void setDaddr(uint128_t address6, uint16_t port)
  {
    setDaddr(reinterpret_cast<const struct in6_addr *>(&address6), port);
  }

  void setSaddr(const IPAddress& address, uint16_t port = 0)
  {
    if (domain == AF_INET)
    {
      setSaddr(reinterpret_cast<const struct in_addr *>(&address.v4), port);
    }
    else
    {
      setSaddr(reinterpret_cast<const struct in6_addr *>(address.v6), port);
    }
  }

  void setDaddr(const IPAddress& address, uint16_t port)
  {
    if (domain == AF_INET)
    {
      setDaddr(reinterpret_cast<const struct in_addr *>(&address.v4), port);
    }
    else
    {
      setDaddr(reinterpret_cast<const struct in6_addr *>(address.v6), port);
    }
  }

  void setSaddr(StringType auto&& address, uint16_t port)
  {
    if (domain == AF_INET)
    {
      struct in_addr addr;
      inet_pton(AF_INET, address.c_str(), &addr);
      setSaddr(&addr, port);
    }
    else
    {
      struct in6_addr addr;
      inet_pton(AF_INET6, address.c_str(), &addr);
      setSaddr(&addr, port);
    }
  }

  void setDaddr(StringType auto&& address, uint16_t port)
  {
    if (domain == AF_INET)
    {
      struct in_addr addr;
      inet_pton(AF_INET, address.c_str(), &addr);
      setDaddr(&addr, port);
    }
    else
    {
      struct in6_addr addr;
      inet_pton(AF_INET6, address.c_str(), &addr);
      setDaddr(&addr, port);
    }
  }

  void setDaddrFromURI(const char *uri, uint16_t port)
  {
    struct addrinfo *result = getAddressFromURI(uri, domain);

    if (domain == AF_INET)
    {
      setDaddr(&reinterpret_cast<struct sockaddr_in *>(result->ai_addr)->sin_addr, port);
    }
    else
    {
      setDaddr(&reinterpret_cast<struct sockaddr_in6 *>(result->ai_addr)->sin6_addr, port);
    }

    freeaddrinfo(result);
  }

  uint32_t daddr4(void)
  {
    return daddr<struct sockaddr_in>()->sin_addr.s_addr;
  }

  uint128_t daddr6(void)
  {
    uint128_t addr6 = 0;
    memcpy(&addr6, daddr<struct sockaddr_in6>()->sin6_addr.s6_addr, 16);

    return addr6;
  }

  uint16_t dport(void)
  {
    if (domain == AF_INET)
    {
      return ntohs(daddr<struct sockaddr_in>()->sin_port);
    }
    else
    {
      return ntohs(daddr<struct sockaddr_in6>()->sin6_port);
    }
  }

  bool daddrEqual(const IPAddress& other)
  {
    if (domain == AF_INET)
    {
      return (memcmp(&daddr<struct sockaddr_in>()->sin_addr, &other.v4, 4) == 0);
    }
    else
    {
      return (memcmp(&daddr<struct sockaddr_in6>()->sin6_addr, &other.v6, 16) == 0);
    }
  }

  IPSocket() = delete;
  IPSocket(int _domain, int _type, int _protocol, bool shouldCreate = true)
      : SocketBase(_domain, _type, _protocol, shouldCreate)
  {}
};

#include <linux/tcp.h>

class TCPSocket : public IPSocket {
private:

  const char *congestionControlScheme = "";
  uint32_t keepAliveUntilSeconds = 0;
  bool yesFastOpen = false;

  void setNoDelay(void)
  {
    const int noDelay = 1;
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay));
  }

protected:

  void configureSocket(void) override // createSocket calls configureSocket
  {
    // Allow rapid listener rebind after update/restart while prior accepted
    // connections may still sit in TIME_WAIT on the same local port.
    int reuseAddress = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseAddress, sizeof(reuseAddress));

    setNoDelay();

    if (congestionControlScheme)
    {
      setCongestionControl(congestionControlScheme);
    }
    if (keepAliveUntilSeconds)
    {
      setKeepaliveTimeoutSeconds(keepAliveUntilSeconds);
    }
    if (yesFastOpen)
    {
      enableTCPFastOpen();
    }
  }

public:

  void setIPVersion(int ip_version) // AF_INET or AF_INET6
  {
    domain = ip_version;
    type = SOCK_STREAM;
    protocol = IPPROTO_TCP;

    if (isFixedFile)
    {
      std::abort();
    }

    if (fd != -1)
    {
      ::close(fd);
    }

    createSocket();
  }

  int accept(void)
  {
    return ::accept(fd, nullptr, nullptr);
  }

  void reset(void) override
  {
    SocketBase::reset();

    congestionControlScheme = "";
    keepAliveUntilSeconds = 0;
    yesFastOpen = false;
  }

  void setKeepaliveTimeoutSeconds(uint32_t timeoutAfterSeconds)
  {
    if (timeoutAfterSeconds == 0)
    {
      timeoutAfterSeconds = 1;
    }
    keepAliveUntilSeconds = timeoutAfterSeconds;

    int turnOn = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &turnOn, sizeof(int));

    int sendThisManyKeepAlivePackets = 2;
    int sendKeepAlivePacketsAtThisIntervalSeconds = 1;

    // Start keepalives early enough that we can send a few probes and still fail
    // by timeoutAfterSeconds; clamp idle to at least 1 second.
    // For TCP_KEEPIDLE
    int tcpKeepIdleVal = (int)(timeoutAfterSeconds - (sendThisManyKeepAlivePackets + 1) * sendKeepAlivePacketsAtThisIntervalSeconds);
    if (tcpKeepIdleVal < 1)
    {
      tcpKeepIdleVal = 1;
    }
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &tcpKeepIdleVal, sizeof(tcpKeepIdleVal));

    // For TCP_KEEPCNT
    int tcpKeepCntVal = sendThisManyKeepAlivePackets;
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &tcpKeepCntVal, sizeof(tcpKeepCntVal));

    // For TCP_KEEPINTVL
    int tcpKeepIntvlVal = sendKeepAlivePacketsAtThisIntervalSeconds;
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &tcpKeepIntvlVal, sizeof(tcpKeepIntvlVal));

    // For TCP_USER_TIMEOUT
    // then fail after this amount of idle time (not necessary to add this but might as well)
    // the maximum amount of time in milliseconds that transmitted data may remain unacknowledged, or bufferred data may remain untransmitted (due to zero window size) before TCP will forcibly close the corresponding connection and return  ETIMEDOUT to the application. Increasing user timeouts allows a TCP connection to survive extended periods without end-to-end connectivity. Decreasing user timeouts allows applications to "fail fast", if so desired.
    unsigned int timeoutMs = timeoutAfterSeconds * 1000;
    setsockopt(fd, SOL_TCP, TCP_USER_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
  }

  void enableTCPFastOpen(void)
  {
    yesFastOpen = true;
    const int fastOpenQueueDepth = 32;
    setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &fastOpenQueueDepth, sizeof(fastOpenQueueDepth));
  }

  void setCongestionControl(const char *scheme)
  {
    congestionControlScheme = scheme;
    setsockopt(fd, SOL_TCP, TCP_CONGESTION, scheme, strlen(scheme));
  }

  void setDatacenterCongestion(void)
  {
    setCongestionControl("dctcp");
  }

  void setBBRCongestion(void)
  {
    setCongestionControl("bbr");
  }

  TCPSocket()
      : IPSocket(0, SOCK_STREAM, IPPROTO_TCP, false)
  {}
};

class UDPSocket : public IPSocket {
private:

  bool yesGRO = false;
  bool yesPacketInfo = false;

public:

  void setIPVersion(int ip_version) // AF_INET or AF_INET6
  {
    domain = ip_version;
    type = SOCK_DGRAM;
    protocol = IPPROTO_UDP;

    if (isFixedFile)
    {
      std::abort();
    }

    if (fd != -1)
    {
      ::close(fd);
    }

    createSocket();
  }

  void configureSocket(void) override
  {
    if (yesGRO)
    {
      enableGRO();
    }
    if (yesPacketInfo)
    {
      enablePacketInfo();
    }
  }

  void enableGRO(void)
  {
    yesGRO = true;
    const uint32_t groEnabled = 1;
    setsockopt(fd, SOL_UDP, UDP_GRO, &groEnabled, sizeof(groEnabled));
  }

  void enablePacketInfo(void)
  {
    yesPacketInfo = true;

    if (domain == AF_INET6)
    {
      const int packetInfoEnabled = 1;
      setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &packetInfoEnabled, sizeof(packetInfoEnabled));
    }
    else
    {
      const int packetInfoEnabled = 1;
      setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &packetInfoEnabled, sizeof(packetInfoEnabled));
    }
  }

  UDPSocket()
      : IPSocket(0, SOCK_DGRAM, IPPROTO_UDP, false)
  {}
};
