// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <liburing.h>
#include <linux/socket.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>

#include "networking/ring.interfaces.h"
#include "networking/guardian.h"
#include "networking/pool.h"

class RecvmsgMultishoter {
public:

  struct msghdr msgh;
  uint32_t bgid;
};

class WaitableProcess {
public:

  siginfo_t infop;
};

class Ring {
public:

  enum class Operation : uint8_t {

    signal,
    recv,
    recvmsg,
    recvmsgMultishot,
    accept,
    acceptMultishot,
    socketCommand,
    linkTimeout,
    timeout,
    timeoutMultishot,
    send,
    sendmsg,
    poll,
    connect,
    close,
    closeRaw,
    shutdown,
    tcpFastOpen,
    ringMessage,
    waitid,
    writeFile,
    fsyncFile
  };

private:

  struct BufferRing {

    // all headers contiguous, then all data contiguous
    struct io_uring_buf_ring *ring;
    uint32_t bufferSize;
    uint32_t count;
    uint32_t bgid;
    uint8_t *buffer_base;

    uint8_t *bufferAtIndex(uint32_t index) const
    {
      return buffer_base + index * bufferSize;
    }

    uint32_t indexForBuffer(uint8_t *buffer)
    {
      return (buffer - buffer_base) / bufferSize;
    }
  };

  struct MsghdrPackage {

    void *socket;
    struct msghdr *msg;
  };

  struct SocketCommandPackage {

    void *socket = nullptr;
    const char *label = nullptr;
    uint32_t optlen = 0;
    alignas(uint64_t) uint8_t optval[32] = {0};
  };

  static thread_local inline Pool<MsghdrPackage, true, false> msghdrPackagePool;
  struct FileBufferPackage {
    int fslot;
    String *buf;
  };

  // NIC (requests / second):
  // IO size | non-zc    | zc             | zc + flush
  // 4000    | 495134    | 606420 (+22%)  | 558971 (+12%)
  // 1500    | 551808    | 577116 (+4.5%) | 565803 (+2.5%)
  // 1000    | 584677    | 592088 (+1.2%) | 560885 (-4%)
  // 600     | 596292    | 598550 (+0.4%) | 555366 (-6.7%)

  static thread_local inline bytell_hash_map<uint32_t, BufferRing> bufferRingsByBgid;
  static thread_local inline bytell_hash_map<void *, uint8_t> socketGenerationByIdentity;

  static uint8_t getTagFromUserData(uint64_t user_data)
  {
    return uint8_t((user_data & 0x00FFFFFFFFFFFFFF) >> 48); // clear top 8 bits where op is
  }

  static Operation getOpFromUserData(uint64_t user_data)
  {
    return Operation(user_data >> 56);
  }

  static void *getObjectFromUserData(uint64_t user_data)
  {
    return reinterpret_cast<void *>(user_data & 0x0000FFFFFFFFFFFF); // clear top 16 bits
  }

  static uint64_t getObjectValueFromUserData(uint64_t user_data) // remember this could only be 48 bits
  {
    return (user_data & 0x0000FFFFFFFFFFFF); // clear top 16 bits
  }

  static uint64_t getUserDataFor(Operation op, uint64_t object, uint8_t tag = 0)
  {
    return (uint64_t(op) << 56) | (uint64_t(tag) << 48) | uint64_t(object);
  }

  static uint64_t getUserDataFor(Operation op, void *object, uint8_t tag = 0)
  {
    return getUserDataFor(op, reinterpret_cast<uint64_t>(object), tag);
  }

  static void setUserData(struct io_uring_sqe *sqe, Operation op, void *object, uint8_t tag = 0)
  {
    sqe->user_data = getUserDataFor(op, object, tag);
  }

  static void setUserData(struct io_uring_sqe *sqe, Operation op, uint64_t object, uint8_t tag = 0) // can't be more than 48 bits though
  {
    sqe->user_data = getUserDataFor(op, object, tag);
  }

  static bool socketGenerationMatches(void *socket, uint8_t tag)
  {
    auto it = socketGenerationByIdentity.find(socket);
    if (it == socketGenerationByIdentity.end())
    {
      return false;
    }

    return (it->second == tag);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void noteSocketGeneration(T *socket)
  {
    socketGenerationByIdentity[socketIdentity(socket)] = socket->ioGeneration;
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void requireFixedFileSocket(T *socket, const char *operation)
  {
    if (socket == nullptr || socket->isFixedFile == false || socket->fslot < 0 || static_cast<uint32_t>(socket->fslot) >= fixedFileCapacity)
    {
      std::abort();
    }
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static bool resolveSocketSubmitFD(T *socket, const char *operation, int& submitFD, bool& useFixedFile)
  {
    submitFD = -1;
    useFixedFile = false;

    if (socket == nullptr)
    {
      return false;
    }

    if (socket->isFixedFile)
    {
      if (socket->fslot < 0 || static_cast<uint32_t>(socket->fslot) >= fixedFileCapacity)
      {
        return false;
      }

      submitFD = socket->fslot;
      useFixedFile = true;
      return true;
    }

    if (socket->fd >= 0)
    {
      submitFD = socket->fd;
      return true;
    }

    return false;
  }

  static void requireFixedFileSlot(int fslot, const char *operation)
  {
    if (fslot < 0 || static_cast<uint32_t>(fslot) >= fixedFileCapacity)
    {
      std::abort();
    }
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void *socketIdentity(T *socket)
  {
    if (socket == nullptr)
    {
      return nullptr;
    }

    // Normalize any base-subobject pointer (for example Reconnector*) to the
    // complete object address so close/operation tracking keys are stable.
    return dynamic_cast<void *>(socket);
  }

  static void writeCreateRingStage(const char *stage)
  {
    int fd = open("/bootstage.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
    {
      (void)write(fd, stage, strlen(stage));
      (void)close(fd);
    }
  }

  static struct io_uring_sqe *getSQESafe(void)
  {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (likely(sqe != nullptr))
    {
      return sqe;
    }

    // Submit pending SQEs to free local SQ ring slots.
    (void)io_uring_submit(&ring);
    sqe = io_uring_get_sqe(&ring);
    if (likely(sqe != nullptr))
    {
      return sqe;
    }

    // Under extreme churn (close/reconnect storms), the local SQ can still be
    // saturated until at least one completion is observed by the kernel.
    (void)io_uring_submit_and_wait(&ring, 1);
    sqe = io_uring_get_sqe(&ring);
    if (likely(sqe != nullptr))
    {
      return sqe;
    }

    std::abort();
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void appendTimeoutMs(T *socket, uint64_t timeoutMs, Operation linkedOp)
  {
    socket->timeout.setTimeoutMs(timeoutMs);

    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_link_timeout(sqe, (struct __kernel_timespec *)&(socket->timeout), 0);
    setUserData(sqe, Operation::linkTimeout, socketIdentity(socket), static_cast<uint8_t>(linkedOp));
  }

public:

  template <typename T> requires (std::is_base_of_v<WaitableProcess, T>)
  static void queueWaitid(T *waiter, idtype_t idtype, id_t id)
  {
    // idtype_t
    // P_PID    == pid of child
    // P_PIDFD  == pid of pidfd

    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_waitid(sqe, idtype, id, &waiter->infop, WEXITED, 0);
    sqe->flags |= IOSQE_ASYNC;
    setUserData(sqe, Operation::waitid, waiter);
  }

  static void queueTimeout(TimeoutPacket *payload)
  {
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_timeout(sqe, (struct __kernel_timespec *)payload, 0, IORING_TIMEOUT_BOOTTIME);
    setUserData(sqe, Operation::timeout, payload);
  }

  static void queueTimeoutMultishot(TimeoutPacket *payload)
  {
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_timeout(sqe, (struct __kernel_timespec *)payload, 0, IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_MULTISHOT);
    setUserData(sqe, Operation::timeoutMultishot, payload);
  }

  static void queueUpdateTimeout(TimeoutPacket *payload)
  {
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_timeout_update(sqe, (struct __kernel_timespec *)payload, getUserDataFor(Operation::timeout, payload), 0);
  }

  // nothing says we can't just use regular cancel for this, but might as well do it this way
  static void queueCancelTimeout(TimeoutPacket *payload)
  {
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_timeout_remove(sqe, getUserDataFor(Operation::timeout, payload), 0);
  }

  static void waitForSignals(void)
  {

    struct io_uring_sqe *sqe = getSQESafe();
    // io_uring_prep_read(sqe, 0, &sigInfo, sizeof(struct signalfd_siginfo), 0);
    // io_uring_sqe_set_flags(sqe, IOSQE_ASYNC | IOSQE_FIXED_FILE);

    io_uring_prep_read(sqe, fixedfiles[0], &sigInfo, sizeof(struct signalfd_siginfo), 0);
    io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);

    setUserData(sqe, Operation::signal, nullptr);
  }

  // sqe
  // union {
  // 	/* index into fixed buffers, if used */
  // 	__u16	buf_index;
  // 	/* for grouped buffer selection */
  // 	__u16	buf_group;
  // } __attribute__((packed));

  template <typename T> requires (std::is_base_of_v<SocketBase, T> && std::is_base_of_v<RecvmsgMultishoter, T>)
  static void queueRecvmsgMultishot(T *socket)
  {
    requireFixedFileSocket(socket, "queueRecvmsgMultishot");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_recvmsg_multishot(sqe, socket->fslot, &socket->msgh, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
    sqe->buf_group = socket->bgid;
    sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
    setUserData(sqe, Operation::recvmsgMultishot, socket, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T> && !std::is_base_of_v<RecvmsgMultishoter, T>)
  static void queueRecvmsg(T *socket, struct msghdr *msg)
  {
    MsghdrPackage *package = msghdrPackagePool.get();
    package->socket = socketIdentity(socket);
    package->msg = msg;

    requireFixedFileSocket(socket, "queueRecvmsg");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_recvmsg(sqe, socket->fslot, msg, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

    setUserData(sqe, Operation::recvmsg, package, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueSendmsg(T *socket, struct msghdr *msg)
  {
    MsghdrPackage *package = msghdrPackagePool.get();
    package->socket = socketIdentity(socket);
    package->msg = msg;

    requireFixedFileSocket(socket, "queueSendmsg");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_sendmsg(sqe, socket->fslot, msg, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

    setUserData(sqe, Operation::sendmsg, (void *)package, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<StreamBase, T> && std::is_base_of_v<SocketBase, T>)
  static void queueSend(T *stream)
  {
    void *socket = socketIdentity(stream);
    if (isClosing.contains(socket))
    {
      return;
    }

    if (stream->pendingSend == false)
    {
      int submitFD = -1;
      bool useFixedFile = false;
      if (resolveSocketSubmitFD(stream, "queueSend", submitFD, useFixedFile) == false)
      {
        return;
      }

      const uint32_t sendBytes = stream->nBytesToSend();
      if (sendBytes == 0)
      {
        return;
      }

      noteSocketGeneration(stream);
      stream->pendingSend = true;
      stream->pendingSendBytes = sendBytes;
      stream->noteSendQueued();

      struct io_uring_sqe *sqe = getSQESafe();
      io_uring_prep_send(sqe, submitFD, stream->pBytesToSend(), sendBytes, 0);
      if (useFixedFile)
      {
        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
      }
      setUserData(sqe, Operation::send, socket, stream->ioGeneration);
    }
  }

  template <typename T> requires (std::is_base_of_v<StreamBase, T> && std::is_base_of_v<SocketBase, T>)
  static void queueRecv(T *stream, int64_t timeoutMs = 0)
  {
    void *socket = socketIdentity(stream);
    if (isClosing.contains(socket))
    {
      return;
    }

    if (stream->pendingRecv == false)
    {
      if (stream->rBuffer.remainingCapacity() == 0)
      {
        if (stream->rBuffer.head > 0)
        {
          stream->rBuffer.shiftHeadToZero();
        }
        else
        {
          return;
        }
      }

      int submitFD = -1;
      bool useFixedFile = false;
      if (resolveSocketSubmitFD(stream, "queueRecv", submitFD, useFixedFile) == false)
      {
        return;
      }

      noteSocketGeneration(stream);
      stream->pendingRecv = true;
      struct io_uring_sqe *sqe = getSQESafe();
      io_uring_prep_recv(sqe, submitFD, stream->rBuffer.pTail(), stream->rBuffer.remainingCapacity(), 0);
      if (timeoutMs > 0)
      {
        if (useFixedFile)
        {
          io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
        }
        else
        {
          io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
        }
      }
      else if (useFixedFile)
      {
        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
      }
      setUserData(sqe, Operation::recv, socket, stream->ioGeneration);

      if (timeoutMs > 0)
      {
        appendTimeoutMs(stream, timeoutMs, Operation::recv);
      }
    }
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueConnect(T *socket, uint64_t timeoutMs = 0)
  {
    void *socketKey = socketIdentity(socket);
    if (isClosing.contains(socketKey))
    {
      return;
    }

    int submitFD = -1;
    bool useFixedFile = false;
    if (resolveSocketSubmitFD(socket, "queueConnect", submitFD, useFixedFile) == false)
    {
      return;
    }

    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_connect(sqe, submitFD, socket->template daddr<struct sockaddr>(), socket->daddrLen);

    if (timeoutMs > 0)
    {
      if (useFixedFile)
      {
        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
      }
      else
      {
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
      }
      appendTimeoutMs(socket, timeoutMs, Operation::connect);
    }
    else if (useFixedFile)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    }

    setUserData(sqe, Operation::connect, socketKey, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueTCPFastOpen(T *socket, const String& earlyData)
  {
    requireFixedFileSocket(socket, "queueTCPFastOpen");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_sendto(sqe, socket->fslot, earlyData.data(), earlyData.size(), MSG_FASTOPEN, socket->template daddr<struct sockaddr>(), socket->daddrLen);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    setUserData(sqe, Operation::tcpFastOpen, socket, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<TCPSocket, T> || std::is_base_of_v<UnixSocket, T>)
  static void queueAcceptMultishot(T *socket)
  {
    requireFixedFileSocket(socket, "queueAcceptMultishot");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_multishot_accept_direct(sqe, socket->fslot, nullptr, nullptr, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    setUserData(sqe, Operation::acceptMultishot, socket, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<TCPSocket, T> || std::is_base_of_v<UnixSocket, T>)
  static void queueAccept(T *socket, struct sockaddr *saddr = nullptr, socklen_t *saddrlen = nullptr, int flags = 0)
  {
    requireFixedFileSocket(socket, "queueAccept");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    // accept_direct returns an io_uring direct descriptor, not a process fd.
    // CLOEXEC is meaningless there and some kernels reject it with EINVAL.
    int directAcceptFlags = (flags & ~SOCK_CLOEXEC);
    io_uring_prep_accept_direct(sqe, socket->fslot, saddr, saddrlen, directAcceptFlags, IORING_FILE_INDEX_ALLOC);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    setUserData(sqe, Operation::accept, socket, socket->ioGeneration);
  }

  template <typename T> requires (std::is_base_of_v<TCPSocket, T> || std::is_base_of_v<UnixSocket, T>)
  static void queueSetSockOptRaw(T *socket,
                                 int level,
                                 int optname,
                                 const void *optval,
                                 socklen_t optlen,
                                 const char *label = nullptr)
  {
    int submitFD = -1;
    bool useFixedFile = false;
    if (resolveSocketSubmitFD(socket, "queueSetSockOptRaw", submitFD, useFixedFile) == false)
    {
      return;
    }

    if (optval == nullptr || optlen <= 0 || size_t(optlen) > sizeof(SocketCommandPackage::optval))
    {
      std::abort();
    }

    SocketCommandPackage *package = new SocketCommandPackage();
    package->socket = socketIdentity(socket);
    package->label = label;
    package->optlen = uint32_t(optlen);
    memcpy(package->optval, optval, size_t(optlen));

    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, submitFD, level, optname, package->optval, int(optlen));
    if (useFixedFile)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    }
    setUserData(sqe, Operation::socketCommand, package);
  }

  template <typename T> requires (std::is_base_of_v<TCPSocket, T> || std::is_base_of_v<UnixSocket, T>)
  static void queueSetSockOptInt(T *socket,
                                 int level,
                                 int optname,
                                 int value,
                                 const char *label = nullptr)
  {
    queueSetSockOptRaw(socket, level, optname, &value, socklen_t(sizeof(value)), label);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueClose(T *socket)
  {
    struct io_uring_sqe *sqe = getSQESafe();
    void *socketKey = socketIdentity(socket);
    bool hadPendingSend = socket->pendingSend;

    // A fresh socket may be created/reused in closeHandler; clear operation guards now
    // so reconnect paths can re-arm recv/send deterministically on the next fd/fslot.
    socket->pendingSend = false;
    socket->pendingRecv = false;
    socket->pendingSendBytes = 0;
    // Invalidate all in-flight completions from this stream generation before
    // the socket pointer is reused for a reconnect.
    socket->bumpIoGeneration();
    noteSocketGeneration(socket);
    if constexpr (requires (T *s) { s->noteSendCompleted(); s->clearQueuedSendBytes(); })
    {
      socket->noteSendCompleted();
      // Closing with an in-flight send means the peer may have already consumed a
      // partial frame. Never replay buffered bytes from this generation after reconnect.
      if (hadPendingSend)
      {
        socket->clearQueuedSendBytes();
      }
    }

    isClosing.insert(socketKey);

    if (socket->isFixedFile)
    {
      if (socket->fslot < 0 || static_cast<uint32_t>(socket->fslot) >= fixedFileCapacity)
      {
        std::abort();
      }

      closingObjectToSlot[socketKey] = socket->fslot;
      io_uring_prep_close_direct(sqe, socket->fslot);
      socket->fslot = -1;
      socket->isFixedFile = false;
    }
    else
    {
      if (socket->fd < 0)
      {
        std::abort();
      }

      io_uring_prep_close(sqe, socket->fd);
      socket->fd = -1;
      socket->isFixedFile = false;
    }

    setUserData(sqe, Operation::close, socketKey);
  }

  static void queueCloseRaw(int fslot) // maybe you accepted direct, but want to reject it
  {
    if (fslot < 0 || static_cast<uint32_t>(fslot) >= fixedFileCapacity)
    {
      std::abort();
    }

    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_close_direct(sqe, fslot);
    setUserData(sqe, Operation::closeRaw, uint64_t(fslot));
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueCancel(T *socket, Operation op)
  {
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_cancel64(sqe, getUserDataFor(op, socketIdentity(socket), socket->ioGeneration), IORING_ASYNC_CANCEL_ANY);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueCancelAll(T *socket)
  {
    requireFixedFileSocket(socket, "queueCancelAll");
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_cancel_fd(sqe, socket->fslot, IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD_FIXED);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queueShutdown(T *socket)
  {
    requireFixedFileSocket(socket, "queueShutdown");
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_shutdown(sqe, socket->fslot, SHUT_WR);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    setUserData(sqe, Operation::shutdown, socket);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queuePoll(T *socket, unsigned poll_mask)
  {
    requireFixedFileSocket(socket, "queuePoll");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_poll_add(sqe, socket->fslot, poll_mask);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    setUserData(sqe, Operation::poll, socket);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queuePoll(T *socket, unsigned poll_mask, uint64_t timeoutMs)
  {
    requireFixedFileSocket(socket, "queuePoll");
    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_poll_add(sqe, socket->fslot, poll_mask);

    if (timeoutMs > 0)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_IO_LINK);
      appendTimeoutMs(socket, timeoutMs, Operation::poll);
    }
    else
    {
      io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    }

    setUserData(sqe, Operation::poll, socket);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queuePollProcessFD(T *socket, int submitFD, bool useFixedFile, unsigned poll_mask)
  {
    if (socket == nullptr || submitFD < 0)
    {
      return;
    }

    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_poll_add(sqe, submitFD, poll_mask);
    if (useFixedFile)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    }
    setUserData(sqe, Operation::poll, socket);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void queuePollProcessFD(T *socket, int submitFD, bool useFixedFile, unsigned poll_mask, uint64_t timeoutMs)
  {
    if (socket == nullptr || submitFD < 0)
    {
      return;
    }

    noteSocketGeneration(socket);
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_poll_add(sqe, submitFD, poll_mask);

    if (timeoutMs > 0)
    {
      io_uring_sqe_set_flags(sqe, (useFixedFile ? IOSQE_FIXED_FILE : 0) | IOSQE_IO_LINK);
      appendTimeoutMs(socket, timeoutMs, Operation::poll);
    }
    else if (useFixedFile)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    }

    setUserData(sqe, Operation::poll, socket);
  }

  static void queueRingMessage(uint32_t ringSlot, String *container)
  {
    requireFixedFileSlot(static_cast<int>(ringSlot), "queueRingMessage");
    // we could also use io_uring_prep_msg_ring_cqe_flags and get another 4 bytes if we needed
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_msg_ring(sqe, ringSlot, ring.ring_fd, getUserDataFor(Operation::ringMessage, container), 0);
    sqe->flags |= IOSQE_FIXED_FILE;
  }

  static void queueRingMessageToRingFD(int ringFD, String *container)
  {
    int ringSlot = registerSiblingRing(ringFD);
    if (ringSlot < 0)
    {
      delete container;
      return;
    }

    queueRingMessage(static_cast<uint32_t>(ringSlot), container);
  }

  // Submit a fixed-file write (fd must be registered as fixed file; pass its slot)
  static void queueWriteBuffer(int fslot, String *buf)
  {
    requireFixedFileSlot(fslot, "queueWriteBuffer");
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_write(sqe, fslot, buf->data(), buf->size(), 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    FileBufferPackage *pkg = new FileBufferPackage {fslot, buf};
    setUserData(sqe, Operation::writeFile, pkg);
  }

  // Submit fsync/fdatasync for a fixed file slot
  static void queueFsyncFile(int fslot, bool dataSync = true)
  {
    requireFixedFileSlot(fslot, "queueFsyncFile");
    struct io_uring_sqe *sqe = getSQESafe();
    io_uring_prep_fsync(sqe, fslot, dataSync ? IORING_FSYNC_DATASYNC : 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    setUserData(sqe, Operation::fsyncFile, (uint64_t)fslot);
  }

private:

  static thread_local inline struct signalfd_siginfo sigInfo; // we don't actually read it so overwrite who cares
  static thread_local inline struct io_uring ring;
  static thread_local inline int *fixedfiles;
  static thread_local inline uint32_t fixedFileCapacity = 0;
  static thread_local inline uint32_t fixedFileReserveLimit = 0;
  static thread_local inline bytell_hash_set<int> vacantFixedFileSlots;
  static thread_local inline bytell_hash_set<void *> isClosing;
  static thread_local inline bytell_hash_map<void *, int> closingObjectToSlot; // we need to access slot after it was type erased, and we set it to -1 in queueClose

  static thread_local inline bytell_hash_map<int, int> fdToRingSlot;

  static thread_local inline bool fixedFilesWereRegistered = false;

  static int installFDIntoFixedFileSlot(int fd, bool relinquishProcessFD = true)
  {
    if (vacantFixedFileSlots.empty())
    {
      return -1;
    }

    int slot = vacantFixedFileSlots.pop();
    if (slot < 0 || static_cast<uint32_t>(slot) >= fixedFileCapacity)
    {
      return -1;
    }

    fixedfiles[slot] = fd;
    if (fixedFilesWereRegistered)
    {
      int result = io_uring_register_files_update(&ring, slot, &fixedfiles[slot], 1);
      if (result < 0)
      {
        fixedfiles[slot] = -1;
        vacantFixedFileSlots.insert(slot);
        return -1;
      }
    }

    // Once fixed files are registered, this process fd is redundant for
    // fixed-file operations. Do not close pre-registration descriptors:
    // they are needed by io_uring_register_files during createRing().
    if (fixedFilesWereRegistered && relinquishProcessFD && fd >= 0)
    {
      ::close(fd);
    }

    return slot;
  }

  static void claimKernelAllocatedFixedSlot(int slot)
  {
    if (slot < 0 || static_cast<uint32_t>(slot) >= fixedFileCapacity)
    {
      return;
    }

    // accept-direct may still allocate from reserved slots on kernels/configurations where
    // file allocation ranges are unsupported or ignored. If that happens, remove the slot
    // from our local reserved pool to prevent aliasing a future installFDIntoFixedFileSlot().
    if (static_cast<uint32_t>(slot) < fixedFileReserveLimit)
    {
      vacantFixedFileSlots.erase(slot);
    }
  }

public:

  static thread_local inline int signals[16];
  static thread_local inline RingInterface *& interfacer = ringInterfacer;
  static thread_local inline RingLifecycle *& lifecycler = ringLifecycler;

  static inline bool shuttingDown = false; // better to put it here than make it some universal static variable in a header
  static inline bool exit = false;

  static int adoptProcessFDIntoFixedFileSlot(int fd, bool relinquishProcessFD = true)
  {
    return installFDIntoFixedFileSlot(fd, relinquishProcessFD);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static bool socketIsClosing(T *socket)
  {
    return isClosing.contains(socketIdentity(socket));
  }

  static bool socketIsClosing(void *socket)
  {
    return isClosing.contains(socket);
  }

  static void rescheduleOnSelf(String *container)
  {
    queueRingMessageToRingFD(ring.ring_fd, container);
  }

  static int getRingFD(void)
  {
    return ring.ring_fd;
  }

  static void submitPending(void)
  {
    (void)io_uring_submit(&ring);
  }

  static bool hasReadyCompletions(void)
  {
    return (io_uring_cq_ready(&ring) > 0);
  }

  static void shutdownForExec(void)
  {
    // Explicitly tear down io_uring so fixed-file
    // references do not survive into the new binary and pin listener ports.
    if (ring.ring_fd <= 0)
    {
      return;
    }

    if (fixedFilesWereRegistered)
    {
      io_uring_unregister_files(&ring);
      fixedFilesWereRegistered = false;
    }

    io_uring_unregister_ring_fd(&ring);
    io_uring_queue_exit(&ring);
    ring.ring_fd = -1;
  }

  static int getFDFromFixedFileSlot(int slot)
  {
    if (slot < 0 || static_cast<uint32_t>(slot) >= fixedFileCapacity)
    {
      return -1;
    }

    return fixedfiles[slot];
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static bool bindSourceAddressBeforeFixedFileInstall(T *socket)
  {
    if (socket == nullptr || socket->fd < 0)
    {
      return true;
    }

    if (socket->saddrLen == 0 || socket->daddrLen == 0)
    {
      return true;
    }

    if (::bind(socket->fd, socket->template saddr<struct sockaddr>(), socket->saddrLen) == 0)
    {
      return true;
    }

    return false;
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void uninstallFromFixedFileSlot(T *socket)
  {
    if (socket->fslot < 0 || static_cast<uint32_t>(socket->fslot) >= fixedFileReserveLimit)
    {
      std::abort();
    }

    vacantFixedFileSlots.insert(socket->fslot);
    fixedfiles[socket->fslot] = -1;
    io_uring_register_files_update(&ring, socket->fslot, &fixedfiles[socket->fslot], 1);
    socket->fslot = -1;
    socket->isFixedFile = false;
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  static void installFDIntoFixedFileSlot(T *socket)
  {
    bindSourceAddressBeforeFixedFileInstall(socket);
    int slot = installFDIntoFixedFileSlot(socket->fd);
    if (slot < 0)
    {
      std::abort();
    }

    socket->fslot = slot;
    socket->isFixedFile = true;
  }

  static int registerSiblingRing(int ringFD) // maybe delete this
  {
    int slot = -1;

    if (fdToRingSlot.find(ringFD) == fdToRingSlot.end())
    {
      slot = installFDIntoFixedFileSlot(ringFD, false);
      if (slot < 0)
      {
        return -1;
      }
      fdToRingSlot.insert_or_assign(ringFD, slot);
    }
    else
    {
      slot = fdToRingSlot[ringFD];
    }

    return slot;
  }

  static uint32_t createBufferRing(uint32_t bufferSize, uint32_t count)
  {
    uint32_t bgid = bufferRingsByBgid.size();

    BufferRing& bufferRing = bufferRingsByBgid[bgid];
    bufferRing.bufferSize = bufferSize;
    bufferRing.count = count;
    bufferRing.bgid = bgid;
    bufferRing.ring = reinterpret_cast<struct io_uring_buf_ring *>(mmap(nullptr, (sizeof(struct io_uring_buf) + bufferSize) * count, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

    bufferRing.buffer_base = (uint8_t *)bufferRing.ring + sizeof(struct io_uring_buf) * count;

    io_uring_buf_ring_init(bufferRing.ring);

    struct io_uring_buf_reg buf_reg;
    buf_reg.ring_addr = (unsigned long)bufferRing.ring;
    buf_reg.ring_entries = count;
    buf_reg.bgid = bgid;

    io_uring_register_buf_ring(&ring, &buf_reg, 0);

    for (uint32_t index = 0; index < count; index++)
    {
      io_uring_buf_ring_add(bufferRing.ring, bufferRing.bufferAtIndex(index), bufferSize, index, io_uring_buf_ring_mask(count), index);
    }

    io_uring_buf_ring_advance(bufferRing.ring, count);

    return bufferRing.bgid;
  }

  template <typename T> requires (std::is_base_of_v<RecvmsgMultishoter, T>)
  static void relinquishBufferToRing(T *shoter, uint8_t *buffer)
  {
    BufferRing& bufferRing = bufferRingsByBgid[shoter->bgid];

    memset(buffer, 0, bufferRing.bufferSize);

    uint32_t bufferIndex = bufferRing.indexForBuffer(buffer);
    io_uring_buf_ring_add(bufferRing.ring, buffer, bufferRing.bufferSize, bufferIndex, io_uring_buf_ring_mask(bufferRing.count), 0);

    io_uring_buf_ring_advance(bufferRing.ring, 1); // 1 buffer
  }

  // max SQE depth is 32,768				(1 << 15)
  // max CQE depth is 65,536				(1 << 16)
  // max fixed files is 1,048,576 		(1 << 20)
  // max registered buffers is 16,384 (1 << 14) we should never overflow this.. but if we did we'd just say sorry, take dynamic. it's seamless now
  //
  // we could drop the virtual functions here and use a RingMaster concept
  // then pass the master into this start function and make this function static
  //
  // we also experimented with recovering the full type information within the ring
  // but we'd still have to recover the context outside (is this a client TCP stream or a database stream, etc)
  // so it's acutally not useful, because we can solve both in one go as we do now
  //
  // don't register more than 512-ish fixed files with valgrind
  static void createRing(uint32_t sqeCount, uint32_t cqeCount, uint32_t nFixedFiles, uint32_t nReserveFixedFiles, int workQueueFD, int sqpollCore, uint32_t nMsghdrPackages)
  {
    writeCreateRingStage("worker:ring-enter");
    // IORING_SETUP_ATTACH_WQ

    const uint32_t msghdrPackageCount = (nMsghdrPackages != 0 ? nMsghdrPackages : 8);
    msghdrPackagePool.initialize(msghdrPackageCount);
    writeCreateRingStage("worker:ring-after-msghdr-init");

    // auto fail if MAX 1'048'576 specified for either
    // signalfd
    nFixedFiles += 1;
    nReserveFixedFiles += 1;

    Guardian::boot();
    writeCreateRingStage("worker:ring-after-guardian-boot");

    fixedfiles = new int[nFixedFiles];
    fixedFileCapacity = nFixedFiles;
    fixedFileReserveLimit = nReserveFixedFiles;
    memset(fixedfiles, 0xff, sizeof(int) * nFixedFiles); // make sparse with -1

    // start at index = 1 because 0 is always for the signal fd
    // nReserveFixedFiles == the count of sockets we will create ourselves... versus being autocreated through direct accept etc
    for (uint32_t index = 1; index < nReserveFixedFiles; index++)
    {
      vacantFixedFileSlots.insert(index);
    }
    writeCreateRingStage("worker:ring-after-fixed-slot-init");

    memset(signals, 0xff, sizeof(int) * 16); // make sparse with -1

    if (lifecycler)
    {
      writeCreateRingStage("worker:ring-before-lifecycle-beforeRing");
      lifecycler->beforeRing(); // they set up to 16 signals in here as well
      writeCreateRingStage("worker:ring-after-lifecycle-beforeRing");
    }

    sigset_t listenForSignals = {};

    {
      uint32_t sigIndex = 0;

      while (sigIndex < 16)
      {
        int signal = signals[sigIndex++];

        if (signal == -1)
        {
          break;
        }
        else
        {
          sigaddset(&listenForSignals, signal);
        }
      }

      sigprocmask(SIG_BLOCK, &listenForSignals, nullptr);
    }

    fixedfiles[0] = signalfd(-1, &listenForSignals, 0);
    writeCreateRingStage("worker:ring-after-signalfd");
    if (fixedfiles[0] < 0)
    {
      std::abort();
    }

    struct io_uring_params params = {};
    params.cq_entries = cqeCount;
    // we can't use IORING_SETUP_REGISTERED_FD_ONLY because we need a process wide descriptor as well, to message
    params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE;
    // SQPOLL rejects DEFER_TASKRUN (EINVAL) on some kernels/configurations.
    if (sqpollCore < 0)
    {
      params.flags |= IORING_SETUP_DEFER_TASKRUN;
    }

    if (workQueueFD > -1)
    {
      params.flags |= IORING_SETUP_ATTACH_WQ;
      params.wq_fd = workQueueFD;
    }

    if (sqpollCore > -1) // if IORING_SETUP_ATTACH_WQ, don't specify sqpollCore so that we don't create an extra SQPOLL thread
    {
      params.flags |= IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
      params.sq_thread_cpu = sqpollCore;
      params.sq_thread_idle = 7000; // how long it should busy poll for
    }

    int initResult = io_uring_queue_init_params(sqeCount, &ring, &params);
    if (initResult < 0 && sqpollCore > -1)
    {
      // Some kernels/configurations reject SQPOLL with this ring config.
      // Fall back to a regular submit path instead of crash-looping.

      params.flags &= ~(IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF);
      params.sq_thread_cpu = 0;
      params.sq_thread_idle = 0;

      memset(&ring, 0, sizeof(ring));
      initResult = io_uring_queue_init_params(sqeCount, &ring, &params);
    }

    if (initResult < 0)
    {
      std::abort();
    }
    writeCreateRingStage("worker:ring-after-io_uring-init");

    int registerRingFDResult = io_uring_register_ring_fd(&ring);
    if (registerRingFDResult < 0)
    {
      std::abort();
    }
    writeCreateRingStage("worker:ring-after-register-ringfd");

    int registerFilesResult = io_uring_register_files(&ring, fixedfiles, nFixedFiles);
    if (registerFilesResult < 0)
    {
      std::abort();
    }
    writeCreateRingStage("worker:ring-after-register-files");

    fixedFilesWereRegistered = true;

    int registerFileAllocRange = io_uring_register_file_alloc_range(&ring, nReserveFixedFiles, nFixedFiles - nReserveFixedFiles);
    if (registerFileAllocRange < 0)
    {
    }
    writeCreateRingStage("worker:ring-after-register-file-range");

    if (lifecycler)
    {
      writeCreateRingStage("worker:ring-before-lifecycle-afterRing");
      lifecycler->afterRing();
      writeCreateRingStage("worker:ring-after-lifecycle-afterRing");
    }
  }

  static void printTimestamp(void)
  {
    // Obtain current time as seconds elapsed since the Unix epoch
    time_t now = time(NULL);

    // Convert to local time format
    struct tm *local_time = localtime(&now);

    // String to store formatted date and time
    char formatted_time[100];

    // Format date and time: Day Month Date HH:MM:SS YYYY
    // e.g., Thu Aug 23 14:55:02 2001
    strftime(formatted_time, sizeof(formatted_time), "%a %b %d %H:%M:%S %Y", local_time);

    // Print formatted date and time
  }

  static void start(void)
  {
    waitForSignals();

    struct io_uring_cqe *cqe;
    uint32_t head;
    uint32_t count;
    int result;
    uint64_t user_data;
    void *object;
    Operation op;

    // if we created a virtual function that took an object and returned its type index tag
    // then another which took a tag and object pointer and returned the properly casted type via a lambda [] (T *castedObject) {}
    // we could then operate here with full type information
    uint8_t tag;

    do
    {
      count = 0;
      io_uring_submit_and_wait(&ring, 1); // calls __sys_io_uring_enter if needs to

      io_uring_for_each_cqe(&ring, head, cqe) // this is just a for loop
      {
        ++count;

        user_data = (uint64_t)io_uring_cqe_get_data(cqe);
        op = getOpFromUserData(user_data);
        object = getObjectFromUserData(user_data);
        tag = getTagFromUserData(user_data);
        result = cqe->res;

        switch (op) // ignore if cancelled or closed
        {
            // all socket based operations
          case Operation::connect:
          case Operation::accept:
          case Operation::acceptMultishot:
          case Operation::send:
          case Operation::recv:
          case Operation::recvmsgMultishot:
          case Operation::tcpFastOpen:
            {
              // ignore the cqe if we've closed the slot
              // there is no point in checking result == -ECANCELLED because we only cancel when we close

              // unless we added a deterministic layer of indirection (which we'd have to deal with for every op all the time)
              // like wrapping each Op in some operations struct that included the object, so that we could static_cast the void *
              // to a known type.... we MUST wait for the close to happen first

              // if we did the type tag trick, we could store on SocketBase a flag saying "ignore until connect or fast open"
              // which would block all the race condition queue ops

              // we could then do automatic acceptMultishotDirectHandler refreshing
              // automatically jump to socketFailed for queueRecv and queueSend errors

              // we could return the object to the handlers with full type information... except for not being allowed to do templated virtual functions
              // and still needing to figure out which stream bin the stream is in, which defacto gives us the type... thus this is useless

              if (isClosing.contains(object))
              {
                continue;
              }
              if (socketGenerationMatches(object, tag) == false)
              {
                auto generationIt = socketGenerationByIdentity.find(object);
                unsigned currentGeneration = (generationIt != socketGenerationByIdentity.end())
                                                 ? unsigned(generationIt->second)
                                                 : 0u;
                continue;
              }
              if ((op == Operation::connect || op == Operation::send || op == Operation::recv || op == Operation::poll) && result == -ECANCELED)
              {
                continue;
              }
              break;
            }
          case Operation::sendmsg:
          case Operation::recvmsg:
            {
              MsghdrPackage *package = static_cast<MsghdrPackage *>(object);
              if (package == nullptr)
              {
                continue;
              }

              if (isClosing.contains(package->socket) || socketGenerationMatches(package->socket, tag) == false)
              {
                auto generationIt = socketGenerationByIdentity.find(package->socket);
                unsigned currentGeneration = (generationIt != socketGenerationByIdentity.end())
                                                 ? unsigned(generationIt->second)
                                                 : 0u;
                msghdrPackagePool.relinquish(package);
                continue;
              }
              break;
            }
          default:
            break;
        }

        switch (op)
        {
          case Operation::ringMessage:
            {
              // result == the sending ring's process unique fd
              // object == a pointer to a String containing a Message
              //
              // IORING_OP_MSG_RING also completes on the sender ring with res=0 (or <0 on error).
              // Only receiver-side CQEs carry a positive source ring fd and should dispatch.
              // The payload is owned by the receiver path and is deleted there.
              if (result <= 0)
              {
                break;
              }

              interfacer->ringMessageHandler(result, static_cast<String *>(object));
              break;
            }
          case Operation::writeFile:
            {
              FileBufferPackage *pkg = static_cast<FileBufferPackage *>(object);
              if (interfacer)
              {
                interfacer->fileWriteHandler(pkg->fslot, result);
              }
              delete pkg->buf;
              delete pkg;
              break;
            }
          case Operation::fsyncFile:
            {
              int slot = static_cast<int>(getObjectValueFromUserData(user_data));
              if (interfacer)
              {
                interfacer->fsyncHandler(slot, result);
              }
              break;
            }
          case Operation::signal:
            {

              // returns false if program is ending
              if (lifecycler->signalHandler(sigInfo))
              {
                waitForSignals();
              }

              break;
            }
          case Operation::waitid:
            {
              if (result < 0)
              {
                std::abort();
              }
              interfacer->waitidHandler(object);
              break;
            }
          case Operation::connect:
            {
              interfacer->connectHandler(object, result);
              break;
            }
          case Operation::accept:
            {
              if (result >= 0)
              {
                claimKernelAllocatedFixedSlot(result);
              }
              interfacer->acceptHandler(object, result);
              break;
            }
          case Operation::acceptMultishot:
            {
              // ENFILE if no empty file slots
              if (result >= 0)
              {
                claimKernelAllocatedFixedSlot(result);
              }

              interfacer->acceptMultishotHandler(object, result, !(cqe->flags & IORING_CQE_F_MORE));
              break;
            }
          case Operation::socketCommand:
            {
              SocketCommandPackage *package = static_cast<SocketCommandPackage *>(object);
              delete package;
              break;
            }
          case Operation::shutdown:
            {

              interfacer->shutdownHandler(object);
              break;
            }
          case Operation::poll:
            {

              interfacer->pollHandler(object, result);
              break;
            }
          case Operation::linkTimeout:
            {

              // Linked timeouts complete with -ECANCELED when the guarded operation
              // finishes in time. Only dispatch real timeout/error completions.
              if (result == -ECANCELED)
              {
                break;
              }

              Operation linkedOp = static_cast<Operation>(tag);
              switch (linkedOp)
              {
                case Operation::connect:
                  {
                    interfacer->connectHandler(object, result);
                    break;
                  }
                case Operation::recv:
                  {
                    interfacer->recvHandler(object, result);
                    break;
                  }
                case Operation::send:
                  {
                    interfacer->sendHandler(object, result);
                    break;
                  }
                case Operation::poll:
                  {
                    interfacer->pollHandler(object, result);
                    break;
                  }
                default:
                  {
                    break;
                  }
              }
              break;
            }
          case Operation::close:
            {

              if (isClosing.contains(object))
              {
                isClosing.erase(object);
                auto it = closingObjectToSlot.find(object);
                if (it != closingObjectToSlot.end())
                {
                  int slot = it->second;
                  closingObjectToSlot.erase(it);
                  if (slot < 0 || static_cast<uint32_t>(slot) >= fixedFileCapacity)
                  {
                    std::abort();
                  }

                  // Slots in the reserved range are managed by our local pool.
                  // Slots in the allocator range come from io_uring accept-direct allocation and must not be pooled here.
                  if (static_cast<uint32_t>(slot) < fixedFileReserveLimit)
                  {
                    vacantFixedFileSlots.insert(slot);
                  }

                  fixedfiles[slot] = -1;
                }
              }

              interfacer->closeHandler(object);
              break;
            }
          case Operation::closeRaw:
            {

              int slot = static_cast<int>(getObjectValueFromUserData(user_data));
              if (slot < 0 || static_cast<uint32_t>(slot) >= fixedFileCapacity)
              {
                std::abort();
              }

              if (static_cast<uint32_t>(slot) < fixedFileReserveLimit)
              {
                vacantFixedFileSlots.insert(slot);
              }

              fixedfiles[slot] = -1;
              break;
            }
          case Operation::sendmsg:
            {

              MsghdrPackage *package = static_cast<MsghdrPackage *>(object);

              interfacer->sendmsgHandler(package->socket, package->msg, result);

              msghdrPackagePool.relinquish(package);
              break;
            }
          case Operation::send:
            {

              interfacer->sendHandler(object, result); // drained send buffer
              break;
            }
          case Operation::recv:
            {

              // -ETIME would mean a timeout was set and it fired before the op completed

              interfacer->recvHandler(object, result);
              break;
            }
          case Operation::recvmsg:
            {

              MsghdrPackage *package = static_cast<MsghdrPackage *>(object);

              interfacer->recvmsgHandler(package->socket, package->msg, result);

              msghdrPackagePool.relinquish(package);
              break;
            }
          case Operation::recvmsgMultishot:
            {

              struct io_uring_recvmsg_out *message = nullptr;
              uint8_t *buffer = nullptr;

              // multishot expires if there was an error OR it was canceled (which is -ECANCELED)
              // IORING_CQE_F_MORE	If set, parent SQE will generate more CQE entries

              if (cqe->flags & IORING_CQE_F_BUFFER) // IORING_CQE_F_BUFFER	If set, the upper 16 bits are the buffer ID
              {
                RecvmsgMultishoter *shoter = static_cast<RecvmsgMultishoter *>(object);

                BufferRing& bufferRing = bufferRingsByBgid[shoter->bgid];

                message = io_uring_recvmsg_validate(bufferRing.bufferAtIndex(cqe->flags >> IORING_CQE_BUFFER_SHIFT), cqe->res, &shoter->msgh);
              }

              interfacer->recvmsgMultishotHandler(object, message, result, !(cqe->flags & IORING_CQE_F_MORE));

              break;
            }
          case Operation::tcpFastOpen:
            {

              interfacer->tcpFastOpenHandler(object, result);
              break;
            }
          case Operation::timeoutMultishot:
            {
              if (!(cqe->flags & IORING_CQE_F_MORE))
              {

                queueTimeoutMultishot((TimeoutPacket *)object);
              }

              [[fallthrough]];
            }
          case Operation::timeout:
            {

              interfacer->timeoutHandler((TimeoutPacket *)object, result);
              break;
            }
          default:
            break;
        }

        if (exit)
        {
          return;
        }
      }

      io_uring_cq_advance(&ring, count);

    } while (true);
  }
};
