// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdlib>
#include <liburing.h>

enum class RingletOp : uint8_t {

  connect,
  accept,
  send,
  sendmsg,
  recv,
  recvmsg,
  close,
  waitid,
  poll,
  pollMulti,
  eventTimeout,
  timeout
};

class Ringlet {
public:

  struct Event {

    RingletOp op;
    void *actor;
    Timeout timeout; // 16 bytes

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
    union {

      struct { // RingletOp::send
        uint8_t *buffer;
        uint64_t len;
      };

      struct { // RingletOp::sendmsg, RingletOp::recvmsg
        struct msghdr *msg;
      };

      struct { // RingletOp::waitid
        siginfo_t infop;
      };
    };
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    void reset(void)
    {
      timeout.clear();
    }
  };

private:

  Pool<Event, true> eventPool {32};
  bool ringFDRegistered = false;

  uint8_t getTagFromUserData(uint64_t user_data)
  {
    return uint8_t((user_data & 0x00FFFFFFFFFFFFFF) >> 48); // clear top 8 bits where op is
  }

  RingletOp getOpFromUserData(uint64_t user_data)
  {
    return RingletOp(user_data >> 56);
  }

  void *getObjectFromUserData(uint64_t user_data)
  {
    return reinterpret_cast<void *>(user_data & 0x0000FFFFFFFFFFFF); // clear top 16 bits
  }

  uint64_t getUserDataFor(RingletOp op, uint64_t object, uint8_t tag = 0)
  {
    return (uint64_t(op) << 56) | (uint64_t(tag) << 48) | uint64_t(object);
  }

  uint64_t getUserDataFor(RingletOp op, void *object, uint8_t tag = 0)
  {
    return getUserDataFor(op, reinterpret_cast<uint64_t>(object), tag);
  }

  void setUserData(struct io_uring_sqe *sqe, RingletOp op, void *object, uint8_t tag = 0)
  {
    sqe->user_data = getUserDataFor(op, object, tag);
  }

  void setUserData(struct io_uring_sqe *sqe, RingletOp op, uint64_t object, uint8_t tag = 0) // can't be more than 48 bits though
  {
    sqe->user_data = getUserDataFor(op, object, tag);
  }

  void appendTimeoutUs(Event *event, uint64_t timeoutUs)
  {
    event->timeout.setTimeoutUs(timeoutUs);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_link_timeout(sqe, (struct __kernel_timespec *)&(event->timeout), 0);
    setUserData(sqe, RingletOp::eventTimeout, event);
  }

  struct io_uring ring;

public:

  void queueTimeout(uint64_t timeoutUs)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::timeout;
    event->timeout.setTimeoutUs(timeoutUs);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_timeout(sqe, (struct __kernel_timespec *)&(event->timeout), 0, IORING_TIMEOUT_BOOTTIME);
    setUserData(sqe, RingletOp::timeout, event);
  }

  void queueWaitid(idtype_t idtype, id_t id, int options, void *process)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::waitid;
    event->actor = process;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_waitid(sqe, idtype, id, &event->infop, options, 0);
    sqe->flags |= IOSQE_ASYNC;
    setUserData(sqe, RingletOp::waitid, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueConnect(T *socket, uint64_t timeoutUs = 0)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::connect;
    event->actor = socket;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_connect(sqe, socket->fd, socket->template address<struct sockaddr>(), socket->addressLen);

    if (timeoutUs > 0)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
      appendTimeoutUs(event, timeoutUs);
    }

    setUserData(sqe, RingletOp::connect, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueAccept(T *socket, uint64_t timeoutUs = 0)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::accept;
    event->actor = socket;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, socket->fd, nullptr, nullptr, 0);

    if (timeoutUs > 0)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
      appendTimeoutUs(event, timeoutUs);
    }

    setUserData(sqe, RingletOp::accept, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueSend(T *socket, uint8_t *buffer, uint64_t len) // this assumes no short sends, obviously not robust
  {
    Event *event = eventPool.get();
    event->op = RingletOp::send;
    event->actor = socket;
    event->buffer = buffer;
    event->len = len;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_send(sqe, socket->fd, buffer, len, 0);
    setUserData(sqe, RingletOp::send, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueSendmsg(T *socket, struct msghdr *msg)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::sendmsg;
    event->actor = socket;
    event->msg = msg;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_sendmsg(sqe, socket->fd, msg, 0);
    setUserData(sqe, RingletOp::sendmsg, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueRecv(T *socket, uint8_t *buffer, uint64_t len) // this assumes no short sends, obviously not robust
  {
    Event *event = eventPool.get();
    event->op = RingletOp::recv;
    event->actor = socket;
    event->buffer = buffer;
    event->len = len;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_recv(sqe, socket->fd, buffer, len, 0);
    setUserData(sqe, RingletOp::recv, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueRecvmsg(T *socket, struct msghdr *msg, uint64_t timeoutUs = 0)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::recvmsg;
    event->actor = socket;
    event->msg = msg;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_recvmsg(sqe, socket->fd, msg, 0);

    if (timeoutUs > 0)
    {
      io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
      appendTimeoutUs(event, timeoutUs);
    }

    setUserData(sqe, RingletOp::recvmsg, event);
  }

  template <typename T> requires (std::is_base_of_v<SocketBase, T>)
  void queueClose(T *socket)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::close;
    event->actor = socket;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_close(sqe, socket->fd);
    setUserData(sqe, RingletOp::close, event);
  }

  void queuePoll(int fd, void *actor, unsigned poll_mask)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::poll;
    event->actor = actor;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_add(sqe, fd, poll_mask);
    setUserData(sqe, RingletOp::poll, event);
  }

  void queuePollMultishot(int fd, void *actor, unsigned poll_mask)
  {
    Event *event = eventPool.get();
    event->op = RingletOp::pollMulti;
    event->actor = actor;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_multishot(sqe, fd, poll_mask);
    setUserData(sqe, RingletOp::pollMulti, event);
  }

  template <typename Lambda>
  void events(Lambda&& lambda)
  {
    struct io_uring_cqe *cqe;
    uint32_t head;
    uint32_t count;
    int result;
    uint64_t user_data;
    void *object;
    RingletOp op;

    bool finished = false;

    do
    {
      count = 0;
      io_uring_submit_and_wait(&ring, 1);

      io_uring_for_each_cqe(&ring, head, cqe) // this is just a for loop
      {
        ++count;

        user_data = (uint64_t)io_uring_cqe_get_data(cqe);

        op = getOpFromUserData(user_data);

        if (op != RingletOp::eventTimeout)
        {
          object = getObjectFromUserData(user_data);
          result = cqe->res;

          Event *event = reinterpret_cast<Event *>(object);

          finished = lambda(op, event, result, cqe->flags);

          event->reset();
          eventPool.relinquish(event);

          if (finished)
          {
            break;
          }
        }
      }

      io_uring_cq_advance(&ring, count);

    } while (finished == false);
  }

  Ringlet(uint32_t nSQEs = 128, uint32_t nCQEs = 128)
  {
    struct io_uring_params params = {};
    params.cq_entries = nCQEs;
    params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE;

    int initResult = io_uring_queue_init_params(nSQEs, &ring, &params);
    if (initResult < 0)
    {
      std::abort();
    }

    int registerRingFDResult = io_uring_register_ring_fd(&ring);
    if (registerRingFDResult < 0)
    {
      io_uring_queue_exit(&ring);
      std::abort();
    }

    ringFDRegistered = true;
  }

  ~Ringlet()
  {
    if (ringFDRegistered)
    {
      io_uring_unregister_ring_fd(&ring);
    }
    io_uring_queue_exit(&ring);
  }
};
