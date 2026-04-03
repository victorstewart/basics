// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <linux/time_types.h>

#pragma once

class Timeout {
public:

  struct __kernel_timespec timeout = {}; // same as struct timespec;

  void setTimeoutUs(uint64_t microseconds)
  {
    if (microseconds > 0)
    {
      timeout.tv_sec = microseconds / 1'000'000;
      timeout.tv_nsec = (microseconds % 1'000'000) * 1000;
    }
  }

  void setTimeoutMs(uint64_t milliseconds)
  {
    if (milliseconds > 0)
    {
      timeout.tv_sec = milliseconds / 1000;
      timeout.tv_nsec = (milliseconds % 1000) * 1'000'000;
    }
  }

  void setTimeoutSeconds(uint64_t seconds)
  {
    if (seconds > 0)
    {
      timeout.tv_sec = seconds;
    }
  }

  bool isLive(void)
  {
    return (timeout.tv_sec != 0 || timeout.tv_nsec != 0);
  }

  void clear(void)
  {
    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;
  }

  int64_t timeoutMs(void)
  {
    // convert seconds to milliseconds, then nanoseconds to milliseconds
    return ((int64_t)timeout.tv_sec * 1000) + (timeout.tv_nsec / 1'000'000);
  }
};

class TimeoutPacket;

class TimeoutDispatcher {
public:

  virtual void dispatchTimeout(TimeoutPacket *packet) = 0;
};

class TimeoutPacket : public Timeout {
public:

  uint128_t identifier; // you can't trust pointers across async bounds, might've been destroyed
  uint64_t flags;
  void *payload;
  void *originator;
  TimeoutDispatcher *dispatcher = nullptr;

  TimeoutPacket() = default;
  TimeoutPacket(uint64_t _flags)
      : flags(_flags)
  {}
};