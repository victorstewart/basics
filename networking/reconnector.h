// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

class Reconnector : public virtual SocketBase {
public:

  uint32_t nConnectionAttempts = 0;
  bool reconnectAfterClose = true;

  int64_t connectTimeoutMs = 0; // must set this

  uint32_t nAttemptsBudget = 0; // try this many times
  uint32_t nDefaultAttemptsBudget; // must set this
  int64_t attemptDeadlineMs = 0; // when set, enforce reconnect budget by elapsed wall clock time

  void reset(void) override
  {
    nConnectionAttempts = 0;
    nAttemptsBudget = 0;
    attemptDeadlineMs = 0;
    reconnectAfterClose = true;
  }

  void attemptConnect(void)
  {
    Ring::queueConnect(this, connectTimeoutMs);
  }

  void attemptForMs(int64_t ms)
  {
    int64_t nowMs = Time::now<TimeResolution::ms>();
    attemptDeadlineMs = nowMs + std::max<int64_t>(ms, 1);

    if (connectTimeoutMs <= 0)
    {
      nAttemptsBudget = 1;
      return;
    }

    nAttemptsBudget = ms / connectTimeoutMs;
    if (nAttemptsBudget == 0)
    {
      nAttemptsBudget = 1;
    }
  }

  void attemptConnectForMs(int64_t ms)
  {
    attemptForMs(ms);
    attemptConnect();
  }

  bool shouldReconnect(void)
  {
    if (reconnectAfterClose == false)
    {
      reconnectAfterClose = true;
      return false;
    }

    return true;
  }

  uint32_t getAttemptBudget(void)
  {
    return (nAttemptsBudget == 0 ? nDefaultAttemptsBudget : nAttemptsBudget);
  }

  void connectAttemptSucceded(void)
  {
    nConnectionAttempts = 0;
    nAttemptsBudget = 0;
    attemptDeadlineMs = 0;
  }

  bool connectAttemptFailed(void)
  {
    nConnectionAttempts += 1;

    if (attemptDeadlineMs > 0)
    {
      if (Time::now<TimeResolution::ms>() < attemptDeadlineMs)
      {
        return false;
      }

      nConnectionAttempts = 0;
      nAttemptsBudget = 0;
      attemptDeadlineMs = 0;
      reconnectAfterClose = false;

      return true;
    }

    if (nConnectionAttempts == getAttemptBudget())
    {
      nConnectionAttempts = 0;
      nAttemptsBudget = 0;
      attemptDeadlineMs = 0;
      reconnectAfterClose = false;

      return true;
    }

    return false;
  }
};
