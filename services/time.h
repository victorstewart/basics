// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <chrono>
#include <cstdint>
#include <ctime>

#pragma once

enum class TimeResolution : uint8_t {

  sec,
  ms,
  us,
  ns
};

namespace Time {

constexpr int64_t daysToMs(int64_t days)
{
  return days * 86'400'000;
}

constexpr int64_t minsToMs(int64_t minutes)
{
  return minutes * 60'000;
}

constexpr int64_t secToMs(int64_t sec)
{
  return sec * 1000;
}

constexpr int64_t secToUs(int64_t sec)
{
  return sec * 1'000'000;
}

constexpr int64_t secToNs(int64_t sec)
{
  return sec * 1'000'000'000;
}

constexpr int64_t nsToSec(int64_t ns)
{
  return ns / 1'000'000'000;
}

constexpr int64_t nsToMs(int64_t ns)
{
  return ns / 1'000'000;
}

constexpr int64_t nsToUs(int64_t ns)
{
  return ns / 1000;
}

constexpr int64_t msToNs(int64_t ms)
{
  return ms * 1'000'000;
}

static int64_t timespecToMs(struct timespec& ts)
{
  return secToMs(ts.tv_sec) + nsToMs(ts.tv_nsec);
}

template <TimeResolution resolution>
static int64_t now(void)
{
  struct timespec ts = {};
  clock_gettime(CLOCK_REALTIME, &ts);

  if constexpr (resolution == TimeResolution::ms)
  {
    return timespecToMs(ts);
  }
  else if constexpr (resolution == TimeResolution::us)
  {
    return secToUs(ts.tv_sec) + nsToUs(ts.tv_nsec);
  }
  else if constexpr (resolution == TimeResolution::ns)
  {
    return secToNs(ts.tv_sec) + (int64_t)ts.tv_nsec;
  }
  else if constexpr (resolution == TimeResolution::sec)
  {
    return ts.tv_sec;
  }

  return 0;
}

static int64_t msSinceBoot(void)
{
  struct timespec boot_time;
  clock_gettime(CLOCK_BOOTTIME, &boot_time);

  return timespecToMs(boot_time);
}
}; // namespace Time

static std::chrono::year_month_day msSinceEpochToYearMonthDay(int64_t timeMs)
{
  std::chrono::system_clock::time_point timePoint {std::chrono::milliseconds {timeMs}};

  auto datePoint = std::chrono::floor<std::chrono::days>(timePoint);

  return std::chrono::year_month_day(datePoint);
}
