// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <cstdint>

#pragma once

constexpr uint64_t operator""_KB(unsigned long long value)
{
  return value * 1024;
}

constexpr uint64_t operator""_MB(unsigned long long value)
{
  return value * 1024 * 1024;
}

constexpr uint64_t operator""_TB(unsigned long long value)
{
  return value * 1024 * 1024 * 1024;
}
