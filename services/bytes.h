// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace Bytes {

constexpr static uint64_t MBtoB(uint64_t megabytes)
{
  return megabytes * (1024 * 1024);
}

constexpr static uint64_t BtoMB(uint64_t bytes)
{
  return bytes / (1024 * 1024);
}
}; // namespace Bytes