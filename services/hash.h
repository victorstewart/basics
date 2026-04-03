// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
// #include <gxhash/gxhash.h>

// #define XXH_INLINE_ALL 1
// #include <xxHash/xxh3.h>

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

extern "C" uint32_t gxhash32(const void *buf, size_t len, int64_t seed);
extern "C" uint64_t gxhash64(const void *buf, size_t len, int64_t seed);

class Hasher {
public:

  enum class SeedPolicy : uint8_t {
    global_shared = 0,
    thread_shared = 1,
    per_hash_random = 2,
  };

private:

  static int64_t makeRandomSeed(void)
  {
    return int64_t(Random::generateNumberWithNBits<64, uint64_t>());
  }

  static std::atomic<int64_t>& globalSeedStorage(void)
  {
    static std::atomic<int64_t> seed {makeRandomSeed()};
    return seed;
  }

public:

  static int64_t& threadSeed(void)
  {
    static thread_local int64_t seed = makeRandomSeed();
    return seed;
  }

  static void setThreadSeed(int64_t seed)
  {
    threadSeed() = seed;
  }

  static int64_t globalSeed(void)
  {
    return globalSeedStorage().load(std::memory_order_relaxed);
  }

  static void setGlobalSeed(int64_t seed)
  {
    globalSeedStorage().store(seed, std::memory_order_relaxed);
  }

  static uint64_t hash(const uint8_t *bytes, uint64_t size, int64_t seed)
  {
    return gxhash64(bytes, size, seed);
  }

  template <SeedPolicy policy>
  static uint64_t hash(const uint8_t *bytes, uint64_t size)
  {
    if constexpr (policy == SeedPolicy::global_shared)
    {
      return hash(bytes, size, globalSeed());
    }

    if constexpr (policy == SeedPolicy::thread_shared)
    {
      return hash(bytes, size, threadSeed());
    }

    return hash(bytes, size, makeRandomSeed());
  }
};
