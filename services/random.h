// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <sys/random.h>
#include <type_traits>

#pragma once

namespace Random {

namespace detail {

template <typename T>
constexpr bool isExtendedIntegralV =
    std::is_integral_v<T> ||
    std::is_same_v<std::remove_cvref_t<T>, __int128_t> ||
    std::is_same_v<std::remove_cvref_t<T>, __uint128_t>;

inline void fillRandomBytes(void *buffer, size_t size) noexcept
{
  auto *bytes = static_cast<unsigned char *>(buffer);
  size_t remaining = size;

  while (remaining > 0)
  {
    ssize_t produced = ::getrandom(bytes, remaining, 0U);

    if (produced < 0)
    {
      if (errno == EINTR)
      {
        continue;
      }

      std::abort();
    }

    if (produced == 0)
    {
      continue;
    }

    size_t written = static_cast<size_t>(produced);
    bytes += written;
    remaining -= written;
  }
}

} // namespace detail

// uint64_t mersenne_twister64(void)
// {
//    // if this is made static, when we fork into a new process.. it will generate the same number
//    // even if made static thread_local
//    std::mt19937_64 rng(std::random_device{}());
//    return rng();
// }

template <uint8_t nBits, typename T = uint128_t>
static T generateNumberWithNBits(bool inclusiveZero = false)
{
  static_assert(detail::isExtendedIntegralV<T>, "generateNumberWithNBits requires an integral result type");
  static_assert(!std::is_signed_v<T>, "generateNumberWithNBits requires an unsigned result type");

  constexpr size_t bitWidth = sizeof(T) * 8;
  static_assert(nBits <= bitWidth, "generateNumberWithNBits: nBits must be <= bit width of T");

  if constexpr (nBits == 0)
  {
    return T {0};
  }

  auto drawSample = [&]() -> T {
    T sample = T {0};
    detail::fillRandomBytes(&sample, sizeof(T));

    if constexpr (nBits < bitWidth)
    {
      constexpr T mask = (T {1} << nBits) - T {1};
      sample &= mask;
    }

    return sample;
  };

  T value = drawSample();

  if (!inclusiveZero)
  {
    while (value == T {0})
    {
      value = drawSample();
    }
  }

  return value;
}

}; // namespace Random
