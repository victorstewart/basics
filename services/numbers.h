// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

uint128_t bitsetToU128(const std::bitset<128>& bitset)
{
  uint128_t result = 0;

  uint8_t *ptr = reinterpret_cast<uint8_t *>(&result);

  for (int i = 0; i < 128; ++i)
  {
    ptr[i / 8] |= (bitset[i] << (i % 8));
  }

  return result;
}

std::bitset<128> u128ToBitset(uint128_t value)
{
  std::bitset<128> result;

  uint8_t *ptr = reinterpret_cast<uint8_t *>(&value);

  for (int byte = 0; byte < 16; ++byte)
  {
    for (int bit = 0; bit < 8; ++bit)
    {
      result[byte * 8 + bit] = (ptr[byte] >> bit) & 1;
    }
  }

  return result;
}
