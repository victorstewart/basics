// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

template <uint8_t nFixed, uint8_t nVariable, uint8_t nTailBits = 128 - nFixed - nVariable>
class Subnet6Pool {
private:

  static_assert(nVariable > 0 && nVariable < 64, "nVariable must be greater than 0 and less than 64");
  static_assert(nFixed + nVariable <= 128, "The sum of nFixed and nVariable must be less than or equal to 128");

  bytell_hash_set<uint128_t> fragments;

public:

  std::bitset<128> fixed;

  uint128_t get(void)
  {
    uint128_t fragment;

    do
    {
      fragment = Random::generateNumberWithNBits<nVariable>();

    } while (fragments.contains(fragment));

    fragments.insert(fragment);

    return bitsetToU128(fixed | (u128ToBitset(fragment) << nTailBits));
  }

  IPPrefix getPrefix(void)
  {
    uint128_t address = get();

    IPPrefix prefix;
    memcpy(prefix.network.v6, &address, 16);
    prefix.network.is6 = true;
    prefix.cidr = nFixed + nVariable;

    return prefix;
  }

  void setFixed(uint128_t base)
  {
    fixed = u128ToBitset(base);
  }

  uint128_t getFixed(void)
  {
    return bitsetToU128(fixed);
  }

  void relinquishSubnet(uint128_t subnet) // base + fragment
  {
    std::bitset<128> bits = u128ToBitset(subnet);

    for (size_t i = 128 - nFixed; i < 128; ++i)
    {
      if (bits[i] != fixed[i])
      {
        return;
      }
    }

    for (size_t i = 128 - nFixed; i < 128; ++i) // clear top n bits
    {
      bits[i] = 0;
    }

    bits >>= nTailBits;

    uint128_t fragment = bitsetToU128(bits);

    fragments.erase(fragment);
  }

  void recordFragment(uint128_t fragment)
  {
    fragments.insert(fragment);
  }

  uint32_t count(void)
  {
    return fragments.size();
  }
};
