// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <chrono>
#include <concepts>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <limits>
#include <signal.h>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

using uint128_t = __uint128_t;
using int128_t = __int128_t;

#include "includes.h"

inline std::string_view stringViewOf(const String& value)
{
  if (value.size() == 0)
  {
    return {};
  }

  return std::string_view(reinterpret_cast<const char *>(value.data()), value.size());
}

class TestSuite {
private:

  int failures_ = 0;

public:

  void expectTrue(bool condition, const char *expression, const char *file, int line)
  {
    if (!condition)
    {
      ++failures_;
      std::cerr << file << ':' << line << ": expected true: " << expression << '\n';
    }
  }

  void expectFalse(bool condition, const char *expression, const char *file, int line)
  {
    if (condition)
    {
      ++failures_;
      std::cerr << file << ':' << line << ": expected false: " << expression << '\n';
    }
  }

  template <typename Actual, typename Expected>
  void expectEqual(const Actual& actual, const Expected& expected, const char *actualExpr, const char *expectedExpr, const char *file, int line)
  {
    if (!(actual == expected))
    {
      ++failures_;
      std::cerr << file << ':' << line
                << ": expected " << actualExpr << " == " << expectedExpr
                << ", got [" << actual << "] vs [" << expected << "]\n";
    }
  }

  template <typename Expected>
  void expectStringEqual(const String& actual, Expected&& expected, const char *actualExpr, const char *expectedExpr, const char *file, int line)
  {
    String expectedString(std::forward<Expected>(expected));

    if (!actual.equals(expectedString))
    {
      ++failures_;
      std::cerr << file << ':' << line
                << ": expected " << actualExpr << " == " << expectedExpr
                << ", got [" << stringViewOf(actual) << "] vs [" << stringViewOf(expectedString) << "]\n";
    }
  }

  int finish(const char *suiteName) const
  {
    if (failures_ == 0)
    {
      std::cout << suiteName << " passed.\n";
    }
    else
    {
      std::cerr << failures_ << ' ' << suiteName << " test(s) failed.\n";
    }

    return failures_;
  }
};

#define EXPECT_TRUE(suite, expression) (suite).expectTrue((expression), #expression, __FILE__, __LINE__)
#define EXPECT_FALSE(suite, expression) (suite).expectFalse((expression), #expression, __FILE__, __LINE__)
#define EXPECT_EQ(suite, actual, expected) (suite).expectEqual((actual), (expected), #actual, #expected, __FILE__, __LINE__)
#define EXPECT_STRING_EQ(suite, actual, expected) (suite).expectStringEqual((actual), (expected), #actual, #expected, __FILE__, __LINE__)
