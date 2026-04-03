// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <type_traits>

#pragma once

template <typename Enum>
struct EnableBitMaskOperators {
  static const bool enable = false;
};

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator!=(Enum lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;

  return (static_cast<underlying>(lhs) != static_cast<underlying>(rhs));
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator!(Enum value)
{
  using underlying = typename std::underlying_type<Enum>::type;

  return (static_cast<underlying>(value) == 0);
}

// aka, has all these bits
template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator&(Enum lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<bool>(
      (static_cast<underlying>(lhs) & static_cast<underlying>(rhs)) == static_cast<underlying>(rhs));
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type
    operator|(Enum lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<Enum>(
      static_cast<underlying>(lhs) |
      static_cast<underlying>(rhs));
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type
    operator^(Enum lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<Enum>(
      static_cast<underlying>(lhs) ^
      static_cast<underlying>(rhs));
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type
    operator~(Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<Enum>(
      ~static_cast<underlying>(rhs));
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type&
    operator|=(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  lhs = static_cast<Enum>(
      static_cast<underlying>(lhs) |
      static_cast<underlying>(rhs));

  return lhs;
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator<(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<underlying>(lhs) < static_cast<underlying>(rhs);
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator>(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<underlying>(lhs) > static_cast<underlying>(rhs);
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator>=(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<underlying>(lhs) >= static_cast<underlying>(rhs);
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, bool>::type
    operator<=(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<underlying>(lhs) <= static_cast<underlying>(rhs);
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type&
    operator&=(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  lhs = static_cast<Enum>(
      static_cast<underlying>(lhs) &
      static_cast<underlying>(rhs));

  return lhs;
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type
    operator+(Enum lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<Enum>(static_cast<underlying>(lhs) + static_cast<underlying>(rhs));
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, void>::type
    operator++(Enum& lhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  lhs = static_cast<Enum>(static_cast<underlying>(lhs) + 1);
}

template <typename Enum>
constexpr
    typename std::enable_if<EnableBitMaskOperators<Enum>::enable, Enum>::type&
    operator^=(Enum& lhs, Enum rhs)
{
  using underlying = typename std::underlying_type<Enum>::type;
  lhs = static_cast<Enum>(
      static_cast<underlying>(lhs) ^
      static_cast<underlying>(rhs));

  return lhs;
}

template <typename Enum>
static bool hasAny(Enum haystack, Enum needles)
{
  using underlying = typename std::underlying_type<Enum>::type;
  return static_cast<bool>(static_cast<underlying>(haystack) & static_cast<underlying>(needles));
}

template <typename Enum>
struct EnableStringFormatingForEnum {
  static const bool enable = false;
};

#define ENABLE_ENUM_STRING_FORMATTING(x)   \
  template <>                              \
  struct EnableStringFormatingForEnum<x> { \
    static const bool enable = true;       \
  };

#define ENABLE_BITMASK_OPERATORS(x)  \
  template <>                        \
  struct EnableBitMaskOperators<x> { \
    static const bool enable = true; \
  };
