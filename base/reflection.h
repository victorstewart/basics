// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <string_view>

#pragma once

template <class T>
constexpr std::string_view type_name()
{
#ifdef __clang__
  std::string_view prettyFunction = __PRETTY_FUNCTION__;
  return std::string_view(prettyFunction.data() + 34, prettyFunction.size() - 35);
#elif defined(__GNUC__)
  std::string_view prettyFunction = __PRETTY_FUNCTION__;
#  if __cplusplus < 201402L
  return std::string_view(prettyFunction.data() + 36, prettyFunction.size() - 37);
#  else
  return std::string_view(prettyFunction.data() + 49, prettyFunction.find(';', 49) - 49);
#  endif
#elif defined(_MSC_VER)
  std::string_view functionSignature = __FUNCSIG__;
  return std::string_view(functionSignature.data() + 84, functionSignature.size() - 91);
#else
  return {};
#endif
}
