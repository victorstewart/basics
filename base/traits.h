// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <tuple>
#include <type_traits>

#pragma once

template <typename T>
struct function_traits;

template <typename ReturnType, typename... Args>
struct function_traits<ReturnType (*)(Args...)> {
  using return_type = ReturnType;
  using args_tuple = std::tuple<Args...>;
  constexpr static std::size_t nargs = sizeof...(Args);
  constexpr static bool is_void_return = std::is_same<ReturnType, void>::value;
};

template <typename ClassType, typename ReturnType, typename... Args>
struct function_traits<ReturnType (ClassType::*)(Args...) const> {
  using return_type = ReturnType;
  using args_tuple = std::tuple<Args...>;
  constexpr static std::size_t nargs = sizeof...(Args);
  constexpr static bool is_void_return = std::is_same<ReturnType, void>::value;
};

template <typename Callable>
struct callable_traits : function_traits<decltype(&Callable::operator())> {};

template <typename Base, typename Derived, auto FuncPtr> concept overrides_virtual_function = requires (Derived *d) {
  dynamic_cast<Base *>(d);
  { static_cast<decltype(FuncPtr)>(&Derived::func) } -> std::same_as<decltype(FuncPtr)>;
};