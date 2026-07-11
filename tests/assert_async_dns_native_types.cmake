# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

foreach(_basics_async_dns_source IN ITEMS
  networking/async.dns.h
  networking/async.dns.cares.h
  networking/happy.eyeballs.h
  tests/async_dns_tests.cpp
  tests/async_dns_cares_tests.cpp
  tests/happy_eyeballs_tests.cpp
)
  file(READ "${BASICS_SOURCE_DIR}/${_basics_async_dns_source}" _basics_async_dns_contents)
  foreach(_basics_forbidden_token IN ITEMS
    "std::string"
    "std::string_view"
    "std::vector"
    "std::unordered_map"
    "std::unordered_set"
    "std::map<"
    "std::set<"
    "boost::unordered"
    "absl::flat_hash"
    "robin_hood::"
    "ska::flat_hash"
  )
    string(FIND "${_basics_async_dns_contents}" "${_basics_forbidden_token}" _basics_forbidden_index)
    if (NOT _basics_forbidden_index EQUAL -1)
      message(FATAL_ERROR "${_basics_async_dns_source} must use Basics String/Vector/bytell containers, found '${_basics_forbidden_token}'.")
    endif()
  endforeach()
endforeach()

file(READ "${BASICS_SOURCE_DIR}/networking/async.dns.cares.h" _basics_cares_header)
foreach(_basics_required_bind_fragment IN ITEMS
  "LocalSocketBinds udpBinds"
  "LocalSocketBinds tcpBinds"
  "ares_set_socket_configure_callback"
)
  string(FIND
    "${_basics_cares_header}"
    "${_basics_required_bind_fragment}"
    _basics_required_bind_index
  )
  if (_basics_required_bind_index EQUAL -1)
    message(FATAL_ERROR "RingAsyncDnsResolver must retain bounded transport-specific local binds; missing '${_basics_required_bind_fragment}'.")
  endif()
endforeach()
