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
file(READ "${BASICS_SOURCE_DIR}/networking/async.dns.h" _basics_dns_header)
foreach(_basics_required_client_fragment IN ITEMS
  "class AsyncDnsClient"
  "virtual bool ready(void) const = 0"
  "virtual Ticket resolve("
  "virtual bool cancel(Ticket ticket) = 0"
)
  string(FIND
    "${_basics_dns_header}"
    "${_basics_required_client_fragment}"
    _basics_required_client_index
  )
  if (_basics_required_client_index EQUAL -1)
    message(FATAL_ERROR "Async DNS must expose the minimal non-owning client seam; missing '${_basics_required_client_fragment}'.")
  endif()
endforeach()
string(FIND
  "${_basics_cares_header}"
  "class RingAsyncDnsResolver final : public AsyncDnsClient"
  _basics_cares_client_index
)
if (_basics_cares_client_index EQUAL -1)
  message(FATAL_ERROR "RingAsyncDnsResolver must implement AsyncDnsClient.")
endif()
foreach(_basics_required_bind_fragment IN ITEMS
  "LocalSocketBindSet udpBinds"
  "LocalSocketBindSet tcpBinds"
  "ares_set_socket_functions_ex"
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

file(READ "${BASICS_SOURCE_DIR}/networking/multi.curl.client.h" _basics_multi_curl_header)
foreach(_basics_required_http_fragment IN ITEMS
  "MultiCurlClient(AsyncDnsClient& requestedResolver"
  "CURLOPT_RESOLVE"
)
  string(FIND
    "${_basics_multi_curl_header}"
    "${_basics_required_http_fragment}"
    _basics_required_http_index
  )
  if (_basics_required_http_index EQUAL -1)
    message(FATAL_ERROR "MultiCurlClient must use injected, pinned DNS results; missing '${_basics_required_http_fragment}'.")
  endif()
endforeach()

file(GLOB_RECURSE _basics_production_sources
  LIST_DIRECTORIES false
  RELATIVE "${BASICS_SOURCE_DIR}"
  "${BASICS_SOURCE_DIR}/networking/*.h"
  "${BASICS_SOURCE_DIR}/networking/*.hh"
  "${BASICS_SOURCE_DIR}/networking/*.hpp"
  "${BASICS_SOURCE_DIR}/networking/*.c"
  "${BASICS_SOURCE_DIR}/networking/*.cc"
  "${BASICS_SOURCE_DIR}/networking/*.cpp"
  "${BASICS_SOURCE_DIR}/services/*.h"
  "${BASICS_SOURCE_DIR}/services/*.hh"
  "${BASICS_SOURCE_DIR}/services/*.hpp"
  "${BASICS_SOURCE_DIR}/services/*.c"
  "${BASICS_SOURCE_DIR}/services/*.cc"
  "${BASICS_SOURCE_DIR}/services/*.cpp"
)
list(SORT _basics_production_sources)
foreach(_basics_source IN LISTS _basics_production_sources)
  if (_basics_source STREQUAL "networking/async.dns.cares.h")
    continue()
  endif()
  file(READ "${BASICS_SOURCE_DIR}/${_basics_source}" _basics_source_contents)
  foreach(_basics_forbidden_resolver IN ITEMS
    "<netdb.h>"
    "getaddrinfo"
    "getaddrinfo_a"
    "freeaddrinfo"
    "gethostbyaddr"
    "gethostbyname"
    "getnameinfo"
    "res_query"
    "res_search"
    "res_send"
    "curl_easy_perform"
  )
    string(FIND "${_basics_source_contents}" "${_basics_forbidden_resolver}" _basics_forbidden_resolver_index)
    if (NOT _basics_forbidden_resolver_index EQUAL -1)
      message(FATAL_ERROR "${_basics_source} owns blocking resolution/HTTP outside the explicit c-ares backend: '${_basics_forbidden_resolver}'.")
    endif()
  endforeach()
endforeach()
