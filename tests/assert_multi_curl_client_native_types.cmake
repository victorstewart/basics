# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

foreach(_basics_curl_source IN ITEMS
  networking/socket.h
  networking/multi.curl.client.h
  tests/multi_curl_client_contract_tests.cpp
  tests/multi_curl_client_tests.cpp
)
  file(READ "${BASICS_SOURCE_DIR}/${_basics_curl_source}" _basics_curl_contents)

  foreach(_basics_forbidden_token IN ITEMS
    "std::string"
    "std::string_view"
    "std::vector"
    "std::unordered_"
    "std::map<"
    "std::set<"
    "boost::unordered"
    "absl::flat_hash"
    "folly::F14"
    "robin_hood::"
    "ska::flat_hash"
    "tsl::"
    "ankerl::unordered_dense"
    "phmap::"
    "google::dense_hash"
  )
    string(FIND "${_basics_curl_contents}" "${_basics_forbidden_token}" _basics_forbidden_index)
    if (NOT _basics_forbidden_index EQUAL -1)
      message(FATAL_ERROR "${_basics_curl_source} must use Basics String/Vector/bytell containers, found '${_basics_forbidden_token}'.")
    endif()
  endforeach()
endforeach()

file(READ "${BASICS_SOURCE_DIR}/networking/multi.curl.client.h" _basics_multi_curl_header)
string(FIND "${_basics_multi_curl_header}" "CURLMNWC_CLEAR_CONNS" _basics_curl_reuse_index)
if (_basics_curl_reuse_index EQUAL -1)
  message(FATAL_ERROR "MultiCurlClient must preserve connection-identity reuse enforcement.")
endif()

file(READ "${BASICS_SOURCE_DIR}/networking/socket.h" _basics_socket_header)
foreach(_basics_required_transport_fragment IN ITEMS
  "class LocalSocketBinds"
  "getsockname"
  "sin6_scope_id"
)
  string(FIND
    "${_basics_socket_header}"
    "${_basics_required_transport_fragment}"
    _basics_required_transport_index
  )
  if (_basics_required_transport_index EQUAL -1)
    message(FATAL_ERROR "LocalSocketBinds must preserve exact endpoint enforcement; missing '${_basics_required_transport_fragment}'.")
  endif()
endforeach()

file(READ "${BASICS_SOURCE_DIR}/tests/protocol_client_tests.cpp" _basics_protocol_client_contents)
function(_basics_assert_native_segment begin_marker end_marker)
  string(FIND "${_basics_protocol_client_contents}" "${begin_marker}" _basics_segment_begin)
  string(FIND "${_basics_protocol_client_contents}" "${end_marker}" _basics_segment_end)
  if (_basics_segment_begin EQUAL -1 OR _basics_segment_end EQUAL -1 OR
      _basics_segment_end LESS_EQUAL _basics_segment_begin)
    message(FATAL_ERROR "Missing or malformed native-type guard segment '${begin_marker}'.")
  endif()
  math(EXPR _basics_segment_length "${_basics_segment_end} - ${_basics_segment_begin}")
  string(SUBSTRING
    "${_basics_protocol_client_contents}"
    ${_basics_segment_begin}
    ${_basics_segment_length}
    _basics_native_segment
  )
  foreach(_basics_forbidden_token IN ITEMS
    "std::string"
    "std::string_view"
    "std::vector"
    "std::unordered_"
    "std::map<"
    "std::set<"
  )
    string(FIND "${_basics_native_segment}" "${_basics_forbidden_token}" _basics_forbidden_index)
    if (NOT _basics_forbidden_index EQUAL -1)
      message(FATAL_ERROR "MultiCurlClient protocol coverage must use Basics native containers, found '${_basics_forbidden_token}'.")
    endif()
  endforeach()
endfunction()

_basics_assert_native_segment(
  "BASICS_MULTI_CURL_CERT_NATIVE_BEGIN"
  "BASICS_MULTI_CURL_CERT_NATIVE_END"
)
_basics_assert_native_segment(
  "BASICS_MULTI_CURL_TLS_NATIVE_BEGIN"
  "BASICS_MULTI_CURL_TLS_NATIVE_END"
)

file(GLOB _basics_owned_cpp_sources
  LIST_DIRECTORIES false
  RELATIVE "${BASICS_SOURCE_DIR}"
  "${BASICS_SOURCE_DIR}/*.h"
  "${BASICS_SOURCE_DIR}/*.hh"
  "${BASICS_SOURCE_DIR}/*.hpp"
  "${BASICS_SOURCE_DIR}/*.cc"
  "${BASICS_SOURCE_DIR}/*.cpp"
  "${BASICS_SOURCE_DIR}/*.cxx"
)

foreach(_basics_owned_directory IN ITEMS
  base bpf databases ebpf enums examples integration-tests lib macros networking services src tests tools types
)
  file(GLOB_RECURSE _basics_owned_directory_sources
    LIST_DIRECTORIES false
    RELATIVE "${BASICS_SOURCE_DIR}"
    "${BASICS_SOURCE_DIR}/${_basics_owned_directory}/*.h"
    "${BASICS_SOURCE_DIR}/${_basics_owned_directory}/*.hh"
    "${BASICS_SOURCE_DIR}/${_basics_owned_directory}/*.hpp"
    "${BASICS_SOURCE_DIR}/${_basics_owned_directory}/*.cc"
    "${BASICS_SOURCE_DIR}/${_basics_owned_directory}/*.cpp"
    "${BASICS_SOURCE_DIR}/${_basics_owned_directory}/*.cxx"
  )
  list(APPEND _basics_owned_cpp_sources ${_basics_owned_directory_sources})
endforeach()

foreach(_basics_owned_source IN LISTS _basics_owned_cpp_sources)
  file(READ "${BASICS_SOURCE_DIR}/${_basics_owned_source}" _basics_owned_contents)
  foreach(_basics_forbidden_hash IN ITEMS
    "std::unordered_"
    "boost::unordered"
    "absl::flat_hash"
    "folly::F14"
    "robin_hood::"
    "ska::flat_hash"
    "tsl::"
    "ankerl::unordered_dense"
    "phmap::"
    "google::dense_hash"
  )
    string(FIND "${_basics_owned_contents}" "${_basics_forbidden_hash}" _basics_hash_index)
    if (NOT _basics_hash_index EQUAL -1)
      message(FATAL_ERROR "${_basics_owned_source} must use Basics bytell_hash containers, found '${_basics_forbidden_hash}'.")
    endif()
  endforeach()
endforeach()
