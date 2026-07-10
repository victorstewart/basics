# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

foreach(_basics_curl_source IN ITEMS
  networking/curl.multi.ring.h
  tests/curl_multi_ring_contract_tests.cpp
  tests/curl_multi_ring_tests.cpp
)
  file(READ "${BASICS_SOURCE_DIR}/${_basics_curl_source}" _basics_curl_contents)

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
    "folly::F14"
    "robin_hood::"
    "ska::flat_hash"
  )
    string(FIND "${_basics_curl_contents}" "${_basics_forbidden_token}" _basics_forbidden_index)
    if (NOT _basics_forbidden_index EQUAL -1)
      message(FATAL_ERROR "${_basics_curl_source} must use Basics String/Vector/bytell containers, found '${_basics_forbidden_token}'.")
    endif()
  endforeach()
endforeach()
