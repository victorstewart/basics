# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

foreach(_basics_curl_source IN ITEMS
  networking/socket.h
  networking/socket.bind.pool.h
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
foreach(_basics_forbidden_resolver_fragment IN ITEMS
  "async.dns.cares.h"
  "RingAsyncDnsResolver"
  "dnsBackend"
  "CURL_VERSION_ASYNCHDNS"
  "resolver.shutdown"
  "resolver.shutdownSafe"
)
  string(FIND
    "${_basics_multi_curl_header}"
    "${_basics_forbidden_resolver_fragment}"
    _basics_forbidden_resolver_index
  )
  if (NOT _basics_forbidden_resolver_index EQUAL -1)
    message(FATAL_ERROR "MultiCurlClient must use only the injected AsyncDnsClient, found '${_basics_forbidden_resolver_fragment}'.")
  endif()
endforeach()
foreach(_basics_required_resolver_fragment IN ITEMS
  "#include <networking/async.dns.h>"
  "AsyncDnsClient& resolver"
  "MultiCurlClient(AsyncDnsClient& requestedResolver"
  "resolver(requestedResolver)"
  "CURLOPT_RESOLVE, transfer.resolveRules"
)
  string(FIND
    "${_basics_multi_curl_header}"
    "${_basics_required_resolver_fragment}"
    _basics_required_resolver_index
  )
  if (_basics_required_resolver_index EQUAL -1)
    message(FATAL_ERROR "MultiCurlClient must preserve non-owning resolver injection; missing '${_basics_required_resolver_fragment}'.")
  endif()
endforeach()

file(GLOB_RECURSE _basics_networking_production_sources
  LIST_DIRECTORIES false
  RELATIVE "${BASICS_SOURCE_DIR}"
  "${BASICS_SOURCE_DIR}/networking/*.h"
  "${BASICS_SOURCE_DIR}/networking/*.hh"
  "${BASICS_SOURCE_DIR}/networking/*.hpp"
  "${BASICS_SOURCE_DIR}/networking/*.cc"
  "${BASICS_SOURCE_DIR}/networking/*.cpp"
  "${BASICS_SOURCE_DIR}/networking/*.cxx"
)
list(SORT _basics_networking_production_sources)
foreach(_basics_networking_source IN LISTS _basics_networking_production_sources)
  file(READ
    "${BASICS_SOURCE_DIR}/${_basics_networking_source}"
    _basics_networking_contents
  )
  foreach(_basics_blocking_resolver IN ITEMS
    getaddrinfo
    getaddrinfo_a
    freeaddrinfo
    gethostbyaddr
    gethostbyname
    gethostent
    getnameinfo
    res_query
    res_search
    res_send
  )
    if (_basics_networking_contents MATCHES
        "(^|[^A-Za-z0-9_])${_basics_blocking_resolver}[ \t\r\n]*\\(")
      message(FATAL_ERROR
        "${_basics_networking_source} owns blocking name resolution through '${_basics_blocking_resolver}'."
      )
    endif()
  endforeach()

  if (NOT _basics_networking_source STREQUAL "networking/async.dns.cares.h" AND
      _basics_networking_contents MATCHES "(^|[^A-Za-z0-9_])ares_[A-Za-z0-9_]+")
    message(FATAL_ERROR
      "${_basics_networking_source} owns c-ares outside the explicit RingAsyncDnsResolver backend."
    )
  endif()
endforeach()

file(READ "${BASICS_SOURCE_DIR}/depofiles/libcurl.DepoFile" _basics_libcurl_depofile)
foreach(_basics_forbidden_libcurl_source_patch IN ITEMS
  "patch -p"
  "CURL_PATCH"
  "--- a/lib/"
)
  string(FIND
    "${_basics_libcurl_depofile}"
    "${_basics_forbidden_libcurl_source_patch}"
    _basics_forbidden_libcurl_source_patch_index
  )
  if (NOT _basics_forbidden_libcurl_source_patch_index EQUAL -1)
    message(FATAL_ERROR
      "The generic Basics libcurl recipe must not patch third-party source; found '${_basics_forbidden_libcurl_source_patch}'."
    )
  endif()
endforeach()
file(READ "${BASICS_SOURCE_DIR}/CMakeLists.txt" _basics_cmakelists)
string(FIND
  "${_basics_cmakelists}"
  "bitsery::bitsery cares::cares gxhash::gxhash"
  _basics_self_transitive_cares_index
)
if (NOT _basics_self_transitive_cares_index EQUAL -1)
  message(FATAL_ERROR "CMakeLists.txt must not link c-ares transitively through basics::basics.")
endif()

file(READ
  "${BASICS_SOURCE_DIR}/tools/generate_release_depofile.cmake"
  _basics_release_depofile_generator
)
string(FIND
  "${_basics_release_depofile_generator}"
  "cares::cares"
  _basics_release_transitive_cares_index
)
if (NOT _basics_release_transitive_cares_index EQUAL -1)
  message(FATAL_ERROR "The release basics package must leave c-ares for explicit resolver-server linkage.")
endif()

string(FIND "${_basics_multi_curl_header}" "CURLMNWC_CLEAR_CONNS" _basics_curl_reuse_index)
if (_basics_curl_reuse_index EQUAL -1)
  message(FATAL_ERROR "MultiCurlClient must preserve connection-identity reuse enforcement.")
endif()

foreach(_basics_required_http_method_fragment IN ITEMS
  "case Method::patch:"
  "CURLOPT_CUSTOMREQUEST, \"PATCH\""
)
  string(FIND
    "${_basics_multi_curl_header}"
    "${_basics_required_http_method_fragment}"
    _basics_required_http_method_index
  )
  if (_basics_required_http_method_index EQUAL -1)
    message(FATAL_ERROR
      "MultiCurlClient is missing generic HTTP method support '${_basics_required_http_method_fragment}'."
    )
  endif()
endforeach()

file(READ "${BASICS_SOURCE_DIR}/networking/socket.bind.pool.h" _basics_socket_header)
foreach(_basics_required_transport_fragment IN ITEMS
  "class LocalSocketBindSet"
  "class LocalSocketBindPool"
  "getsockname"
  "sin6_scope_id"
)
  string(FIND
    "${_basics_socket_header}"
    "${_basics_required_transport_fragment}"
    _basics_required_transport_index
  )
  if (_basics_required_transport_index EQUAL -1)
    message(FATAL_ERROR "Local socket bind pooling must preserve exact endpoint enforcement; missing '${_basics_required_transport_fragment}'.")
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
