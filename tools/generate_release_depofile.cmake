# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.21)

get_filename_component(_basics_tools_dir "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(_basics_repo_root "${_basics_tools_dir}" DIRECTORY)

set(_basics_cmakelists "${_basics_repo_root}/CMakeLists.txt")
if (NOT EXISTS "${_basics_cmakelists}")
  message(FATAL_ERROR "Could not locate basics CMakeLists.txt at ${_basics_cmakelists}")
endif()

if (NOT DEFINED BASICS_RELEASE_VERSION OR "${BASICS_RELEASE_VERSION}" STREQUAL "")
  file(READ "${_basics_cmakelists}" _basics_cmakelists_contents)
  string(REGEX MATCH "project\\(basics VERSION ([0-9]+(\\.[0-9]+)+) LANGUAGES" _basics_version_match "${_basics_cmakelists_contents}")
  if (NOT CMAKE_MATCH_1)
    message(FATAL_ERROR "Failed to parse basics project version from ${_basics_cmakelists}")
  endif()
  set(BASICS_RELEASE_VERSION "${CMAKE_MATCH_1}")
endif()

if (NOT DEFINED BASICS_RELEASE_TAG OR "${BASICS_RELEASE_TAG}" STREQUAL "")
  set(BASICS_RELEASE_TAG "v${BASICS_RELEASE_VERSION}")
endif()

if (NOT DEFINED OUTPUT OR "${OUTPUT}" STREQUAL "")
  set(OUTPUT "${_basics_repo_root}/.run/release-assets/basics.DepoFile")
endif()

if (NOT DEFINED BASICS_RELEASE_SOURCE_URL OR "${BASICS_RELEASE_SOURCE_URL}" STREQUAL "")
  set(BASICS_RELEASE_SOURCE_URL "https://github.com/victorstewart/basics/archive/refs/tags/${BASICS_RELEASE_TAG}.tar.gz")
endif()

get_filename_component(_basics_output_dir "${OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${_basics_output_dir}")

if (NOT DEFINED BASICS_RELEASE_DOWNLOAD_PATH OR "${BASICS_RELEASE_DOWNLOAD_PATH}" STREQUAL "")
  set(BASICS_RELEASE_DOWNLOAD_PATH "${_basics_output_dir}/basics-${BASICS_RELEASE_VERSION}.tar.gz")
endif()

file(
  DOWNLOAD
  "${BASICS_RELEASE_SOURCE_URL}"
  "${BASICS_RELEASE_DOWNLOAD_PATH}"
  STATUS _basics_download_status
  TLS_VERIFY ON
)
list(LENGTH _basics_download_status _basics_download_status_length)
if (_basics_download_status_length LESS 1)
  message(FATAL_ERROR "Download status for ${BASICS_RELEASE_SOURCE_URL} was empty.")
endif()
list(GET _basics_download_status 0 _basics_download_code)
if (NOT _basics_download_code EQUAL 0)
  list(GET _basics_download_status 1 _basics_download_message)
  message(
    FATAL_ERROR
    "Failed to download ${BASICS_RELEASE_SOURCE_URL} to ${BASICS_RELEASE_DOWNLOAD_PATH}: ${_basics_download_message}"
  )
endif()

file(SHA256 "${BASICS_RELEASE_DOWNLOAD_PATH}" BASICS_RELEASE_SOURCE_SHA256)

set(BASICS_PACKAGE_NAME "basics")
set(BASICS_PACKAGE_VERSION "${BASICS_RELEASE_VERSION}")
set(BASICS_PACKAGE_MIMALLOC_MODE "OBJECT")
set(BASICS_PACKAGE_DEPENDENCY_LINK_MODE "STATIC")
set(BASICS_PACKAGE_TIDESDB_ENABLED "OFF")
set(BASICS_PACKAGE_TIDESDB_DEPENDS "")
set(BASICS_PACKAGE_MIMALLOC_DEPENDS "DEPENDS mimalloc VERSION 3.0.1")
set(BASICS_PACKAGE_SOURCE_URL "${BASICS_RELEASE_SOURCE_URL}")
set(BASICS_PACKAGE_SOURCE_SHA256 "${BASICS_RELEASE_SOURCE_SHA256}")
set(
  BASICS_PACKAGE_DIRECT_DEPENDENCY_LINKS
  "SG14::SG14 aegis::aegis bitsery::bitsery gxhash::gxhash itoa::itoa libbpf::libbpf libcurl::libcurl libssh2::libssh2 zlib::zlib liburing::liburing::static nghttp2::nghttp2 openssl simdjson::simdjson static_type_info::static_type_info"
)
set(BASICS_PACKAGE_MIMALLOC_LINK " mimalloc::runtime::object")
set(BASICS_PACKAGE_USE_MIMALLOC 1)
string(
  JOIN
  "\n"
  BASICS_PACKAGE_STAGING_RULES
  "STAGE_TREE SOURCE base include/base"
  "STAGE_TREE SOURCE ebpf include/ebpf"
  "STAGE_TREE SOURCE enums include/enums"
  "STAGE_TREE SOURCE macros include/macros"
  "STAGE_TREE SOURCE networking include/networking"
  "STAGE_TREE SOURCE services include/services"
  "STAGE_TREE SOURCE types include/types"
  "STAGE_FILE SOURCE includes.h include/includes.h"
)

configure_file(
  "${_basics_repo_root}/depofiles/basics.DepoFile.in"
  "${OUTPUT}"
  @ONLY
)

message(STATUS "Wrote detached release DepoFile: ${OUTPUT}")
message(STATUS "Source URL: ${BASICS_RELEASE_SOURCE_URL}")
message(STATUS "SHA256: ${BASICS_RELEASE_SOURCE_SHA256}")
