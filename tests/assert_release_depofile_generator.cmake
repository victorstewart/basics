# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED BASICS_SOURCE_DIR OR "${BASICS_SOURCE_DIR}" STREQUAL "")
  message(FATAL_ERROR "BASICS_SOURCE_DIR is required.")
endif()

if (NOT DEFINED TEST_ROOT OR "${TEST_ROOT}" STREQUAL "")
  set(TEST_ROOT "${BASICS_SOURCE_DIR}/.run/release-depofile-generator-contract")
endif()

set(_basics_generator "${BASICS_SOURCE_DIR}/tools/generate_release_depofile.cmake")
set(_basics_archive "${TEST_ROOT}/basics-0.4.5.tar.gz")
set(_basics_final_url "https://example.invalid/basics/releases/download/v0.4.5/basics-0.4.5.tar.gz")
set(_basics_local_output "${TEST_ROOT}/local-archive.DepoFile")
set(_basics_downloaded_archive "${TEST_ROOT}/downloaded-basics-0.4.5.tar.gz")
set(_basics_url_output "${TEST_ROOT}/url-only.DepoFile")

file(REMOVE_RECURSE "${TEST_ROOT}")
file(MAKE_DIRECTORY "${TEST_ROOT}")
file(WRITE "${_basics_archive}" "deterministic release archive fixture\n")
file(SHA256 "${_basics_archive}" _basics_expected_sha256)

execute_process(
  COMMAND
    "${CMAKE_COMMAND}"
      "-DBASICS_RELEASE_VERSION=0.4.5"
      "-DBASICS_RELEASE_SOURCE_ARCHIVE=${_basics_archive}"
      "-DBASICS_RELEASE_SOURCE_URL=${_basics_final_url}"
      "-DOUTPUT=${_basics_local_output}"
      -P "${_basics_generator}"
  RESULT_VARIABLE _basics_local_result
  ERROR_VARIABLE _basics_local_error
)
if (NOT _basics_local_result EQUAL 0)
  message(FATAL_ERROR "Local-archive release DepoFile generation failed:\n${_basics_local_error}")
endif()

file(READ "${_basics_local_output}" _basics_local_depofile)
foreach(_basics_required_line IN ITEMS
  "SOURCE URL ${_basics_final_url}"
  "SHA256 ${_basics_expected_sha256}"
)
  string(FIND "${_basics_local_depofile}" "${_basics_required_line}" _basics_required_line_index)
  if (_basics_required_line_index EQUAL -1)
    message(FATAL_ERROR "Local-archive release DepoFile is missing '${_basics_required_line}'.")
  endif()
endforeach()
string(FIND "${_basics_local_depofile}" "file://${_basics_archive}" _basics_local_path_index)
if (NOT _basics_local_path_index EQUAL -1)
  message(FATAL_ERROR "Detached release DepoFile leaked its local checksum source path.")
endif()

execute_process(
  COMMAND
    "${CMAKE_COMMAND}"
      "-DBASICS_RELEASE_VERSION=0.4.5"
      "-DBASICS_RELEASE_SOURCE_URL=file://${_basics_archive}"
      "-DBASICS_RELEASE_DOWNLOAD_PATH=${_basics_downloaded_archive}"
      "-DOUTPUT=${_basics_url_output}"
      -P "${_basics_generator}"
  RESULT_VARIABLE _basics_url_result
  ERROR_VARIABLE _basics_url_error
)
if (NOT _basics_url_result EQUAL 0)
  message(FATAL_ERROR "URL-only release DepoFile generation failed:\n${_basics_url_error}")
endif()
file(SHA256 "${_basics_downloaded_archive}" _basics_downloaded_sha256)
if (NOT _basics_downloaded_sha256 STREQUAL _basics_expected_sha256)
  message(FATAL_ERROR "URL-only generation did not checksum the downloaded source bytes.")
endif()

execute_process(
  COMMAND
    "${CMAKE_COMMAND}"
      "-DBASICS_RELEASE_VERSION=0.4.5"
      "-DBASICS_RELEASE_SOURCE_ARCHIVE=${_basics_archive}"
      "-DOUTPUT=${TEST_ROOT}/missing-url.DepoFile"
      -P "${_basics_generator}"
  RESULT_VARIABLE _basics_missing_url_result
)
if (_basics_missing_url_result EQUAL 0)
  message(FATAL_ERROR "Local-archive generation accepted an implicit URL that may identify different bytes.")
endif()
