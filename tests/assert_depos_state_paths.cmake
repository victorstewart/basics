# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED BASICS_SOURCE_DIR OR "${BASICS_SOURCE_DIR}" STREQUAL "")
  message(FATAL_ERROR "BASICS_SOURCE_DIR is required.")
endif()
if (NOT DEFINED BASICS_STATE_PATH_TEST_ROOT OR "${BASICS_STATE_PATH_TEST_ROOT}" STREQUAL "")
  message(FATAL_ERROR "BASICS_STATE_PATH_TEST_ROOT is required.")
endif()

function(_basics_require_cache_path build_dir variable expected)
  file(STRINGS "${build_dir}/CMakeCache.txt" _cache_lines REGEX "^${variable}:PATH=")
  list(LENGTH _cache_lines _cache_line_count)
  if (NOT _cache_line_count EQUAL 1)
    message(FATAL_ERROR "${build_dir} must contain exactly one ${variable}:PATH cache entry.")
  endif()
  list(GET _cache_lines 0 _cache_line)
  if (NOT _cache_line STREQUAL "${variable}:PATH=${expected}")
    message(FATAL_ERROR "${build_dir} selected '${_cache_line}', expected ${variable}:PATH=${expected}.")
  endif()
endfunction()

function(_basics_run_state_path_probe label)
  set(options)
  set(one_value_args ROOT)
  set(multi_value_args ENVIRONMENT CMAKE_ARGS)
  cmake_parse_arguments(PROBE "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})
  if (NOT DEFINED PROBE_ROOT OR "${PROBE_ROOT}" STREQUAL "")
    message(FATAL_ERROR "${label} requires ROOT.")
  endif()

  set(_build_dir "${BASICS_STATE_PATH_TEST_ROOT}/${label}")
  execute_process(
    COMMAND
      "${CMAKE_COMMAND}" -E env --unset=DEPOS_ROOT ${PROBE_ENVIRONMENT}
      "${CMAKE_COMMAND}"
      -S "${BASICS_SOURCE_DIR}"
      -B "${_build_dir}"
      -DBASICS_VALIDATE_DEPOS_STATE_PATHS_ONLY=ON
      ${PROBE_CMAKE_ARGS}
    RESULT_VARIABLE _configure_result
    OUTPUT_VARIABLE _configure_stdout
    ERROR_VARIABLE _configure_stderr
  )
  if (NOT _configure_result EQUAL 0)
    message(FATAL_ERROR
      "${label} state-path configure failed (${_configure_result}).\nstdout:\n${_configure_stdout}\nstderr:\n${_configure_stderr}")
  endif()

  _basics_require_cache_path("${_build_dir}" DEPOS_ROOT "${PROBE_ROOT}")
  _basics_require_cache_path("${_build_dir}" DEPOS_BOOTSTRAP_DIR "${_build_dir}/depos-bootstrap")
endfunction()

file(REMOVE_RECURSE "${BASICS_STATE_PATH_TEST_ROOT}")
file(MAKE_DIRECTORY "${BASICS_STATE_PATH_TEST_ROOT}")

_basics_run_state_path_probe(
  default
  ROOT "${BASICS_STATE_PATH_TEST_ROOT}/default/depos-root"
)
_basics_run_state_path_probe(
  explicit
  ROOT "${BASICS_STATE_PATH_TEST_ROOT}/explicit-root"
  CMAKE_ARGS "-DDEPOS_ROOT:PATH=${BASICS_STATE_PATH_TEST_ROOT}/explicit-root"
)
_basics_run_state_path_probe(
  environment
  ROOT "${BASICS_STATE_PATH_TEST_ROOT}/environment-root"
  ENVIRONMENT "DEPOS_ROOT=${BASICS_STATE_PATH_TEST_ROOT}/environment-root"
)
