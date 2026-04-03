# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
if (NOT DEFINED BASICS_REPO_ROOT OR "${BASICS_REPO_ROOT}" STREQUAL "")
  message(FATAL_ERROR "BASICS_REPO_ROOT is required.")
endif()

if (NOT DEFINED BASICS_PACKAGE_DEPOFILE OR "${BASICS_PACKAGE_DEPOFILE}" STREQUAL "")
  message(FATAL_ERROR "BASICS_PACKAGE_DEPOFILE is required.")
endif()

if (NOT DEFINED BUILD_DIR OR "${BUILD_DIR}" STREQUAL "")
  message(FATAL_ERROR "BUILD_DIR is required.")
endif()

set(_downstream_source_dir "${BASICS_REPO_ROOT}/tests/downstream_package")

file(REMOVE_RECURSE "${BUILD_DIR}")

set(_configure_args
  -S "${_downstream_source_dir}"
  -B "${BUILD_DIR}"
  "-DBASICS_REPO_ROOT=${BASICS_REPO_ROOT}"
  "-DBASICS_PACKAGE_DEPOFILE=${BASICS_PACKAGE_DEPOFILE}"
)

if (DEFINED BASICS_DOWNSTREAM_ENABLE_TIDESDB AND NOT "${BASICS_DOWNSTREAM_ENABLE_TIDESDB}" STREQUAL "")
  list(APPEND _configure_args "-DBASICS_DOWNSTREAM_ENABLE_TIDESDB=${BASICS_DOWNSTREAM_ENABLE_TIDESDB}")
endif()

if (DEFINED GENERATOR AND NOT "${GENERATOR}" STREQUAL "")
  list(PREPEND _configure_args -G "${GENERATOR}")
endif()

if (DEFINED CXX_COMPILER AND NOT "${CXX_COMPILER}" STREQUAL "")
  list(APPEND _configure_args "-DCMAKE_CXX_COMPILER=${CXX_COMPILER}")
endif()

if (DEFINED CMAKE_BUILD_TYPE_VALUE AND NOT "${CMAKE_BUILD_TYPE_VALUE}" STREQUAL "")
  list(APPEND _configure_args "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE_VALUE}")
endif()

if (DEFINED CMAKE_MAKE_PROGRAM_VALUE AND NOT "${CMAKE_MAKE_PROGRAM_VALUE}" STREQUAL "")
  list(APPEND _configure_args "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM_VALUE}")
endif()

if (DEFINED DEPOS_EXECUTABLE_VALUE AND NOT "${DEPOS_EXECUTABLE_VALUE}" STREQUAL "")
  list(APPEND _configure_args "-DDEPOS_EXECUTABLE=${DEPOS_EXECUTABLE_VALUE}")
endif()

if (DEFINED DEPOS_ROOT_VALUE AND NOT "${DEPOS_ROOT_VALUE}" STREQUAL "")
  list(APPEND _configure_args "-DDEPOS_ROOT=${DEPOS_ROOT_VALUE}")
endif()

if (DEFINED DEPOS_BOOTSTRAP_DIR_VALUE AND NOT "${DEPOS_BOOTSTRAP_DIR_VALUE}" STREQUAL "")
  list(APPEND _configure_args "-DDEPOS_BOOTSTRAP_DIR=${DEPOS_BOOTSTRAP_DIR_VALUE}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" ${_configure_args}
  RESULT_VARIABLE _configure_result
)

if (NOT _configure_result EQUAL 0)
  message(FATAL_ERROR "Failed to configure downstream basics package smoke project.")
endif()

include(ProcessorCount)
ProcessorCount(_downstream_parallelism)
if (_downstream_parallelism EQUAL 0)
  set(_downstream_parallelism 1)
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" --build "${BUILD_DIR}" --parallel "${_downstream_parallelism}"
  RESULT_VARIABLE _build_result
)

if (NOT _build_result EQUAL 0)
  message(FATAL_ERROR "Failed to build downstream basics package smoke project.")
endif()

execute_process(
  COMMAND "${CMAKE_CTEST_COMMAND}" --test-dir "${BUILD_DIR}" --output-on-failure
  RESULT_VARIABLE _test_result
)

if (NOT _test_result EQUAL 0)
  message(FATAL_ERROR "Failed to run downstream basics package smoke project.")
endif()

if (DEFINED EXPECT_MIMALLOC_OBJECT_INTERPOSITION AND EXPECT_MIMALLOC_OBJECT_INTERPOSITION)
  set(_downstream_link_txt "${BUILD_DIR}/CMakeFiles/basics_downstream_package_smoke.dir/link.txt")
  set(_downstream_executable "${BUILD_DIR}/basics_downstream_package_smoke")

  if (NOT EXISTS "${_downstream_link_txt}")
    message(FATAL_ERROR "Expected downstream link.txt was not produced: ${_downstream_link_txt}")
  endif()
  if (NOT EXISTS "${_downstream_executable}")
    message(FATAL_ERROR "Expected downstream executable was not produced: ${_downstream_executable}")
  endif()

  file(READ "${_downstream_link_txt}" _downstream_link_line)
  string(FIND "${_downstream_link_line}" "mimalloc.o" _downstream_mimalloc_index)
  string(FIND "${_downstream_link_line}" "main.cpp.o" _downstream_main_index)
  if (_downstream_mimalloc_index EQUAL -1)
    message(FATAL_ERROR "Downstream OBJECT-mode executable link line did not include mimalloc.o:\n${_downstream_link_line}")
  endif()
  if (_downstream_main_index EQUAL -1)
    message(FATAL_ERROR "Downstream OBJECT-mode executable link line did not include main.cpp.o:\n${_downstream_link_line}")
  endif()
  if (_downstream_mimalloc_index GREATER _downstream_main_index)
    message(FATAL_ERROR "Downstream OBJECT-mode executable did not place mimalloc.o before main.cpp.o:\n${_downstream_link_line}")
  endif()

  execute_process(
    COMMAND nm -C "${_downstream_executable}"
    RESULT_VARIABLE _downstream_nm_result
    OUTPUT_VARIABLE _downstream_nm_stdout
    ERROR_VARIABLE _downstream_nm_stderr
  )
  if (NOT _downstream_nm_result EQUAL 0)
    message(
      FATAL_ERROR
      "Failed to inspect downstream executable symbols with nm.\n"
      "stdout:\n${_downstream_nm_stdout}\n"
      "stderr:\n${_downstream_nm_stderr}"
    )
  endif()

  foreach(_downstream_symbol IN ITEMS " T malloc" " T free" " T calloc" " T realloc")
    string(FIND "${_downstream_nm_stdout}" "${_downstream_symbol}" _downstream_symbol_index)
    if (_downstream_symbol_index EQUAL -1)
      message(
        FATAL_ERROR
        "Downstream OBJECT-mode executable did not export expected allocator override symbol '${_downstream_symbol}'.\n"
        "nm output:\n${_downstream_nm_stdout}"
      )
    endif()
  endforeach()
endif()
