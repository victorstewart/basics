# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.21)

if (NOT DEFINED CXX_COMPILER)
  message(FATAL_ERROR "CXX_COMPILER is required")
endif()

if (NOT DEFINED TEST_SOURCE)
  message(FATAL_ERROR "TEST_SOURCE is required")
endif()

if (NOT DEFINED OUTPUT_OBJECT)
  message(FATAL_ERROR "OUTPUT_OBJECT is required")
endif()

set(command "${CXX_COMPILER}" "-std=c++20")

foreach(include_dir IN LISTS INCLUDE_DIRS)
  if (NOT include_dir STREQUAL "")
    list(APPEND command "-I${include_dir}")
  endif()
endforeach()

foreach(compile_definition IN LISTS COMPILE_DEFINITIONS)
  if (NOT compile_definition STREQUAL "")
    list(APPEND command "-D${compile_definition}")
  endif()
endforeach()

list(APPEND command "-c" "${TEST_SOURCE}" "-o" "${OUTPUT_OBJECT}")

execute_process(
  COMMAND ${command}
  RESULT_VARIABLE compile_result
  OUTPUT_VARIABLE compile_stdout
  ERROR_VARIABLE compile_stderr
)

if (compile_result EQUAL 0)
  string(JOIN " " rendered_command ${command})
  message(FATAL_ERROR "Compilation unexpectedly succeeded for ${TEST_SOURCE}\nCommand: ${rendered_command}")
endif()

message(STATUS "Expected compile failure observed for ${TEST_SOURCE}")
