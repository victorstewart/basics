# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Victor Stewart

cmake_minimum_required(VERSION 3.21)

project(basics_downstream_package_consumer LANGUAGES CXX)

include(CTest)

option(BASICS_DOWNSTREAM_ENABLE_TIDESDB "Require the optional TidesDB basics package surface in the downstream smoke consumer" OFF)
option(BASICS_DOWNSTREAM_STATE_PATH_PROBE_ONLY "Configure only far enough to inspect downstream Depos state paths" OFF)

if (NOT DEFINED BASICS_PACKAGE_DEPOFILE OR "${BASICS_PACKAGE_DEPOFILE}" STREQUAL "")
  message(FATAL_ERROR "BASICS_PACKAGE_DEPOFILE must be provided to the downstream package smoke project.")
endif()

if (NOT DEFINED DEPOS_ROOT OR "${DEPOS_ROOT}" STREQUAL "")
  if (DEFINED ENV{DEPOS_ROOT} AND NOT "$ENV{DEPOS_ROOT}" STREQUAL "")
    set(
      DEPOS_ROOT
      "$ENV{DEPOS_ROOT}"
      CACHE PATH
      "Downstream Depos root inherited from ENV{DEPOS_ROOT}"
    )
  else()
    set(
      DEPOS_ROOT
      "${CMAKE_BINARY_DIR}/depos-root"
      CACHE PATH
      "Downstream consumer-local Depos root"
    )
  endif()
endif()
if (NOT DEFINED DEPOS_BOOTSTRAP_DIR OR "${DEPOS_BOOTSTRAP_DIR}" STREQUAL "")
  set(
    DEPOS_BOOTSTRAP_DIR
    "${CMAKE_BINARY_DIR}/depos-bootstrap"
    CACHE PATH
    "Downstream consumer-local Depos bootstrap directory"
  )
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../.depos.cmake")

if (BASICS_DOWNSTREAM_STATE_PATH_PROBE_ONLY)
  return()
endif()

depos_depend("${BASICS_PACKAGE_DEPOFILE}")

add_executable(basics_downstream_package_smoke main.cpp)
target_compile_features(basics_downstream_package_smoke PRIVATE cxx_std_20)
if (BASICS_DOWNSTREAM_ENABLE_TIDESDB)
  target_compile_definitions(basics_downstream_package_smoke PRIVATE BASICS_DOWNSTREAM_ENABLE_TIDESDB=1)
endif()
depos_link(basics_downstream_package_smoke PRIVATE basics::basics cares::cares)

add_test(NAME basics_downstream_package_smoke COMMAND basics_downstream_package_smoke)
