# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Victor Stewart

cmake_minimum_required(VERSION 3.21)

project(basics_downstream_package_consumer LANGUAGES CXX)

include(CTest)

option(BASICS_DOWNSTREAM_ENABLE_TIDESDB "Require the optional TidesDB basics package surface in the downstream smoke consumer" OFF)

if (NOT DEFINED BASICS_PACKAGE_DEPOFILE OR "${BASICS_PACKAGE_DEPOFILE}" STREQUAL "")
  message(FATAL_ERROR "BASICS_PACKAGE_DEPOFILE must be provided to the downstream package smoke project.")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../.depos.cmake")

depos_depend("${BASICS_PACKAGE_DEPOFILE}")

add_executable(basics_downstream_package_smoke main.cpp)
target_compile_features(basics_downstream_package_smoke PRIVATE cxx_std_20)
if (BASICS_DOWNSTREAM_ENABLE_TIDESDB)
  target_compile_definitions(basics_downstream_package_smoke PRIVATE BASICS_DOWNSTREAM_ENABLE_TIDESDB=1)
endif()
depos_link(basics_downstream_package_smoke PRIVATE basics::basics)

add_test(NAME basics_downstream_package_smoke COMMAND basics_downstream_package_smoke)
