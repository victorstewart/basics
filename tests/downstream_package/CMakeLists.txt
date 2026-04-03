# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Victor Stewart

cmake_minimum_required(VERSION 3.21)

project(basics_downstream_package_consumer LANGUAGES CXX)

include(CTest)

if (NOT DEFINED BASICS_REPO_ROOT OR "${BASICS_REPO_ROOT}" STREQUAL "")
  message(FATAL_ERROR "BASICS_REPO_ROOT must be provided to the downstream package smoke project.")
endif()

if (NOT DEFINED BASICS_PACKAGE_DEPOFILE OR "${BASICS_PACKAGE_DEPOFILE}" STREQUAL "")
  message(FATAL_ERROR "BASICS_PACKAGE_DEPOFILE must be provided to the downstream package smoke project.")
endif()

include("${BASICS_REPO_ROOT}/.depos.cmake")

file(GLOB _basics_dependency_depofiles CONFIGURE_DEPENDS "${BASICS_REPO_ROOT}/depofiles/*.DepoFile")
list(SORT _basics_dependency_depofiles)
depos_depend(FILES ${_basics_dependency_depofiles} "${BASICS_PACKAGE_DEPOFILE}")

add_executable(basics_downstream_package_smoke main.cpp)
target_compile_features(basics_downstream_package_smoke PRIVATE cxx_std_20)
depos_link(basics_downstream_package_smoke PRIVATE basics::basics)

add_test(NAME basics_downstream_package_smoke COMMAND basics_downstream_package_smoke)
