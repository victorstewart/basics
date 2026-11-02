# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED BASICS_SOURCE_DIR OR "${BASICS_SOURCE_DIR}" STREQUAL "")
  message(FATAL_ERROR "BASICS_SOURCE_DIR is required.")
endif()

file(READ "${BASICS_SOURCE_DIR}/depos.project.cmake" _basics_project_defaults)
if (NOT _basics_project_defaults MATCHES [[set\(DEPOS_BOOTSTRAP_VERSION "0\.5\.6" CACHE STRING "Pinned depos version used by basics" FORCE\)]])
  message(FATAL_ERROR "Basics must pin DEPOS_BOOTSTRAP_VERSION to 0.5.6.")
endif()

file(SHA256 "${BASICS_SOURCE_DIR}/.depos.cmake" _basics_depos_interface_sha256)
set(_basics_expected_depos_interface_sha256 "3443771f5f90ad5b600dbb7f763ce963e69adcee2a7d77d35a3b3f2b5feb9923")
if (NOT _basics_depos_interface_sha256 STREQUAL _basics_expected_depos_interface_sha256)
  message(FATAL_ERROR "Basics .depos.cmake diverged from the pinned Depos 0.5.6 interface: ${_basics_depos_interface_sha256}")
endif()
