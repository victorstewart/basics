# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED BASICS_SOURCE_DIR OR "${BASICS_SOURCE_DIR}" STREQUAL "")
  message(FATAL_ERROR "BASICS_SOURCE_DIR is required.")
endif()
file(READ "${BASICS_SOURCE_DIR}/networking/ring.h" _basics_ring)
set(_basics_create_ring_logging_guard [=[static void writeCreateRingStage(const char *stage)
  {
#if NAMETAG_ENABLE_DEBUG_LOGS]=])
string(FIND "${_basics_ring}" "${_basics_create_ring_logging_guard}"
  _basics_create_ring_logging_guard_index)
if (_basics_create_ring_logging_guard_index EQUAL -1)
  message(FATAL_ERROR
    "Ring::createRing diagnostic bootstage writes must be compile-time gated.")
endif()
