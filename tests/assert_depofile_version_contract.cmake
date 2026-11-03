# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED BASICS_SOURCE_DIR OR "${BASICS_SOURCE_DIR}" STREQUAL "")
  message(FATAL_ERROR "BASICS_SOURCE_DIR is required.")
endif()
if (NOT DEFINED TEST_ROOT OR "${TEST_ROOT}" STREQUAL "")
  message(FATAL_ERROR "TEST_ROOT is required.")
endif()

file(REMOVE_RECURSE "${TEST_ROOT}")
file(MAKE_DIRECTORY "${TEST_ROOT}")

function(_basics_write_fixture path package_version dependency_version)
  file(WRITE "${path}" "NAME version-contract-fixture\nVERSION ${package_version}\nDEPENDS fixture VERSION ${dependency_version}\n")
endfunction()

function(_basics_configure_contract label fixture expect_success)
  set(_basics_build "${TEST_ROOT}/${label}")
  execute_process(
    COMMAND "${CMAKE_COMMAND}"
      -S "${BASICS_SOURCE_DIR}"
      -B "${_basics_build}"
      -DBASICS_MIMALLOC_MODE=NONE
      -DBASICS_DEPENDENCY_LINK_MODE=STATIC
      -DBASICS_VALIDATE_DEPOFILE_VERSIONS_ONLY=ON
      "-DBASICS_VERSION_CONTRACT_EXTRA_DEPOFILE=${fixture}"
    RESULT_VARIABLE _basics_result
    OUTPUT_VARIABLE _basics_output
    ERROR_VARIABLE _basics_error
  )
  if (expect_success AND NOT _basics_result EQUAL 0)
    message(FATAL_ERROR "${label} unexpectedly rejected:\n${_basics_output}\n${_basics_error}")
  elseif (NOT expect_success AND _basics_result EQUAL 0)
    message(FATAL_ERROR "${label} unexpectedly accepted.")
  endif()
endfunction()

# This configures the source-owned generated self DepoFile at the exact path
# published in Basics source archives. Its rc.4 VERSION must not be rejected.
set(_basics_valid "${TEST_ROOT}/valid.DepoFile")
_basics_write_fixture("${_basics_valid}" "0.4.14-rc.4" "1.2.3-rc.7")
_basics_configure_contract(valid_rc "${_basics_valid}" TRUE)
set(_basics_self_depofile "${TEST_ROOT}/valid_rc/.deps/basics-self/basics.DepoFile")
if (NOT EXISTS "${_basics_self_depofile}")
  message(FATAL_ERROR "Version-only configuration did not generate the published self DepoFile.")
endif()
file(READ "${_basics_self_depofile}" _basics_self_contents)
string(FIND "${_basics_self_contents}" "VERSION 0.4.14-rc.4" _basics_self_version_index)
if (_basics_self_version_index EQUAL -1)
  message(FATAL_ERROR "Published self DepoFile does not preserve Basics rc.4 release identity.")
endif()

foreach(_basics_case IN ITEMS
  "label:0.4.14-preview.2:1.2.3"
  "rc_zero:0.4.14-rc.0:1.2.3"
  "suffix:0.4.14-rc.2-extra:1.2.3"
  "dependency_label:1.2.3:1.2.3-preview.1"
)
  string(REPLACE ":" ";" _basics_fields "${_basics_case}")
  list(GET _basics_fields 0 _basics_label)
  list(GET _basics_fields 1 _basics_package_version)
  list(GET _basics_fields 2 _basics_dependency_version)
  set(_basics_fixture "${TEST_ROOT}/${_basics_label}.DepoFile")
  _basics_write_fixture("${_basics_fixture}" "${_basics_package_version}" "${_basics_dependency_version}")
  _basics_configure_contract("reject_${_basics_label}" "${_basics_fixture}" FALSE)
endforeach()
