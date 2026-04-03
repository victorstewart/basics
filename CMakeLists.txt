# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.21)

project(basics VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
include("${CMAKE_CURRENT_SOURCE_DIR}/.depos.cmake")

set(BASICS_MIMALLOC_MODE "" CACHE STRING "Explicit mimalloc mode for basics: NONE, OBJECT, STATIC, or SHARED")
set_property(CACHE BASICS_MIMALLOC_MODE PROPERTY STRINGS NONE OBJECT STATIC SHARED)
set(BASICS_DEPENDENCY_LINK_MODE "" CACHE STRING "Explicit preferred direct dependency linkage for basics: STATIC or SHARED")
set_property(CACHE BASICS_DEPENDENCY_LINK_MODE PROPERTY STRINGS STATIC SHARED)
set(BASICS_SANITIZER_MODE "NONE" CACHE STRING "Optional sanitizer mode for basics test targets: NONE or ASAN_UBSAN")
set_property(CACHE BASICS_SANITIZER_MODE PROPERTY STRINGS NONE ASAN_UBSAN)
option(BASICS_ENABLE_TIDESDB "Include the optional TidesDB wrapper and dependency in the generated basics package surface" OFF)

file(GLOB _basics_dependency_depofiles CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/depofiles/*.DepoFile")
list(SORT _basics_dependency_depofiles)

function(_basics_package_stage_rules out_var include_tidesdb)
  set(
    _basics_stage_lines
    "STAGE_TREE SOURCE base include/base"
    "STAGE_TREE SOURCE ebpf include/ebpf"
    "STAGE_TREE SOURCE enums include/enums"
    "STAGE_TREE SOURCE macros include/macros"
    "STAGE_TREE SOURCE networking include/networking"
    "STAGE_TREE SOURCE services include/services"
    "STAGE_TREE SOURCE types include/types"
    "STAGE_FILE SOURCE includes.h include/includes.h"
  )
  if (include_tidesdb)
    list(APPEND _basics_stage_lines "STAGE_TREE SOURCE databases include/databases")
  endif()
  string(JOIN "\n" _basics_stage_rules ${_basics_stage_lines})
  set(${out_var} "${_basics_stage_rules}" PARENT_SCOPE)
endfunction()

function(_basics_prepare_self_depofile out_var)
  string(TOUPPER "${BASICS_MIMALLOC_MODE}" _basics_mimalloc_mode)
  string(TOUPPER "${BASICS_DEPENDENCY_LINK_MODE}" _basics_dependency_link_mode)
  if (_basics_mimalloc_mode STREQUAL "")
    message(FATAL_ERROR "BASICS_MIMALLOC_MODE must be explicitly set to NONE, OBJECT, STATIC, or SHARED. OBJECT is the recommended choice because it hijacks the libc allocation interface.")
  endif()
  if (_basics_dependency_link_mode STREQUAL "")
    message(FATAL_ERROR "BASICS_DEPENDENCY_LINK_MODE must be explicitly set to STATIC or SHARED.")
  elseif (NOT _basics_dependency_link_mode STREQUAL "STATIC" AND NOT _basics_dependency_link_mode STREQUAL "SHARED")
    message(FATAL_ERROR "Unsupported BASICS_DEPENDENCY_LINK_MODE='${BASICS_DEPENDENCY_LINK_MODE}'. Expected STATIC or SHARED.")
  endif()

  string(TOLOWER "${_basics_mimalloc_mode}" _basics_mimalloc_mode_suffix)
  string(TOLOWER "${_basics_dependency_link_mode}" _basics_dependency_link_mode_suffix)
  if (BASICS_ENABLE_TIDESDB)
    set(_basics_tidesdb_variant_suffix "on")
    set(BASICS_SELF_TIDESDB_ENABLED "ON")
    set(BASICS_SELF_TIDESDB_DEPENDS "DEPENDS tidesdb VERSION 8.6.2")
    set(BASICS_SELF_TIDESDB_LINK " tidesdb::tidesdb")
  else()
    set(_basics_tidesdb_variant_suffix "off")
    set(BASICS_SELF_TIDESDB_ENABLED "OFF")
    set(BASICS_SELF_TIDESDB_DEPENDS "")
    set(BASICS_SELF_TIDESDB_LINK "")
  endif()

  set(BASICS_SELF_PACKAGE_NAME "basics_mimalloc_${_basics_mimalloc_mode_suffix}_deps_${_basics_dependency_link_mode_suffix}_tidesdb_${_basics_tidesdb_variant_suffix}")
  set(BASICS_SELF_MIMALLOC_MODE "${_basics_mimalloc_mode}")
  set(BASICS_SELF_DEPENDENCY_LINK_MODE "${_basics_dependency_link_mode}")
  if (_basics_dependency_link_mode STREQUAL "STATIC")
    set(BASICS_SELF_LIBURING_LINK "liburing::liburing::static")
  elseif (_basics_dependency_link_mode STREQUAL "SHARED")
    set(BASICS_SELF_LIBURING_LINK "liburing::liburing::shared")
  else()
    message(FATAL_ERROR "Unsupported BASICS_DEPENDENCY_LINK_MODE='${BASICS_DEPENDENCY_LINK_MODE}'. Expected STATIC or SHARED.")
  endif()

  set(BASICS_SELF_DIRECT_DEPENDENCY_LINKS "SG14::SG14 aegis::aegis bitsery::bitsery gxhash::gxhash itoa::itoa libbpf::libbpf libcurl::libcurl libssh2::libssh2 zlib::zlib ${BASICS_SELF_LIBURING_LINK} nghttp2::nghttp2 openssl simdjson::simdjson static_type_info::static_type_info${BASICS_SELF_TIDESDB_LINK}")

  set(_basics_self_root "${CMAKE_BINARY_DIR}/.deps/basics-self")
  set(_basics_source_root "${_basics_self_root}/source")
  set(_basics_archive "${_basics_self_root}/basics-working-tree.tar")
  set(_basics_depofile "${_basics_self_root}/basics.DepoFile")

  file(REMOVE_RECURSE "${_basics_self_root}")
  file(MAKE_DIRECTORY "${_basics_source_root}")

  set(_basics_public_dirs base ebpf enums macros networking services types)
  if (BASICS_ENABLE_TIDESDB)
    list(APPEND _basics_public_dirs databases)
  endif()

  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/depofiles" DESTINATION "${_basics_source_root}")
  foreach(_basics_public_dir IN LISTS _basics_public_dirs)
    file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/${_basics_public_dir}" DESTINATION "${_basics_source_root}")
  endforeach()
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/includes.h" DESTINATION "${_basics_source_root}")

  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar cf "${_basics_archive}" --format=gnutar source
    WORKING_DIRECTORY "${_basics_self_root}"
    RESULT_VARIABLE _basics_archive_result
    ERROR_VARIABLE _basics_archive_error
    ERROR_STRIP_TRAILING_WHITESPACE
  )

  if (NOT _basics_archive_result EQUAL 0)
    message(FATAL_ERROR "Failed to archive generated basics source payload:\n${_basics_archive_error}")
  endif()

  file(SHA256 "${_basics_archive}" _basics_archive_sha256)
  set(BASICS_PACKAGE_NAME "${BASICS_SELF_PACKAGE_NAME}")
  set(BASICS_PACKAGE_VERSION "${PROJECT_VERSION}")
  set(BASICS_PACKAGE_MIMALLOC_MODE "${BASICS_SELF_MIMALLOC_MODE}")
  set(BASICS_PACKAGE_DEPENDENCY_LINK_MODE "${BASICS_SELF_DEPENDENCY_LINK_MODE}")
  set(BASICS_PACKAGE_TIDESDB_ENABLED "${BASICS_SELF_TIDESDB_ENABLED}")
  set(BASICS_PACKAGE_TIDESDB_DEPENDS "${BASICS_SELF_TIDESDB_DEPENDS}")
  set(BASICS_PACKAGE_SOURCE_URL "file://${_basics_archive}")
  set(BASICS_PACKAGE_SOURCE_SHA256 "${_basics_archive_sha256}")
  if (_basics_mimalloc_mode STREQUAL "NONE")
    set(BASICS_PACKAGE_USE_MIMALLOC 0)
    set(BASICS_PACKAGE_MIMALLOC_DEPENDS "")
    set(BASICS_PACKAGE_MIMALLOC_LINK "")
  elseif (_basics_mimalloc_mode STREQUAL "OBJECT")
    set(BASICS_PACKAGE_USE_MIMALLOC 1)
    set(BASICS_PACKAGE_MIMALLOC_DEPENDS "DEPENDS mimalloc VERSION 3.0.1")
    set(BASICS_PACKAGE_MIMALLOC_LINK " mimalloc::runtime::object")
  elseif (_basics_mimalloc_mode STREQUAL "STATIC")
    set(BASICS_PACKAGE_USE_MIMALLOC 2)
    set(BASICS_PACKAGE_MIMALLOC_DEPENDS "DEPENDS mimalloc VERSION 3.0.1")
    set(BASICS_PACKAGE_MIMALLOC_LINK " mimalloc::runtime::static")
  elseif (_basics_mimalloc_mode STREQUAL "SHARED")
    set(BASICS_PACKAGE_USE_MIMALLOC 2)
    set(BASICS_PACKAGE_MIMALLOC_DEPENDS "DEPENDS mimalloc VERSION 3.0.1")
    set(BASICS_PACKAGE_MIMALLOC_LINK " mimalloc::runtime::shared")
  else()
    message(FATAL_ERROR "Unsupported BASICS_MIMALLOC_MODE='${BASICS_MIMALLOC_MODE}'. Expected NONE, OBJECT, STATIC, or SHARED.")
  endif()
  set(BASICS_PACKAGE_DIRECT_DEPENDENCY_LINKS "${BASICS_SELF_DIRECT_DEPENDENCY_LINKS}")
  _basics_package_stage_rules(BASICS_PACKAGE_STAGING_RULES ${BASICS_ENABLE_TIDESDB})
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/depofiles/basics.DepoFile.in"
    "${_basics_depofile}"
    @ONLY
  )

  set(${out_var} "${_basics_depofile}" PARENT_SCOPE)
endfunction()

function(_basics_validate_depofile_versions)
  set(_basics_version_regex "^[0-9]+(\\.[0-9]+)+$")

  foreach(_basics_depofile IN LISTS ARGN)
    file(STRINGS "${_basics_depofile}" _basics_depofile_lines)

    foreach(_basics_line IN LISTS _basics_depofile_lines)
      if (_basics_line MATCHES "^VERSION[ \t]+([^ \t]+)$")
        set(_basics_version "${CMAKE_MATCH_1}")
        if (NOT _basics_version MATCHES "${_basics_version_regex}")
          message(FATAL_ERROR "DepoFile ${_basics_depofile} has non-tiered package version '${_basics_version}'")
        endif()
      elseif (_basics_line MATCHES "^DEPENDS[ \t]+.*[ \t]+VERSION[ \t]+([^ \t]+)$")
        set(_basics_version "${CMAKE_MATCH_1}")
        if (NOT _basics_version MATCHES "${_basics_version_regex}")
          message(FATAL_ERROR "DepoFile ${_basics_depofile} has non-tiered dependency version '${_basics_version}' in line '${_basics_line}'")
        endif()
      endif()
    endforeach()
  endforeach()
endfunction()

_basics_prepare_self_depofile(_basics_self_depofile)
string(TOUPPER "${BASICS_MIMALLOC_MODE}" _basics_selected_mimalloc_mode)

_basics_validate_depofile_versions(${_basics_dependency_depofiles} "${_basics_self_depofile}")
depos_depend("${_basics_self_depofile}")

function(_basics_configure_dev_compile_target target optimization_flag)
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_compile_definitions(${target} PRIVATE BASICS_TESTS_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests")
  depos_link(${target} PRIVATE basics::basics)
  target_compile_features(${target} PRIVATE cxx_std_20)
  target_compile_options(
    ${target}
    PRIVATE
      ${optimization_flag}
      -Wall
      -Wextra
      -pedantic
      -Wno-unused-function
      -Wno-unused-parameter
      -Wno-unused-variable
  )

  if (BASICS_SANITIZER_MODE STREQUAL "NONE")
    # no-op
  elseif (BASICS_SANITIZER_MODE STREQUAL "ASAN_UBSAN")
    if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
      message(FATAL_ERROR "BASICS_SANITIZER_MODE=ASAN_UBSAN requires a Clang or GNU C++ compiler.")
    endif()

    target_compile_options(
      ${target}
      PRIVATE
        -O1
        -g
        -fno-omit-frame-pointer
        -fsanitize=address,undefined
    )
    target_link_options(
      ${target}
      PRIVATE
        -fsanitize=address,undefined
    )
  else()
    message(FATAL_ERROR "Unsupported BASICS_SANITIZER_MODE='${BASICS_SANITIZER_MODE}'. Expected NONE or ASAN_UBSAN.")
  endif()
endfunction()

function(_basics_configure_dev_executable target)
  depos_link(${target} PRIVATE basics::basics)

  if (BASICS_SANITIZER_MODE STREQUAL "NONE")
    # no-op
  elseif (BASICS_SANITIZER_MODE STREQUAL "ASAN_UBSAN")
    if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
      message(FATAL_ERROR "BASICS_SANITIZER_MODE=ASAN_UBSAN requires a Clang or GNU C++ compiler.")
    endif()

    target_link_options(
      ${target}
      PRIVATE
        -fsanitize=address,undefined
    )
  else()
    message(FATAL_ERROR "Unsupported BASICS_SANITIZER_MODE='${BASICS_SANITIZER_MODE}'. Expected NONE or ASAN_UBSAN.")
  endif()
endfunction()

function(_basics_add_test_executable target source)
  set(_basics_object_target "${target}__objects")
  add_library(${_basics_object_target} OBJECT ${source} ${ARGN})
  _basics_configure_dev_compile_target(${_basics_object_target} -O2)

  add_executable(${target} $<TARGET_OBJECTS:${_basics_object_target}>)
  _basics_configure_dev_executable(${target})
  add_test(NAME ${target} COMMAND ${target})
endfunction()

function(_basics_add_benchmark_executable target source)
  set(_basics_object_target "${target}__objects")
  add_library(${_basics_object_target} OBJECT ${source} ${ARGN})
  _basics_configure_dev_compile_target(${_basics_object_target} -O3)
  target_compile_definitions(${_basics_object_target} PRIVATE NDEBUG)

  add_executable(${target} $<TARGET_OBJECTS:${_basics_object_target}>)
  _basics_configure_dev_executable(${target})
endfunction()

_basics_add_test_executable(basics_codec_tests tests/codec_tests.cpp)
_basics_add_test_executable(basics_codec_fuzz_tests tests/codec_fuzz_tests.cpp)
_basics_add_test_executable(basics_bitsery_tests tests/bitsery_tests.cpp)
_basics_add_test_executable(basics_containers_tests tests/containers_tests.cpp)
_basics_add_test_executable(basics_ebpf_program_tests tests/ebpf_program_tests.cpp)
_basics_add_test_executable(basics_filesystem_tests tests/filesystem_tests.cpp)
_basics_add_test_executable(basics_linux_integration_tests tests/linux_integration_tests.cpp)
_basics_add_test_executable(basics_memfd_reflection_tests tests/memfd_reflection_tests.cpp)
_basics_add_test_executable(basics_netlink_tests tests/netlink_tests.cpp)
_basics_add_test_executable(basics_networking_primitives_tests tests/networking_primitives_tests.cpp)
_basics_add_test_executable(basics_networking_support_structures_tests tests/networking_support_structures_tests.cpp)
_basics_add_test_executable(basics_protocol_client_tests tests/protocol_client_tests.cpp)
_basics_add_test_executable(basics_ring_integration_tests tests/ring_integration_tests.cpp)
_basics_add_test_executable(basics_stream_tests tests/stream_tests.cpp)
_basics_add_test_executable(basics_tls_tests tests/tls_tests.cpp)
_basics_add_test_executable(basics_public_headers_smoke tests/public_headers_compile_smoke.cpp)
_basics_add_test_executable(basics_services_sanity_tests tests/services_sanity_tests.cpp)
_basics_add_test_executable(basics_string_tests tests/string_tests.cpp)
_basics_add_test_executable(basics_vault_tests tests/vault_tests.cpp)
_basics_add_benchmark_executable(basics_benchmarks tests/benchmarks.cpp)
_basics_add_benchmark_executable(basics_networking_profile tests/networking_profile.cpp)
_basics_add_benchmark_executable(basics_tls_profile tests/tls_profile.cpp)

add_test(
  NAME basics_string_formatter_compile_fail
  COMMAND
    "${CMAKE_COMMAND}"
      "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
      "-DTEST_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/tests/string_unsupported_formatter_compile_fail.cpp"
      "-DOUTPUT_OBJECT=${CMAKE_CURRENT_BINARY_DIR}/string_unsupported_formatter_compile_fail.o"
      "-DINCLUDE_DIRS=$<TARGET_PROPERTY:basics::basics,INTERFACE_INCLUDE_DIRECTORIES>"
      "-DCOMPILE_DEFINITIONS=$<TARGET_PROPERTY:basics::basics,INTERFACE_COMPILE_DEFINITIONS>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/expect_compile_failure.cmake"
)

add_test(
  NAME basics_public_headers_missing_use_mimalloc_compile_fail
  COMMAND
    "${CMAKE_COMMAND}"
      "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
      "-DTEST_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/tests/public_headers_missing_use_mimalloc_compile_fail.cpp"
      "-DOUTPUT_OBJECT=${CMAKE_CURRENT_BINARY_DIR}/public_headers_missing_use_mimalloc_compile_fail.o"
      "-DINCLUDE_DIRS=$<TARGET_PROPERTY:basics::basics,INTERFACE_INCLUDE_DIRECTORIES>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/expect_compile_failure.cmake"
)

add_test(
  NAME basics_public_headers_invalid_use_mimalloc_compile_fail
  COMMAND
    "${CMAKE_COMMAND}"
      "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
      "-DTEST_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/tests/public_headers_invalid_use_mimalloc_compile_fail.cpp"
      "-DOUTPUT_OBJECT=${CMAKE_CURRENT_BINARY_DIR}/public_headers_invalid_use_mimalloc_compile_fail.o"
      "-DINCLUDE_DIRS=$<TARGET_PROPERTY:basics::basics,INTERFACE_INCLUDE_DIRECTORIES>"
      "-DCOMPILE_DEFINITIONS=USE_MIMALLOC=3"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/expect_compile_failure.cmake"
)

add_test(
  NAME basics_downstream_package_consumer_smoke
  COMMAND
    "${CMAKE_COMMAND}"
      "-DBASICS_PACKAGE_DEPOFILE=${_basics_self_depofile}"
      "-DBASICS_DOWNSTREAM_ENABLE_TIDESDB=$<IF:$<BOOL:${BASICS_ENABLE_TIDESDB}>,ON,OFF>"
      "-DBUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}/downstream-package-consumer"
      "-DEXPECT_MIMALLOC_OBJECT_INTERPOSITION=$<IF:$<STREQUAL:${_basics_selected_mimalloc_mode},OBJECT>,ON,OFF>"
      "-DGENERATOR=${CMAKE_GENERATOR}"
      "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
      "-DCMAKE_BUILD_TYPE_VALUE=${CMAKE_BUILD_TYPE}"
      "-DCMAKE_MAKE_PROGRAM_VALUE=${CMAKE_MAKE_PROGRAM}"
      "-DDEPOS_EXECUTABLE_VALUE=${DEPOS_EXECUTABLE}"
      "-DDEPOS_ROOT_VALUE=${DEPOS_ROOT}"
      "-DDEPOS_BOOTSTRAP_DIR_VALUE=${DEPOS_BOOTSTRAP_DIR}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_downstream_consumer.cmake"
)

add_test(
  NAME basics_tidesdb_package_contract
  COMMAND
    "${CMAKE_COMMAND}"
      "-DBASICS_PACKAGE_DEPOFILE=${_basics_self_depofile}"
      "-DEXPECT_TIDESDB=$<IF:$<BOOL:${BASICS_ENABLE_TIDESDB}>,ON,OFF>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/assert_tidesdb_package_contract.cmake"
)
