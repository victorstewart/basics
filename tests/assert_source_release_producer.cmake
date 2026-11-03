# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED BASICS_SOURCE_DIR OR "${BASICS_SOURCE_DIR}" STREQUAL "")
  message(FATAL_ERROR "BASICS_SOURCE_DIR is required.")
endif()

set(_basics_producer "${BASICS_SOURCE_DIR}/tools/package-source-release.sh")
if (NOT EXISTS "${_basics_producer}")
  message(FATAL_ERROR "Missing Basics source-release producer.")
endif()
file(READ "${_basics_producer}" _basics_producer_contents)

foreach(_basics_required_contract IN ITEMS
  [[BASICS_SOURCE_RELEASE_VERSION:-${declared_version}]]
  [[disagrees with source identity]]
  [[source worktree must be clean and fully committed]]
  [[git -C "${repo_root}" archive --format=tar]]
  [[gzip -n]]
  [[releases/download/v${version}/${asset_name}]]
  [[BASICS_RELEASE_SOURCE_ARCHIVE=${archive}]]
  [[BASICS_RELEASE_SOURCE_URL=${source_url}]]
  [[services/memfd.h]]
  [[tools/package-source-release.sh]]
  [[source_commit=${commit}]]
)
  string(FIND "${_basics_producer_contents}" "${_basics_required_contract}" _basics_contract_index)
  if (_basics_contract_index EQUAL -1)
    message(FATAL_ERROR "Basics source-release producer is missing '${_basics_required_contract}'.")
  endif()
endforeach()

file(READ "${BASICS_SOURCE_DIR}/CMakeLists.txt" _basics_cmakelists)
string(FIND "${_basics_cmakelists}"
  [[set(BASICS_RELEASE_IDENTITY "0.4.14-rc.4")]]
  _basics_source_identity_index)
if (_basics_source_identity_index EQUAL -1)
  message(FATAL_ERROR "Basics source does not own the exact release identity.")
endif()

foreach(_basics_forbidden_contract IN ITEMS
  [[archive/refs/heads]]
  [[tar -cz]]
  [[SOURCE_DATE_EPOCH:-$(date]]
  [[uname -s]]
)
  string(FIND "${_basics_producer_contents}" "${_basics_forbidden_contract}" _basics_forbidden_index)
  if (NOT _basics_forbidden_index EQUAL -1)
    message(FATAL_ERROR "Basics source-release producer contains forbidden nondeterministic path '${_basics_forbidden_contract}'.")
  endif()
endforeach()
