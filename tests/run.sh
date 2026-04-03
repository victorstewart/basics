#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
quick_build_dir="${repo_root}/build/tests"
matrix_build_root="${repo_root}/build/tests-matrix"
sanitizer_build_dir="${repo_root}/build/tests-sanitizers"
matrix_mode=0
sanitizer_mode=NONE

usage() {
  cat <<'EOF'
Usage:
  ./tests/run.sh
  ./tests/run.sh --matrix
  ./tests/run.sh --sanitizers

Default mode builds the recommended quick path:
  BASICS_MIMALLOC_MODE=OBJECT
  BASICS_DEPENDENCY_LINK_MODE=STATIC

--matrix builds and tests every supported mimalloc/link-mode variant for
clang++ and g++ when those compilers are available.

--sanitizers builds and runs the sanitizer lane with:
  BASICS_MIMALLOC_MODE=NONE
  BASICS_DEPENDENCY_LINK_MODE=STATIC
  BASICS_SANITIZER_MODE=ASAN_UBSAN
EOF
}

if [[ $# -gt 1 ]]; then
  usage
  exit 2
fi

if [[ $# -eq 1 ]]; then
  case "$1" in
    --matrix)
      matrix_mode=1
      ;;
    --sanitizers)
      sanitizer_mode=ASAN_UBSAN
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
fi

compiler_bins=()
compiler_labels=()

add_compiler() {
  local compiler_name="$1"
  local compiler_label="$2"

  if command -v "${compiler_name}" >/dev/null 2>&1; then
    compiler_bins+=("$(command -v "${compiler_name}")")
    compiler_labels+=("${compiler_label}")
  fi
}

add_compiler clang++ clang
add_compiler g++ gxx

if [[ ${#compiler_bins[@]} -eq 0 ]]; then
  compiler_bins+=("")
  compiler_labels+=(default)
fi

run_variant() {
  local build_dir="$1"
  local compiler_bin="$2"
  local compiler_label="$3"
  local mimalloc_mode="$4"
  local dependency_link_mode="$5"
  local tidesdb_mode="${6:-OFF}"
  local variant_sanitizer_mode="${7:-NONE}"

  echo "==> [${compiler_label}] BASICS_MIMALLOC_MODE=${mimalloc_mode} BASICS_DEPENDENCY_LINK_MODE=${dependency_link_mode} BASICS_ENABLE_TIDESDB=${tidesdb_mode} BASICS_SANITIZER_MODE=${variant_sanitizer_mode}"

  rm -rf "${build_dir}"

  local -a cmake_args=(
    -S "${repo_root}"
    -B "${build_dir}"
    -DBASICS_MIMALLOC_MODE="${mimalloc_mode}"
    -DBASICS_DEPENDENCY_LINK_MODE="${dependency_link_mode}"
    -DBASICS_ENABLE_TIDESDB="${tidesdb_mode}"
    -DBASICS_SANITIZER_MODE="${variant_sanitizer_mode}"
  )

  if [[ -n "${compiler_bin}" ]]; then
    cmake_args+=("-DCMAKE_CXX_COMPILER=${compiler_bin}")
  fi

  if [[ -n "${DEPOS_EXECUTABLE:-}" ]]; then
    cmake_args+=("-DDEPOS_EXECUTABLE=${DEPOS_EXECUTABLE}")
  fi

  cmake "${cmake_args[@]}"
  cmake --build "${build_dir}" -j"$(nproc)"
  if [[ "${variant_sanitizer_mode}" == "ASAN_UBSAN" ]]; then
    ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" \
    UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
      ctest --test-dir "${build_dir}" --output-on-failure -j"$(nproc)"
  else
    ctest --test-dir "${build_dir}" --output-on-failure -j"$(nproc)"
  fi
}

if [[ ${matrix_mode} -eq 1 ]]; then
  mimalloc_modes=(NONE OBJECT STATIC SHARED)
  dependency_link_modes=(STATIC SHARED)
  tidesdb_modes=(OFF ON)

  for compiler_index in "${!compiler_bins[@]}"; do
    compiler_bin="${compiler_bins[compiler_index]}"
    compiler_label="${compiler_labels[compiler_index]}"

    for mimalloc_mode in "${mimalloc_modes[@]}"; do
      for dependency_link_mode in "${dependency_link_modes[@]}"; do
        for tidesdb_mode in "${tidesdb_modes[@]}"; do
          build_dir="${matrix_build_root}/${compiler_label}/${mimalloc_mode,,}-${dependency_link_mode,,}-tidesdb-${tidesdb_mode,,}"
          run_variant "${build_dir}" "${compiler_bin}" "${compiler_label}" "${mimalloc_mode}" "${dependency_link_mode}" "${tidesdb_mode}"
        done
      done
    done
  done
else
  if [[ "${sanitizer_mode}" == "ASAN_UBSAN" ]]; then
    run_variant "${sanitizer_build_dir}" "${compiler_bins[0]}" "${compiler_labels[0]}" NONE STATIC OFF "${sanitizer_mode}"
  else
    run_variant "${quick_build_dir}" "${compiler_bins[0]}" "${compiler_labels[0]}" OBJECT STATIC OFF "${sanitizer_mode}"
  fi
fi
