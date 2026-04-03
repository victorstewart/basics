#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${BASICS_BENCHMARK_BUILD_DIR:-${repo_root}/build/benchmarks}"

choose_compiler() {
  if [[ -n "${CXX:-}" ]]; then
    printf '%s\n' "${CXX}"
    return
  fi

  if command -v clang++ >/dev/null 2>&1; then
    command -v clang++
    return
  fi

  if command -v g++ >/dev/null 2>&1; then
    command -v g++
    return
  fi

  printf '\n'
}

compiler_bin="$(choose_compiler)"

cmake_args=(
  -S "${repo_root}"
  -B "${build_dir}"
  -DBASICS_MIMALLOC_MODE="${BASICS_MIMALLOC_MODE:-OBJECT}"
  -DBASICS_DEPENDENCY_LINK_MODE="${BASICS_DEPENDENCY_LINK_MODE:-STATIC}"
  -DBASICS_SANITIZER_MODE="${BASICS_SANITIZER_MODE:-NONE}"
)

if [[ -n "${compiler_bin}" ]]; then
  cmake_args+=("-DCMAKE_CXX_COMPILER=${compiler_bin}")
fi

if [[ -n "${DEPOS_EXECUTABLE:-}" ]]; then
  cmake_args+=("-DDEPOS_EXECUTABLE=${DEPOS_EXECUTABLE}")
fi

if [[ -n "${CMAKE_BUILD_TYPE:-}" ]]; then
  cmake_args+=("-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
else
  cmake_args+=("-DCMAKE_BUILD_TYPE=Release")
fi

cmake "${cmake_args[@]}"
cmake --build "${build_dir}" -j"$(nproc)" --target basics_benchmarks
"${build_dir}/basics_benchmarks" "$@"
