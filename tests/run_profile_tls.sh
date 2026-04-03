#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${repo_root}/build/tls-profile"
output_dir="${repo_root}/build/tls-profile-output"
iterations=128
payload_bytes=4096
scenario="all"
heap_interval_bytes=1048576
heap_profiler_so="/usr/lib/libtcmalloc_and_profiler.so"

usage() {
  cat <<'EOF'
Usage:
  ./tests/run_profile_tls.sh
  ./tests/run_profile_tls.sh --scenario tls-handshake
  ./tests/run_profile_tls.sh --scenario tls-long-lived-session --iterations 64 --payload-bytes 16384
  ./tests/run_profile_tls.sh --scenario tls-steady-state --iterations 256 --payload-bytes 16384
  ./tests/run_profile_tls.sh --output-dir /tmp/basics-tls-profile

This runner builds `basics_tls_profile`, then captures for each selected scenario:
  - a sampled `perf` profile using the software `cpu-clock` event
  - a `perf report --stdio` text summary
  - a folded stack file
  - an SVG flamegraph
  - a `strace -c` syscall summary
  - raw gperftools heap-profile artifacts for allocation analysis
EOF
}

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)
      scenario="${2:-}"
      shift 2
      ;;
    --iterations)
      iterations="${2:-}"
      shift 2
      ;;
    --payload-bytes)
      payload_bytes="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --heap-interval-bytes)
      heap_interval_bytes="${2:-}"
      shift 2
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
done

for tool in perf inferno-collapse-perf inferno-flamegraph strace; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "missing required tool: ${tool}" >&2
    exit 1
  fi
done

if [[ ! -f "${heap_profiler_so}" ]]; then
  echo "missing required heap profiler library: ${heap_profiler_so}" >&2
  exit 1
fi

compiler_bin="$(choose_compiler)"
cmake_args=(
  -S "${repo_root}"
  -B "${build_dir}"
  -DBASICS_MIMALLOC_MODE=OBJECT
  -DBASICS_DEPENDENCY_LINK_MODE=STATIC
  -DBASICS_SANITIZER_MODE=NONE
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
)

if [[ -n "${compiler_bin}" ]]; then
  cmake_args+=("-DCMAKE_CXX_COMPILER=${compiler_bin}")
fi

if [[ -n "${DEPOS_EXECUTABLE:-}" ]]; then
  cmake_args+=("-DDEPOS_EXECUTABLE=${DEPOS_EXECUTABLE}")
fi

cmake "${cmake_args[@]}"
cmake --build "${build_dir}" -j"$(nproc)" --target basics_tls_profile

mkdir -p "${output_dir}"
rm -f \
  "${output_dir}"/*.perf.data \
  "${output_dir}"/*.perf.txt \
  "${output_dir}"/*.perf.folded \
  "${output_dir}"/*.perf.svg \
  "${output_dir}"/*.strace.txt \
  "${output_dir}"/*.heap.* \
  "${output_dir}"/*.heap.log

run_perf_profile() {
  local scenario_name="$1"
  shift
  local base="${output_dir}/${scenario_name}"

  echo "==> profiling ${scenario_name}"

  perf record \
    -o "${base}.perf.data" \
    -e cpu-clock \
    --call-graph dwarf \
    -- "${build_dir}/basics_tls_profile" "$@" >/dev/null

  perf report --stdio -i "${base}.perf.data" > "${base}.perf.txt"
  perf script -i "${base}.perf.data" | inferno-collapse-perf > "${base}.perf.folded"
  inferno-flamegraph < "${base}.perf.folded" > "${base}.perf.svg"
  strace -f -qq -c -o "${base}.strace.txt" "${build_dir}/basics_tls_profile" "$@" >/dev/null
}

run_heap_profile() {
  local scenario_name="$1"
  shift
  local base="${output_dir}/${scenario_name}"

  echo "==> heap profiling ${scenario_name}"

  HEAPPROFILE="${base}.heap" \
  HEAP_PROFILE_ALLOCATION_INTERVAL="${heap_interval_bytes}" \
  LD_PRELOAD="${heap_profiler_so}" \
    "${build_dir}/basics_tls_profile" "$@" >/dev/null 2>"${base}.heap.log"
}

run_scenario() {
  local scenario_name="$1"
  local profile_scenario="$2"

  run_perf_profile "${scenario_name}" --scenario "${profile_scenario}" --iterations "${iterations}" --payload-bytes "${payload_bytes}"
  run_heap_profile "${scenario_name}" --scenario "${profile_scenario}" --iterations "${iterations}" --payload-bytes "${payload_bytes}"
}

if [[ "${scenario}" == "all" ]]; then
  run_scenario tls-handshake tls-handshake
  run_scenario tls-long-lived-session tls-long-lived-session
else
  case "${scenario}" in
    tls-handshake|tls-steady-state|tls-long-lived-session)
      run_scenario "${scenario}" "${scenario}"
      ;;
    *)
      echo "unsupported scenario: ${scenario}" >&2
      exit 2
      ;;
  esac
fi

echo "wrote TLS profiling artifacts under ${output_dir}"
