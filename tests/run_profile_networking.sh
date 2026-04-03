#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${repo_root}/build/networking-profile"
output_dir="${repo_root}/build/networking-profile-output"
iterations=128
payload_bytes=$((64 * 1024))
scenario="all"

usage() {
  cat <<'EOF'
Usage:
  ./tests/run_profile_networking.sh
  ./tests/run_profile_networking.sh --scenario ring-loopback
  ./tests/run_profile_networking.sh --scenario tls-tests
  ./tests/run_profile_networking.sh --iterations 128 --payload-bytes 65536 --output-dir /tmp/basics-network-profile

This runner builds `basics_networking_profile`, then captures for each selected scenario:
  - a sampled `perf` profile using the software `cpu-clock` event
  - a `perf report --stdio` text summary
  - a folded stack file
  - an SVG flamegraph
  - a `strace -c` syscall summary
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
cmake --build "${build_dir}" -j"$(nproc)" --target basics_networking_profile basics_tls_tests

mkdir -p "${output_dir}"
rm -f "${output_dir}"/*.perf.data "${output_dir}"/*.perf.txt "${output_dir}"/*.perf.folded "${output_dir}"/*.perf.svg "${output_dir}"/*.strace.txt "${output_dir}"/*.workload.sh

run_command_profile() {
  local scenario_name="$1"
  shift
  local base="${output_dir}/${scenario_name}"
  local workload_script="${output_dir}/${scenario_name}.workload.sh"

  echo "==> profiling ${scenario_name}"

  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo "for ((iteration = 0; iteration < ${iterations}; ++iteration)); do"
    printf '  '
    printf '%q ' "$@"
    echo ' >/dev/null'
    echo 'done'
  } > "${workload_script}"
  chmod +x "${workload_script}"

  perf record \
    -o "${base}.perf.data" \
    -e cpu-clock \
    --call-graph dwarf \
    -- "${workload_script}"

  perf report --stdio -i "${base}.perf.data" > "${base}.perf.txt"
  perf script -i "${base}.perf.data" | inferno-collapse-perf > "${base}.perf.folded"
  inferno-flamegraph < "${base}.perf.folded" > "${base}.perf.svg"
  strace -f -qq -c -o "${base}.strace.txt" "${workload_script}" >/dev/null
  rm -f "${workload_script}"
}

if [[ "${scenario}" == "all" ]]; then
  run_command_profile ring-loopback "${build_dir}/basics_networking_profile" --scenario ring-loopback --iterations 1 --payload-bytes "${payload_bytes}"
  run_command_profile tls-tests "${build_dir}/basics_tls_tests"
else
  case "${scenario}" in
    ring-loopback)
      run_command_profile ring-loopback "${build_dir}/basics_networking_profile" --scenario ring-loopback --iterations 1 --payload-bytes "${payload_bytes}"
      ;;
    tls-tests)
      run_command_profile tls-tests "${build_dir}/basics_tls_tests"
      ;;
    *)
      echo "unsupported scenario: ${scenario}" >&2
      exit 2
      ;;
  esac
fi

echo "wrote profiling artifacts under ${output_dir}"
