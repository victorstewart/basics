#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${BASICS_COMPARE_OUTPUT_DIR:-${repo_root}/build/benchmarks-compare}"
object_build_dir="${output_dir}/object"
static_build_dir="${output_dir}/static"
summary_file="${output_dir}/container_allocator_compare.txt"
raw_file="${output_dir}/container_allocator_compare_raw.tsv"
min_time_ms=100
warmup_runs=1
repetitions=7
rounds=7
cpu_override="${BASICS_BENCHMARK_CPU:-}"

usage() {
  cat <<'EOF'
Usage:
  ./tests/run_compare_container_allocator_modes.sh
  ./tests/run_compare_container_allocator_modes.sh --min-time-ms 100 --repetitions 7 --rounds 7
  ./tests/run_compare_container_allocator_modes.sh --cpu 3 --output-dir /tmp/basics-bench-compare

This runner performs a controlled comparison between:
  - BASICS_MIMALLOC_MODE=OBJECT  (USE_MIMALLOC=1)
  - BASICS_MIMALLOC_MODE=STATIC  (USE_MIMALLOC=2)

Protocol:
  - builds both benchmark binaries once
  - runs each benchmark in a fresh process
  - alternates allocator-mode order across rounds and benchmarks
  - alternates benchmark order across rounds
  - pins execution to one allowed CPU when `taskset` is available
  - emits raw TSV data plus a summary with machine/build metadata, variability, and slot-bias reporting
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

detect_first_allowed_cpu() {
  python - <<'PY'
import os
affinity = sorted(os.sched_getaffinity(0))
print(affinity[0] if affinity else "")
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --min-time-ms)
      min_time_ms="${2:-}"
      shift 2
      ;;
    --warmup-runs)
      warmup_runs="${2:-}"
      shift 2
      ;;
    --repetitions)
      repetitions="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --cpu)
      cpu_override="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      object_build_dir="${output_dir}/object"
      static_build_dir="${output_dir}/static"
      summary_file="${output_dir}/container_allocator_compare.txt"
      raw_file="${output_dir}/container_allocator_compare_raw.tsv"
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

compiler_bin="$(choose_compiler)"
mkdir -p "${output_dir}"

cpu_to_use="${cpu_override}"
if [[ -z "${cpu_to_use}" ]] && command -v taskset >/dev/null 2>&1; then
  cpu_to_use="$(detect_first_allowed_cpu)"
fi

run_prefix=()
if [[ -n "${cpu_to_use}" ]] && command -v taskset >/dev/null 2>&1; then
  run_prefix=(taskset -c "${cpu_to_use}")
fi

configure_and_build() {
  local build_dir="$1"
  local mimalloc_mode="$2"

  local cmake_args=(
    -S "${repo_root}"
    -B "${build_dir}"
    -DBASICS_MIMALLOC_MODE="${mimalloc_mode}"
    -DBASICS_DEPENDENCY_LINK_MODE=STATIC
    -DBASICS_SANITIZER_MODE=NONE
    -DCMAKE_BUILD_TYPE=Release
  )

  if [[ -n "${compiler_bin}" ]]; then
    cmake_args+=("-DCMAKE_CXX_COMPILER=${compiler_bin}")
  fi

  if [[ -n "${DEPOS_EXECUTABLE:-}" ]]; then
    cmake_args+=("-DDEPOS_EXECUTABLE=${DEPOS_EXECUTABLE}")
  fi

  cmake "${cmake_args[@]}"
  cmake --build "${build_dir}" -j"$(nproc)" --target basics_benchmarks
}

parse_metric() {
  local key="$1"
  local benchmark="$2"
  local mode_label="$3"
  local output_text="$4"
  BENCHMARK_OUTPUT="${output_text}" python - "$key" "$benchmark" "$mode_label" <<'PY'
import os
import sys
key = sys.argv[1]
benchmark = sys.argv[2]
mode_label = sys.argv[3]
text = os.environ["BENCHMARK_OUTPUT"]
line = next((line for line in text.splitlines() if line.startswith("benchmark=")), None)
if line is None:
    raise SystemExit(
        f"missing benchmark= line while parsing {benchmark} [{mode_label}] output:\n{text}"
    )
fields = {}
for token in line.split():
    if "=" in token:
        name, value = token.split("=", 1)
        fields[name] = value
if key not in fields:
    raise SystemExit(
        f"missing {key}= field while parsing {benchmark} [{mode_label}] line:\n{line}"
    )
print(fields[key])
PY
}

parse_header_metric() {
  local key="$1"
  local mode_label="$2"
  local output_text="$3"
  BENCHMARK_OUTPUT="${output_text}" python - "$key" "$mode_label" <<'PY'
import os
import sys
key = sys.argv[1]
mode_label = sys.argv[2]
text = os.environ["BENCHMARK_OUTPUT"]
line = next((line for line in text.splitlines() if line.startswith("benchmark_count=")), None)
if line is None:
    raise SystemExit(
        f"missing benchmark_count= header while parsing {mode_label} output:\n{text}"
    )
fields = {}
for token in line.split():
    if "=" in token:
        name, value = token.split("=", 1)
        fields[name] = value
if key not in fields:
    raise SystemExit(
        f"missing {key}= field while parsing {mode_label} header:\n{line}"
    )
print(fields[key])
PY
}

run_benchmark_output() {
  local build_dir="$1"
  local benchmark="$2"
  local mode_label="$3"
  local repetitions_override="${4:-${repetitions}}"
  local iterations_override="${5:-0}"
  local warmup_override="${6:-${warmup_runs}}"

  local cmd=("${build_dir}/basics_benchmarks" --exact "${benchmark}" --min-time-ms "${min_time_ms}" --warmup-runs "${warmup_override}" --repetitions "${repetitions_override}")
  if [[ "${iterations_override}" != "0" ]]; then
    cmd+=(--iterations "${iterations_override}")
  fi

  local output
  if [[ ${#run_prefix[@]} -gt 0 ]]; then
    if ! output="$("${run_prefix[@]}" "${cmd[@]}" 2>&1)"; then
      printf 'benchmark execution failed for %s [%s]\n%s\n' "${benchmark}" "${mode_label}" "${output}" >&2
      return 1
    fi
  else
    if ! output="$("${cmd[@]}" 2>&1)"; then
      printf 'benchmark execution failed for %s [%s]\n%s\n' "${benchmark}" "${mode_label}" "${output}" >&2
      return 1
    fi
  fi

  printf '%s\n' "${output}"
}

calibrate_fixed_iterations() {
  local benchmark="$1"
  local object_output
  local static_output
  local object_iterations
  local static_iterations

  object_output="$(run_benchmark_output "${object_build_dir}" "${benchmark}" "OBJECT-calibration" 1 0 0)"
  static_output="$(run_benchmark_output "${static_build_dir}" "${benchmark}" "STATIC-calibration" 1 0 0)"
  object_iterations="$(parse_metric iterations "${benchmark}" "OBJECT-calibration" "${object_output}")"
  static_iterations="$(parse_metric iterations "${benchmark}" "STATIC-calibration" "${static_output}")"

  if (( object_iterations > static_iterations )); then
    printf '%s\n' "${object_iterations}"
  else
    printf '%s\n' "${static_iterations}"
  fi
}

run_one() {
  local build_dir="$1"
  local benchmark="$2"
  local mode_label="$3"
  local fixed_iterations="$4"

  local output
  output="$(run_benchmark_output "${build_dir}" "${benchmark}" "${mode_label}" "${repetitions}" "${fixed_iterations}" "${warmup_runs}")"

  local ns_per_op
  local ops_per_s
  local median_ns
  local iterations
  ns_per_op="$(parse_metric ns_per_op "${benchmark}" "${mode_label}" "${output}")"
  ops_per_s="$(parse_metric ops_per_s "${benchmark}" "${mode_label}" "${output}")"
  median_ns="$(parse_metric median_ns "${benchmark}" "${mode_label}" "${output}")"
  iterations="$(parse_metric iterations "${benchmark}" "${mode_label}" "${output}")"
  printf '%s\t%s\t%s\t%s\t%s\n' "${ns_per_op}" "${ops_per_s}" "${median_ns}" "${iterations}" "${mode_label}"
}

compiler_version=""
if [[ -n "${compiler_bin}" ]]; then
  compiler_version="$("${compiler_bin}" --version | head -n 1)"
fi

git_revision="unknown"
git_tree_state="unavailable"
if git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git_revision="$(git -C "${repo_root}" rev-parse --verify HEAD 2>/dev/null || true)"
  if [[ -z "${git_revision}" ]]; then
    git_revision="unborn"
  fi

  git_tree_state="clean"
  if ! git -C "${repo_root}" diff --quiet --ignore-submodules=all --exit-code 2>/dev/null || \
     ! git -C "${repo_root}" diff --cached --quiet --ignore-submodules=all --exit-code 2>/dev/null; then
    git_tree_state="dirty"
  fi
fi
cpu_model="$(lscpu 2>/dev/null | awk -F: '/Model name:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
kernel_line="$(uname -srvmo)"
governor="unknown"
governor_path=""
available_governors_path=""
requested_governor="unchanged"
restore_governor=""
restore_governor_path=""

restore_cpu_governor() {
  if [[ -n "${restore_governor_path}" ]] && [[ -n "${restore_governor}" ]]; then
    printf '%s\n' "${restore_governor}" > "${restore_governor_path}"
  fi
}

trap restore_cpu_governor EXIT

if [[ -n "${cpu_to_use}" ]]; then
  governor_path="/sys/devices/system/cpu/cpu${cpu_to_use}/cpufreq/scaling_governor"
  available_governors_path="/sys/devices/system/cpu/cpu${cpu_to_use}/cpufreq/scaling_available_governors"
fi

if [[ -n "${governor_path}" ]] && [[ -r "${governor_path}" ]]; then
  governor="$(<"${governor_path}")"
fi

if [[ -n "${governor_path}" ]] && [[ -w "${governor_path}" ]] && [[ -r "${available_governors_path}" ]]; then
  if grep -qw performance "${available_governors_path}" && [[ "${governor}" != "performance" ]]; then
    printf '%s\n' performance > "${governor_path}"
    requested_governor="performance"
    restore_governor="${governor}"
    restore_governor_path="${governor_path}"
    governor="$(<"${governor_path}")"
  fi
fi

configure_and_build "${object_build_dir}" OBJECT
configure_and_build "${static_build_dir}" STATIC

mapfile -t benchmarks < <("${object_build_dir}/basics_benchmarks" --list | awk -F'\t' '$1 ~ /^containers\./ {print $1}')

if [[ ${#benchmarks[@]} -eq 0 ]]; then
  echo "no container benchmarks found" >&2
  exit 1
fi

declare -A canonical_index_by_benchmark=()
for ((index = 0; index < ${#benchmarks[@]}; ++index)); do
  canonical_index_by_benchmark["${benchmarks[index]}"]="${index}"
done

declare -A fixed_iterations_by_benchmark=()
for benchmark in "${benchmarks[@]}"; do
  fixed_iterations_by_benchmark["${benchmark}"]="$(calibrate_fixed_iterations "${benchmark}")"
done

probe_output="$(run_benchmark_output "${object_build_dir}" "${benchmarks[0]}" "OBJECT-probe" 1 1 0)"
hasher_seed_policy="$(parse_header_metric hasher_seed_policy "OBJECT-probe" "${probe_output}")"
hasher_seed="$(parse_header_metric hasher_seed "OBJECT-probe" "${probe_output}")"

printf 'round\tbenchmark_index\tbenchmark\tmode\tmode_order_slot\tns_per_op\tops_per_s\tmedian_ns\titerations\n' > "${raw_file}"

for ((round = 1; round <= rounds; ++round)); do
  if (( round % 2 == 1 )); then
    ordered_benchmarks=("${benchmarks[@]}")
  else
    ordered_benchmarks=()
    for ((index = ${#benchmarks[@]} - 1; index >= 0; --index)); do
      ordered_benchmarks+=("${benchmarks[index]}")
    done
  fi

  for ((bench_index = 0; bench_index < ${#ordered_benchmarks[@]}; ++bench_index)); do
    benchmark="${ordered_benchmarks[bench_index]}"
    canonical_index="${canonical_index_by_benchmark[${benchmark}]}"

    if (( (round + canonical_index) % 2 == 0 )); then
      mode_sequence=("OBJECT" "STATIC")
    else
      mode_sequence=("STATIC" "OBJECT")
    fi

    for slot in 0 1; do
      mode="${mode_sequence[slot]}"
      if [[ "${mode}" == "OBJECT" ]]; then
        build_dir="${object_build_dir}"
      else
        build_dir="${static_build_dir}"
      fi

      IFS=$'\t' read -r ns_per_op ops_per_s median_ns iterations_run mode_label < <(run_one "${build_dir}" "${benchmark}" "${mode}" "${fixed_iterations_by_benchmark[${benchmark}]}")
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${round}" "${bench_index}" "${benchmark}" "${mode_label}" "$((slot + 1))" \
        "${ns_per_op}" "${ops_per_s}" "${median_ns}" "${iterations_run}" >> "${raw_file}"
    done
  done
done

python - "${raw_file}" "${summary_file}" <<'PY'
import csv
import statistics
import sys
from collections import defaultdict

raw_path, summary_path = sys.argv[1], sys.argv[2]
metrics = defaultdict(lambda: defaultdict(list))
ops = defaultdict(lambda: defaultdict(list))
slot_metrics = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

with open(raw_path, newline="") as f:
    reader = csv.DictReader(f, delimiter="\t")
    for row in reader:
        metrics[row["benchmark"]][row["mode"]].append(float(row["ns_per_op"]))
        ops[row["benchmark"]][row["mode"]].append(float(row["ops_per_s"]))
        slot_metrics[row["benchmark"]][row["mode"]][row["mode_order_slot"]].append(float(row["ns_per_op"]))

def median_absolute_deviation(samples, median):
    return statistics.median(abs(sample - median) for sample in samples)

def slot_median(samples):
    return statistics.median(samples) if samples else float("nan")

def slot_bias_pct(first_slot, second_slot):
    if first_slot == 0.0 or first_slot != first_slot or second_slot != second_slot:
        return float("nan")
    return ((second_slot - first_slot) / first_slot) * 100.0

with open(summary_path, "w", newline="") as out:
    out.write(
        "benchmark\t"
        "object_median_ns_per_op\tobject_mad_ns_per_op\t"
        "static_median_ns_per_op\tstatic_mad_ns_per_op\t"
        "delta_pct_static_vs_object\t"
        "object_median_ops_per_s\tstatic_median_ops_per_s\t"
        "object_slot1_median_ns_per_op\tobject_slot2_median_ns_per_op\tobject_slot_bias_pct_second_vs_first\t"
        "static_slot1_median_ns_per_op\tstatic_slot2_median_ns_per_op\tstatic_slot_bias_pct_second_vs_first\t"
        "object_runs\tstatic_runs\n"
    )
    for benchmark in sorted(metrics):
        object_ns = statistics.median(metrics[benchmark]["OBJECT"])
        static_ns = statistics.median(metrics[benchmark]["STATIC"])
        object_mad = median_absolute_deviation(metrics[benchmark]["OBJECT"], object_ns)
        static_mad = median_absolute_deviation(metrics[benchmark]["STATIC"], static_ns)
        object_ops = statistics.median(ops[benchmark]["OBJECT"])
        static_ops = statistics.median(ops[benchmark]["STATIC"])
        delta_pct = ((static_ns - object_ns) / object_ns) * 100.0
        object_slot1 = slot_median(slot_metrics[benchmark]["OBJECT"]["1"])
        object_slot2 = slot_median(slot_metrics[benchmark]["OBJECT"]["2"])
        static_slot1 = slot_median(slot_metrics[benchmark]["STATIC"]["1"])
        static_slot2 = slot_median(slot_metrics[benchmark]["STATIC"]["2"])
        object_slot_bias = slot_bias_pct(object_slot1, object_slot2)
        static_slot_bias = slot_bias_pct(static_slot1, static_slot2)
        out.write(
            f"{benchmark}\t"
            f"{object_ns:.2f}\t{object_mad:.2f}\t"
            f"{static_ns:.2f}\t{static_mad:.2f}\t"
            f"{delta_pct:.2f}\t"
            f"{object_ops:.2f}\t{static_ops:.2f}\t"
            f"{object_slot1:.2f}\t{object_slot2:.2f}\t{object_slot_bias:.2f}\t"
            f"{static_slot1:.2f}\t{static_slot2:.2f}\t{static_slot_bias:.2f}\t"
            f"{len(metrics[benchmark]['OBJECT'])}\t{len(metrics[benchmark]['STATIC'])}\n"
        )
PY

{
  echo "# container allocator comparison"
  echo "# generated_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "# git_revision=${git_revision}"
  echo "# git_tree_state=${git_tree_state}"
  echo "# compiler=${compiler_bin}"
  echo "# compiler_version=${compiler_version}"
  echo "# kernel=${kernel_line}"
  echo "# cpu_model=${cpu_model}"
  echo "# pinned_cpu=${cpu_to_use:-none}"
  echo "# cpu_governor=${governor}"
  echo "# cpu_governor_requested=${requested_governor}"
  echo "# hasher_seed_policy=${hasher_seed_policy}"
  echo "# hasher_seed=${hasher_seed}"
  echo "# min_time_ms=${min_time_ms}"
  echo "# warmup_runs=${warmup_runs}"
  echo "# repetitions=${repetitions}"
  echo "# rounds=${rounds}"
  echo "# object_build_dir=${object_build_dir}"
  echo "# static_build_dir=${static_build_dir}"
  echo "# protocol=fresh_process_per_measurement, fixed_iterations_per_benchmark=max(object_calibration,static_calibration), alternating_mode_order, alternating_benchmark_order, slot_bias_reported, median_and_mad_summary, temporary_performance_governor_when_writable"
  echo
  cat "${summary_file}"
} > "${summary_file}.tmp"
mv "${summary_file}.tmp" "${summary_file}"

echo "wrote raw results to ${raw_file}"
echo "wrote summary to ${summary_file}"
