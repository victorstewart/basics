<!-- Copyright 2026 Victor Stewart -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Benchmarks

`basics` ships one repo-owned benchmark entrypoint:

```bash
./tests/run_benchmarks.sh
```

That runner configures and builds `basics_benchmarks` with:

- `BASICS_MIMALLOC_MODE=OBJECT`
- `BASICS_DEPENDENCY_LINK_MODE=STATIC`
- `BASICS_SANITIZER_MODE=NONE`
- `clang++` when available, otherwise `g++`, otherwise the toolchain default

## CLI

List the checked-in benchmark set:

```bash
./tests/run_benchmarks.sh --list
```

Run a filtered subset:

```bash
./tests/run_benchmarks.sh --filter codec
./tests/run_benchmarks.sh --filter tls
./tests/run_benchmarks.sh --filter bitsery
```

Tune run length:

```bash
./tests/run_benchmarks.sh --min-time-ms 50 --repetitions 5
```

Override the build shape when you need to compare allocator modes or dependency-link modes:

```bash
BASICS_MIMALLOC_MODE=STATIC \
BASICS_BENCHMARK_BUILD_DIR=./build/benchmarks-static \
./tests/run_benchmarks.sh --filter containers
```

The harness prints `use_mimalloc=<0|1|2>`, `allocator_mode=<none|object|explicit>`, `hasher_seed_policy=...`, and `hasher_seed=...` on the header line so saved baselines are self-describing.

The harness prints one stable `benchmark=... key=value ...` line per benchmark. That output is intended to be redirected to a file and compared over time. For one-benchmark isolation runs, use `--exact <full-benchmark-name>`. For fresh-process comparison runs, the controlled runner adds one untimed warm-up execution per measurement by default.

For allocator-mode numbers you want to share externally, use the controlled comparison runner instead of ad hoc `run_benchmarks.sh` output:

```bash
./tests/run_compare_container_allocator_modes.sh
```

That runner:

- builds both `BASICS_MIMALLOC_MODE=OBJECT` and `BASICS_MIMALLOC_MODE=STATIC`
- runs each benchmark in a fresh process
- alternates allocator-mode order across rounds and benchmarks
- alternates benchmark order across rounds
- pins execution to one allowed CPU when `taskset` is available
- temporarily requests the pinned CPU's `performance` governor when the host exposes it and the runner can restore it afterward
- records the fixed benchmark hash-seed policy and seed in the summary metadata
- emits:
  - `build/benchmarks-compare/container_allocator_compare_raw.tsv`
  - `build/benchmarks-compare/container_allocator_compare.txt`

## Current Categories

- `string.*`: `String` growth and append hot paths
- `containers.noncrypto_hasher.*`: direct hasher throughput for string, pointer, and integral keys
- `containers.keys_are_equal.*`: direct equality throughput for string, pointer, and integral keys
- `containers.bytell_hash_map.*`: map lookup and insert/lookup/erase workloads across string, pointer, and integral keys
- `containers.bytell_hash_set.*`: set insert/lookup/erase workloads
- `containers.vector.*`: `Vector` push/contains/erase wrapper behavior
- `codec.*`: Base64 and Base62 encode/decode throughput
- `serialization.bitsery.*`: `BitseryEngine` serialize, deserialize, and round-trip behavior for representative map and vector payloads
- `scenario.message.*`: direct wire-message construction behavior
- `scenario.stream.*`: wire-message construction and framing
- `scenario.tls.*`: TLS context creation, memory-BIO handshake, and steady-state encrypted round-trip behavior from checked-in PEM fixtures

## Baseline Capture

Capture a baseline:

```bash
./tests/run_benchmarks.sh --min-time-ms 50 --repetitions 5 > /tmp/basics-benchmark-baseline.txt
```

Capture a comparison after a change:

```bash
./tests/run_benchmarks.sh --min-time-ms 50 --repetitions 5 > /tmp/basics-benchmark-current.txt
diff -u /tmp/basics-benchmark-baseline.txt /tmp/basics-benchmark-current.txt
```

Compare `USE_MIMALLOC=1` against the explicit STL allocator path (`USE_MIMALLOC=2`) for the container wrappers:

```bash
./tests/run_compare_container_allocator_modes.sh --min-time-ms 100 --repetitions 7 --rounds 7
cat ./build/benchmarks-compare/container_allocator_compare.txt
```

`OBJECT` produces `use_mimalloc=1`, while `STATIC` and `SHARED` produce `use_mimalloc=2`, which is the explicit `mi_stl_allocator` path used by the container wrappers. The controlled comparison runner also forces the benchmark-side hash policy to a deterministic global seed so fresh-process runs do not compare different random hash seeds.

Use the plain `run_benchmarks.sh` flow for quick exploration and optimization work. Use `run_compare_container_allocator_modes.sh` when you need a summary that minimizes order bias and is suitable for discussion with upstream maintainers. Its summary reports both per-mode median absolute deviation and first-slot versus second-slot medians so order effects remain visible instead of being hand-waved away.

For cleaner comparisons, keep the machine stable while measuring:

- avoid running the sanitizer lane
- avoid mixing benchmark runs with the full `--matrix` test lane
- reuse the same compiler and build type
- rerun the same filtered subset when comparing a targeted optimization
