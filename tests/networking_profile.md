<!-- Copyright 2026 Victor Stewart -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Networking Profiling

`basics` ships one repo-owned networking profiling entrypoint:

```bash
./tests/run_profile_networking.sh
```

This runner builds `basics_networking_profile` and `basics_tls_tests` with `RelWithDebInfo`, then captures sampled profiles for the selected scenarios with:

- `perf record -e cpu-clock --call-graph dwarf`
- `perf report --stdio`
- `inferno-collapse-perf`
- `inferno-flamegraph`
- `strace -c`

## Scenarios

- `ring-loopback`: dedicated loopback TCP accept/recv/send/close workload through `Ring`, `TCPSocket`, and `TCPStream`
- `tls-tests`: repeated execution of the checked-in `basics_tls_tests` executable to profile the current `TLSBase` behavior

For the deeper TLS copy/allocation tranche introduced by `O1.2`, use [tests/tls_profile.md](tls_profile.md). That runner isolates handshake and the denser long-lived TLS session workload directly instead of profiling the broader correctness test binary.

List or run them directly through the executable if needed:

```bash
./build/networking-profile/basics_networking_profile --list-scenarios
./build/networking-profile/basics_networking_profile --scenario ring-loopback --iterations 128
```

## Standard Capture

Capture both scenarios into the default output directory:

```bash
./tests/run_profile_networking.sh
```

Capture only the ring path:

```bash
./tests/run_profile_networking.sh --scenario ring-loopback --iterations 128 --payload-bytes 4096
./tests/run_profile_networking.sh --scenario tls-tests --iterations 16
```

Write artifacts somewhere else:

```bash
./tests/run_profile_networking.sh --output-dir /tmp/basics-network-profile
```

## Output Artifacts

For each scenario, the runner emits:

- `<scenario>.perf.data`: raw sampled profile
- `<scenario>.perf.txt`: `perf report --stdio` summary
- `<scenario>.perf.folded`: collapsed stack file
- `<scenario>.perf.svg`: flamegraph
- `<scenario>.strace.txt`: syscall summary from `strace -c`

## Comparison Workflow

Capture a baseline:

```bash
./tests/run_profile_networking.sh --output-dir /tmp/basics-network-profile-before
```

Capture the post-change result:

```bash
./tests/run_profile_networking.sh --output-dir /tmp/basics-network-profile-after
diff -u /tmp/basics-network-profile-before/ring-loopback.perf.txt /tmp/basics-network-profile-after/ring-loopback.perf.txt
diff -u /tmp/basics-network-profile-before/ring-loopback.strace.txt /tmp/basics-network-profile-after/ring-loopback.strace.txt
```

For flamegraph comparison, open the paired `.perf.svg` files side by side.
