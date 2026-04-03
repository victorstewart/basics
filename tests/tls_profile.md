<!-- Copyright 2026 Victor Stewart -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# TLS Profiling

`basics` ships one repo-owned TLS profiling entrypoint:

```bash
./tests/run_profile_tls.sh
```

This runner builds `basics_tls_profile` with `RelWithDebInfo`, then captures per-scenario artifacts with:

- `perf record -e cpu-clock --call-graph dwarf`
- `perf report --stdio`
- `inferno-collapse-perf`
- `inferno-flamegraph`
- `strace -c`
- gperftools heap profiling through `LD_PRELOAD=/usr/lib/libtcmalloc_and_profiler.so`

## Scenarios

- `tls-handshake`: repeated TLS negotiation over `TLSBase` memory BIOs with preloaded in-memory `SSL_CTX`s
- `tls-steady-state`: repeated bidirectional encrypted read/write after one negotiated handshake
- `tls-long-lived-session`: one negotiated session followed by 32 bidirectional transfers per iteration, intended to produce a denser steady-state profile for `encryptInto()` / `decryptFrom()` and BIO buffer behavior

List or run them directly through the executable if needed:

```bash
./build/tls-profile/basics_tls_profile --list-scenarios
./build/tls-profile/basics_tls_profile --scenario tls-handshake --iterations 128
./build/tls-profile/basics_tls_profile --scenario tls-steady-state --iterations 128 --payload-bytes 4096
./build/tls-profile/basics_tls_profile --scenario tls-long-lived-session --iterations 64 --payload-bytes 16384
```

## What This Is Auditing

The profile is aimed at the exact copy/allocation points inside `networking/tls.h`:

- `setupTLS()` allocates `SSL` plus the inbound and outbound memory BIOs
- `encryptInto()` feeds plaintext from `Buffer` into `SSL_write()`, then copies encrypted bytes from the read BIO back into `Buffer`
- `decryptFrom()` copies received ciphertext from `Buffer` into the write BIO, then copies decrypted plaintext back out with `SSL_read()`
- steady-state behavior is dominated by those BIO and `Buffer` transitions rather than context parsing, so the profile keeps `SSL_CTX` creation outside the timed steady-state loop

Use the benchmark harness for comparable timing numbers:

```bash
./tests/run_benchmarks.sh --filter tls
```

That covers:

- `scenario.tls.generate_ctx_from_pem`
- `scenario.tls.handshake_memory_bio`
- `scenario.tls.steady_state_roundtrip_4k`

## Standard Capture

Capture the default TLS profile set into the default output directory:

```bash
./tests/run_profile_tls.sh
```

That default run now captures:

- `tls-handshake`
- `tls-long-lived-session`

Capture only the handshake path:

```bash
./tests/run_profile_tls.sh --scenario tls-handshake --iterations 256
```

Capture the denser long-lived steady-state path with a larger payload:

```bash
./tests/run_profile_tls.sh --scenario tls-long-lived-session --iterations 64 --payload-bytes 16384
```

Capture the shorter single-round-trip steady-state path when you specifically want that smaller shape:

```bash
./tests/run_profile_tls.sh --scenario tls-steady-state --iterations 128 --payload-bytes 16384
```

Write artifacts somewhere else:

```bash
./tests/run_profile_tls.sh --output-dir /tmp/basics-tls-profile
```

## Output Artifacts

For each scenario, the runner emits:

- `<scenario>.perf.data`: raw sampled profile
- `<scenario>.perf.txt`: `perf report --stdio` summary
- `<scenario>.perf.folded`: collapsed stack file
- `<scenario>.perf.svg`: flamegraph
- `<scenario>.strace.txt`: syscall summary from `strace -c`
- `<scenario>.heap.*`: raw gperftools heap-profile snapshots
- `<scenario>.heap.log`: heap-profiler progress log

The heap artifacts are intentionally kept in raw gperftools format so they can be rendered or diffed later with the preferred `pprof` tooling for the target machine.

## Comparison Workflow

Capture a baseline:

```bash
./tests/run_profile_tls.sh --output-dir /tmp/basics-tls-profile-before
./tests/run_benchmarks.sh --filter tls > /tmp/basics-tls-bench-before.txt
```

Capture the post-change result:

```bash
./tests/run_profile_tls.sh --output-dir /tmp/basics-tls-profile-after
./tests/run_benchmarks.sh --filter tls > /tmp/basics-tls-bench-after.txt
diff -u /tmp/basics-tls-profile-before/tls-handshake.perf.txt /tmp/basics-tls-profile-after/tls-handshake.perf.txt
diff -u /tmp/basics-tls-profile-before/tls-long-lived-session.perf.txt /tmp/basics-tls-profile-after/tls-long-lived-session.perf.txt
diff -u /tmp/basics-tls-bench-before.txt /tmp/basics-tls-bench-after.txt
```

For flamegraph comparison, open the paired `.perf.svg` files side by side.
