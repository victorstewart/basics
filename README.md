<!-- Copyright 2026 Victor Stewart -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# basics

`basics` is my personal C++20 utility library.

This repo is public for source visibility and collaboration, but it is not a supported public package and no external adoption surface is promised.

It builds through CMake with `depos`-managed dependencies.

## Build And Test

Recommended quick path:

```bash
bash ./tests/run.sh
```

Sanitizer lane:

```bash
bash ./tests/run.sh --sanitizers
```

Full supported matrix across `BASICS_MIMALLOC_MODE`, `BASICS_DEPENDENCY_LINK_MODE`, and `BASICS_ENABLE_TIDESDB`:

```bash
bash ./tests/run.sh --matrix
```

Direct CMake path:

```bash
cmake -S . -B build -DBASICS_MIMALLOC_MODE=OBJECT -DBASICS_DEPENDENCY_LINK_MODE=STATIC
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure -j"$(nproc)"
```

Other repo-owned workflows, including benchmarks and profiling, live under `tests/`.

## License

Apache-2.0. See [LICENSE](LICENSE).
