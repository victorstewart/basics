<!-- Copyright 2026 Victor Stewart -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# basics

`basics` is my personal C++20 utility library.

It builds through CMake with `depos`-managed dependencies. Release tags publish a detached
`basics.DepoFile` asset alongside the GitHub source tarball so `depos 0.5.0+` consumers can
download one depofile, fetch the source tarball, and let the embedded `depofiles/` tree resolve
the full dependency graph.

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

## Release Asset

Generate the detached published release depofile for the current tagged version:

```bash
cmake -DOUTPUT="$PWD/.run/release-assets/basics.DepoFile" -P tools/generate_release_depofile.cmake
```

## License

Apache-2.0. See [LICENSE](LICENSE).
