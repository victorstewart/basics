#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Wrapper for clang-format that enforces the pinned major version
# and ensures the repo's .clang-format is respected.
#
# - Pinned major: 21 (see AGENTS.md)
# - Injects -style=file unless already provided
# - Fails fast with guidance if the detected version != 21
#
# Usage examples:
#   scripts/clang-format.sh -i path/to/file.cpp
#   git ls-files | rg -n '\.(c|cc|cxx|cpp|ixx|mpp|cppm|h|hh|hpp|ipp|tpp|tcc|inl|inc)$' -N -o | \
#     xargs -I{} scripts/clang-format.sh -i {}

PINNED_MAJOR=21

resolve_bin() {
  # Priority: $CLANG_FORMAT (env) > clang-format-21 > /opt/homebrew llvm > clang-format (any) > brew llvm@21
  local cand

  if [[ -n "${CLANG_FORMAT:-}" && -x "${CLANG_FORMAT}" ]]; then
    echo "$CLANG_FORMAT"; return 0
  fi

  for cand in \
    clang-format-21 \
    /opt/homebrew/opt/llvm/bin/clang-format \
    clang-format
  do
    if command -v "$cand" >/dev/null 2>&1; then
      echo "$(command -v "$cand")"; return 0
    fi
    [[ -x "$cand" ]] && { echo "$cand"; return 0; }
  done

  if command -v brew >/dev/null 2>&1; then
    if brew --prefix llvm@21 >/dev/null 2>&1; then
      local p
      p="$(brew --prefix llvm@21)/bin/clang-format"
      [[ -x "$p" ]] && { echo "$p"; return 0; }
    fi
  fi

  return 1
}

detect_major() {
  local bin="$1"
  "$bin" --version 2>/dev/null | sed -nE 's/.*version ([0-9]+).*/\1/p'
}

die_with_help() {
  local msg="$1"
  cat >&2 <<EOF
ERROR: $msg

Pinned clang-format major: ${PINNED_MAJOR}

Install hints:
  - macOS (Homebrew, Apple Silicon):
      arch -arm64 brew install llvm
      echo 'export PATH="/opt/homebrew/opt/llvm/bin:\$PATH"' >> ~/.bash_profile
  - macOS (Homebrew, Intel prefix):
      brew install llvm
      echo 'export PATH="/usr/local/opt/llvm/bin:\$PATH"' >> ~/.bash_profile
  - Ubuntu/Debian:
      sudo apt-get update && sudo apt-get install -y clang-format-${PINNED_MAJOR}
      sudo update-alternatives --install /usr/bin/clang-format clang-format \
        /usr/bin/clang-format-${PINNED_MAJOR} 100

Alternatively, set CLANG_FORMAT to an absolute path of a ${PINNED_MAJOR}.x binary.
EOF
  exit 2
}

BIN=$(resolve_bin || true)
[[ -n "${BIN:-}" ]] || die_with_help "No clang-format binary found."

MAJOR=$(detect_major "$BIN")
[[ -n "${MAJOR:-}" ]] || die_with_help "Could not detect clang-format major version from: $BIN"

if [[ "$MAJOR" != "$PINNED_MAJOR" ]]; then
  die_with_help "Found clang-format major $MAJOR, expected ${PINNED_MAJOR}. BIN=$BIN"
fi

# Ensure the repo config is parseable by this version.
if ! "$BIN" -style=file -dump-config >/dev/null 2>&1; then
  cat >&2 <<EOF
ERROR: $BIN could not parse .clang-format with -style=file.
       Verify the config or the installed clang-format ${PINNED_MAJOR}.x.
EOF
  exit 3
fi

# Inject -style=file unless provided by the caller.
args=("$@")
has_style=false
for a in "${args[@]:-}"; do
  [[ "$a" == "-style" || "$a" == -style=* ]] && { has_style=true; break; }
done

if [[ "$has_style" == false ]]; then
  args=("-style=file" "${args[@]}")
fi

exec "$BIN" "${args[@]}"

