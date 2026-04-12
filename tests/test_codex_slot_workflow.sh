#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
slot_start="${repo_root}/tools/codex_slot_start.sh"
slot_land="${repo_root}/tools/codex_slot_land.sh"
slot_abandon="${repo_root}/tools/codex_slot_abandon.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

create_clone_repo()
{
  local root="$1"
  local initial_branch="$2"
  local seed_repo="${root}/seed"
  local origin_repo="${root}/origin.git"
  local clone_repo="${root}/clone"

  mkdir -p "$root"
  git init --initial-branch="$initial_branch" "$seed_repo" >/dev/null
  git -C "$seed_repo" config user.name "codex-slot-test"
  git -C "$seed_repo" config user.email "codex-slot-test@example.com"
  printf '%s\n' "hello" > "${seed_repo}/README.md"
  git -C "$seed_repo" add README.md
  git -C "$seed_repo" commit -m "init" >/dev/null

  git clone --bare "$seed_repo" "$origin_repo" >/dev/null
  git clone "$origin_repo" "$clone_repo" >/dev/null
  git -C "$clone_repo" config user.name "codex-slot-test"
  git -C "$clone_repo" config user.email "codex-slot-test@example.com"

  printf '%s\n' "$clone_repo"
}

make_stub_codex()
{
  local root="$1"
  local stub_bin="${root}/bin"

  mkdir -p "$stub_bin"
  cat > "${stub_bin}/codex" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
  chmod +x "${stub_bin}/codex"

  printf '%s\n' "$stub_bin"
}

run_case_branch_reuse()
{
  local case_root="${tmp_dir}/branch_reuse"
  local clone_repo
  local stub_bin

  clone_repo="$(create_clone_repo "$case_root" main)"
  stub_bin="$(make_stub_codex "$case_root")"

  git -C "$clone_repo" branch "codex/1"

  (
    cd "$clone_repo"
    PATH="${stub_bin}:${PATH}" bash "$slot_start" 1 >/dev/null
  )

  test -d "${clone_repo}/.worktrees/codex-1"
  test "$(git -C "${clone_repo}/.worktrees/codex-1" rev-parse --abbrev-ref HEAD)" = "codex/1"
}

run_case_base_branch_resolution()
{
  local case_root="${tmp_dir}/base_branch"
  local clone_repo
  local stub_bin

  clone_repo="$(create_clone_repo "$case_root" master)"
  stub_bin="$(make_stub_codex "$case_root")"

  (
    cd "$clone_repo"
    PATH="${stub_bin}:${PATH}" bash "$slot_start" 2 >/dev/null
  )

  test ! -d "${clone_repo}/.worktrees/codex-1"
  test -d "${clone_repo}/.worktrees/codex-2"
  test "$(git -C "${clone_repo}/.worktrees/codex-2" rev-parse --abbrev-ref HEAD)" = "codex/2"
  test "$(git -C "${clone_repo}/.worktrees/codex-2" rev-parse HEAD)" = "$(git -C "${clone_repo}" rev-parse master)"
  if git -C "$clone_repo" show-ref --verify --quiet refs/heads/main
  then
    echo "unexpected main branch in master-based test repo" >&2
    exit 1
  fi
}

run_case_land_and_abandon()
{
  local case_root="${tmp_dir}/land_and_abandon"
  local clone_repo
  local stub_bin
  local worktree_path

  clone_repo="$(create_clone_repo "$case_root" main)"
  stub_bin="$(make_stub_codex "$case_root")"

  (
    cd "$clone_repo"
    PATH="${stub_bin}:${PATH}" bash "$slot_start" 3 >/dev/null
  )

  worktree_path="${clone_repo}/.worktrees/codex-3"
  printf '%s\n' "landed" > "${worktree_path}/feature.txt"
  git -C "$worktree_path" add feature.txt
  git -C "$worktree_path" commit -m "slot change" >/dev/null

  (
    cd "$clone_repo"
    bash "$slot_land" 3 >/dev/null
  )

  test ! -d "$worktree_path"
  if git -C "$clone_repo" show-ref --verify --quiet refs/heads/codex/3
  then
    echo "slot branch codex/3 was not deleted after landing" >&2
    exit 1
  fi
  test -f "${clone_repo}/feature.txt"
  grep -Fxq 'landed' "${clone_repo}/feature.txt"

  (
    cd "$clone_repo"
    PATH="${stub_bin}:${PATH}" bash "$slot_start" 4 >/dev/null
  )

  printf '%s\n' "dirty" > "${clone_repo}/.worktrees/codex-4/dirty.txt"

  (
    cd "$clone_repo"
    bash "$slot_abandon" all >/dev/null
  )

  test ! -d "${clone_repo}/.worktrees/codex-4"
  if git -C "$clone_repo" show-ref --verify --quiet refs/heads/codex/4
  then
    echo "slot branch codex/4 was not deleted after abandon all" >&2
    exit 1
  fi
}

run_case_branch_reuse
run_case_base_branch_resolution
run_case_land_and_abandon
