#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

slot="${1:?slot name}"

if ! printf '%s' "$slot" | grep -Eq '^[A-Za-z0-9._-]+$'
then
  echo "Invalid slot: $slot (use only A-Za-z0-9._-)" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
wt_base="${repo_root}/.worktrees"
wt_path="${wt_base}/codex-${slot}"
branch="codex/${slot}"

resolve_base_branch()
{
  local repo="$1"
  local base=""

  if base="$(git -C "$repo" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)"
  then
    base="${base#origin/}"
  fi

  if [ -z "$base" ]
  then
    if git -C "$repo" show-ref --verify --quiet refs/heads/main
    then
      base="main"
    elif git -C "$repo" show-ref --verify --quiet refs/heads/master
    then
      base="master"
    else
      base="$(git -C "$repo" rev-parse --abbrev-ref HEAD)"
    fi
  fi

  printf '%s\n' "$base"
}

base_branch="$(resolve_base_branch "$repo_root")"

mkdir -p "$wt_base"

main_exclude="$(git -C "$repo_root" rev-parse --git-path info/exclude)"
if ! grep -Fxq '.worktrees/' "$main_exclude" 2>/dev/null
then
  printf '%s\n' '.worktrees/' >> "$main_exclude"
fi

git -C "$repo_root" fetch origin
git -C "$repo_root" switch "$base_branch"

main_status_lines="$(git -C "$repo_root" status --porcelain | grep -Ev '^\?\? \.worktrees(/.*)?$' || true)"
if [ -n "$main_status_lines" ]
then
  echo "Base worktree has uncommitted changes; commit/stash first." >&2
  printf '%s\n' "$main_status_lines" >&2
  exit 1
fi

git -C "$repo_root" pull --ff-only

if [ ! -d "$wt_path" ]
then
  git -C "$repo_root" worktree prune >/dev/null 2>&1 || true

  if git -C "$repo_root" show-ref --verify --quiet "refs/heads/${branch}"
  then
    git -C "$repo_root" worktree add "$wt_path" "$branch"
  else
    git -C "$repo_root" worktree add "$wt_path" -b "$branch" "$base_branch"
  fi
else
  if ! git -C "$wt_path" rev-parse --is-inside-work-tree >/dev/null 2>&1
  then
    echo "Worktree path exists but is not a git worktree: $wt_path" >&2
    echo "Remove it or run: ./tools/codex_slot_abandon.sh $slot" >&2
    exit 1
  fi
fi

mkdir -p "${wt_path}/.codex"

wt_exclude="$(git -C "$wt_path" rev-parse --git-path info/exclude)"
if ! grep -Fxq '.codex/' "$wt_exclude" 2>/dev/null
then
  printf '%s\n' '.codex/' >> "$wt_exclude"
fi

global_codex_home="${CODEX_HOME:-$HOME/.codex}"
global_auth="${global_codex_home}/auth.json"
global_cfg="${global_codex_home}/config.toml"

slot_auth="${wt_path}/.codex/auth.json"
slot_cfg="${wt_path}/.codex/config.toml"

if [ ! -e "$slot_auth" ] && [ -f "$global_auth" ]
then
  cp -f "$global_auth" "$slot_auth"
  chmod 600 "$slot_auth" 2>/dev/null || true
fi

if [ ! -e "$slot_cfg" ] && [ -f "$global_cfg" ]
then
  cp -f "$global_cfg" "$slot_cfg"
  chmod 600 "$slot_cfg" 2>/dev/null || true
fi

command -v codex >/dev/null 2>&1 || { echo "codex not found in PATH" >&2; exit 1; }
CODEX_HOME="${wt_path}/.codex" codex --cd "$wt_path"
