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
wt_path="${repo_root}/.worktrees/codex-${slot}"
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

if [ ! -d "$wt_path" ]
then
  echo "Worktree path does not exist: $wt_path" >&2
  exit 1
fi

status_lines="$(git -C "$wt_path" status --porcelain | grep -Ev '^\?\? \.codex(/.*)?$' || true)"
if [ -n "$status_lines" ]
then
  echo "Worktree has uncommitted changes: $wt_path" >&2
  printf '%s\n' "$status_lines" >&2
  exit 1
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

git -C "$wt_path" fetch origin
git -C "$wt_path" rebase "$base_branch"

git -C "$repo_root" merge --no-ff --no-edit "$branch"

git -C "$repo_root" worktree remove --force "$wt_path"
git -C "$repo_root" branch -d "$branch"
