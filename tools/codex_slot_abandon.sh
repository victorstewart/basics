#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

slot="${1:?slot name (e.g. 1) OR 'all'}"

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

common_git_dir="$(git rev-parse --git-common-dir)"
main_root="$(cd "${common_git_dir}/.." && pwd)"

cd "$main_root"

base_branch="$(resolve_base_branch "$main_root")"
git switch "$base_branch" >/dev/null 2>&1 || true

abandon_one()
{
  local s="$1"
  local wt_path="${main_root}/.worktrees/codex-${s}"
  local branch="codex/${s}"

  if ! printf '%s' "$s" | grep -Eq '^[A-Za-z0-9._-]+$'
  then
    echo "Invalid slot: $s (use only A-Za-z0-9._-)" >&2
    exit 1
  fi

  if [ -d "$wt_path" ]
  then
    git worktree remove --force "$wt_path" || true
  fi

  if [ -d "$wt_path" ]
  then
    rm -rf "$wt_path"
  fi

  if git show-ref --verify --quiet "refs/heads/${branch}"
  then
    git branch -D "$branch"
  fi
}

if [ "$slot" = "all" ]
then
  if [ -d "${main_root}/.worktrees" ]
  then
    for d in "${main_root}/.worktrees"/codex-*
    do
      if [ -d "$d" ]
      then
        s="$(basename "$d")"
        s="${s#codex-}"
        if [ -n "$s" ]
        then
          abandon_one "$s"
        fi
      fi
    done
  fi
else
  abandon_one "$slot"
fi

git worktree prune >/dev/null 2>&1 || true
