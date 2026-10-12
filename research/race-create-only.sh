#!/usr/bin/env bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for mode in ordinary create_only; do
  mkdir -p "$tmp/$mode"
  cd "$tmp/$mode"
  git init -q --bare remote.git
  git clone -q remote.git a
  git -C a config user.email probe@example.invalid
  git -C a config user.name Probe
  printf 'base\n' > a/README.md
  git -C a add .
  git -C a commit -qm base
  git -C a push -q origin HEAD:refs/heads/master
  git clone -q remote.git b
  printf 'base\nA\n' > a/README.md
  git -C a commit -qam change
  ref=refs/heads/research/probe
  test -z "$(git -C a ls-remote --heads origin "$ref")"
  initial=$(git -C b rev-parse HEAD)
  git -C b push -q origin "$initial:$ref"
  before=$(git --git-dir=remote.git rev-parse "$ref")
  set +e
  if [ "$mode" = ordinary ]; then
    git -C a push origin "HEAD:$ref" >/dev/null 2>&1
  else
    git -C a push "--force-with-lease=$ref:" origin "HEAD:$ref" >/dev/null 2>&1
  fi
  rc=$?
  set -e
  after=$(git --git-dir=remote.git rev-parse "$ref")
  if [ "$mode" = ordinary ]; then
    test "$rc" -eq 0 && test "$before" != "$after"
    echo "race_ordinary_overwrote_branch=yes"
  else
    test "$rc" -ne 0 && test "$before" = "$after"
    echo "race_create_only_rejected_overwrite=yes"
  fi
done
