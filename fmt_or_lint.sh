#!/usr/bin/env bash

set -euo pipefail

ALL=''
FMT=''
while getopts 'af' flag; do
  case "${flag}" in
    a) ALL=1 ;;
    f) FMT=1 ;;
  esac
done
readonly ALL
readonly FMT

function list-files() {
  if [ $# -ne 1 ]; then
    echo "Usage: ${FUNCNAME} [ext]"
    return 1
  fi
  if [ $ALL ]; then
    # All non-deleted files.
    comm -23 <(git ls-files -c -o --exclude-standard "*.$1" | sort) <(git ls-files -d | sort)
  else
    # New or modified files relative to main branch, and untracked files.
    cat <(git diff --name-only --diff-filter=d main | grep "\.$1$") <(git ls-files -o --exclude-standard "*.$1") | sort
  fi
}

if [ $FMT ]; then
  if [ "$(command -v gofmt)" ]; then
    gofmt -s -w .
  fi
  if [ "$(command -v prettier)" ]; then
    prettier --write .
  fi
  if [ "$(command -v ruff)" ]; then
    ruff check --fix-only .
    ruff format .
  fi
else
  if [ "$(command -v go)" -a -f go.mod ]; then
    go vet ./...
  fi
  if [ "$(command -v prettier)" ]; then
    prettier --check .
  fi
  if [ "$(command -v jshint)" ]; then
    jshint .
  fi
  if [ "$(command -v ruff)" ]; then
    ruff check .
    ruff format --check .
  fi
  readonly PY_FILES=$(list-files py)
  if [ "$PY_FILES" != '' ]; then
    if [ "$(command -v pyright)" ]; then
      pyright $PY_FILES
    fi
  fi
fi
