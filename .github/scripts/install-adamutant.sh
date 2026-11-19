#!/usr/bin/env bash
# Build AdaMutant (https://github.com/gomurin0428/AdaMutant) at COMMIT and
# put its executable in PREFIX/bin, then add PREFIX/bin to the job's PATH.
# AdaMutant builds with Alire, which brings Libadalang and the compiler that
# Libadalang supports; the first build takes about 20 minutes, so a PREFIX
# restored from a cache that holds the build of COMMIT is used as it is.
# The executable links Libadalang statically and needs nothing else.
# Usage: install-adamutant.sh PREFIX COMMIT
set -euo pipefail

prefix=$1
commit=$2
if [ "$(cat "$prefix/.commit" 2> /dev/null || true)" != "$commit" ]; then
  work=$(mktemp -d)
  alr=$(bash "$(dirname "$0")/fetch-alr.sh" "$work")
  source="$work/adamutant"
  git init --quiet "$source"
  git -C "$source" fetch --quiet --depth 1 https://github.com/gomurin0428/AdaMutant "$commit"
  git -C "$source" checkout --quiet FETCH_HEAD
  (cd "$source" && "$alr" -n build)
  rm -rf "$prefix"
  mkdir -p "$prefix/bin"
  cp "$source/bin/adamutant" "$prefix/bin/"
  echo "$commit" > "$prefix/.commit"
fi
echo "$prefix/bin" >> "$GITHUB_PATH"
