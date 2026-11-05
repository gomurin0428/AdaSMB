#!/usr/bin/env bash
# Build AdaMutant (https://github.com/gomurin0428/AdaMutant) at COMMIT into
# PREFIX and add PREFIX/bin to the job's PATH. Needs gprbuild on PATH.
# Usage: install-adamutant.sh PREFIX COMMIT
set -euo pipefail

prefix=$1
commit=$2
git init --quiet "$prefix"
git -C "$prefix" fetch --quiet --depth 1 https://github.com/gomurin0428/AdaMutant "$commit"
git -C "$prefix" checkout --quiet FETCH_HEAD
gprbuild -p -q -P "$prefix/adamutant.gpr"
echo "$prefix/bin" >> "$GITHUB_PATH"
