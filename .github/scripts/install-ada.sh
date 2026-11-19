#!/usr/bin/env bash
# Install the given Alire crates (for example gnat_native=16.1.0) into PREFIX
# with alr 2.1.1 and add PREFIX/bin to the job's PATH.
# Usage: install-ada.sh PREFIX CRATE=VERSION...
# fetch-alr.sh checks the alr archive against its published SHA-256.
# A cached PREFIX (marked by .installed) is reused without downloading.
set -euo pipefail

prefix=$1
shift
if [ ! -f "$prefix/.installed" ]; then
  alr=$(bash "$(dirname "$0")/fetch-alr.sh" "$(mktemp -d)")
  "$alr" -n settings --global --set msys2.do_not_install true
  "$alr" -n install --prefix="$prefix" "$@"
  touch "$prefix/.installed"
fi

bin="$prefix/bin"
if command -v cygpath > /dev/null; then
  bin=$(cygpath -w "$bin")
fi
echo "$bin" >> "$GITHUB_PATH"
