#!/usr/bin/env bash
# Install the given Alire crates (for example gnat_native=14.2.1) into PREFIX
# with alr 2.1.1 and add PREFIX/bin to the job's PATH.
# Usage: install-ada.sh PREFIX CRATE=VERSION...
# The alr archive is checked against the SHA-256 published with the release.
# A cached PREFIX (marked by .installed) is reused without downloading.
set -euo pipefail

prefix=$1
shift
alr_version=2.1.1
case "${RUNNER_OS}/${RUNNER_ARCH}" in
  Linux/X64)
    asset=x86_64-linux
    digest=09c66bcd8c35dd4b97b72c3d9b76e44caa6964a2db35aba069f396f00f1f64c7 ;;
  Windows/X64)
    asset=x86_64-windows
    digest=863013b1f94da6f3b7d0d5a74022ac3370424eeea9a470ebdb33d188d61b9125 ;;
  macOS/ARM64)
    asset=aarch64-macos
    digest=2c4867bfff3b95ecd9d846df460a52983d2b0072808b341f8fa5d82494fb309e ;;
  *)
    echo "unsupported runner: ${RUNNER_OS}/${RUNNER_ARCH}" >&2
    exit 1 ;;
esac

if [ ! -f "$prefix/.installed" ]; then
  work=$(mktemp -d)
  archive="$work/alr.zip"
  curl -fsSL -o "$archive" \
    "https://github.com/alire-project/alire/releases/download/v${alr_version}/alr-${alr_version}-bin-${asset}.zip"
  if command -v sha256sum > /dev/null; then
    actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
  else
    actual=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
  fi
  if [ "$actual" != "$digest" ]; then
    echo "alr archive digest mismatch: $actual" >&2
    exit 1
  fi
  unzip -q "$archive" -d "$work/alr"
  alr="$work/alr/bin/alr"
  chmod +x "$alr" 2> /dev/null || true
  "$alr" -n settings --global --set msys2.do_not_install true
  "$alr" -n install --prefix="$prefix" "$@"
  touch "$prefix/.installed"
fi

bin="$prefix/bin"
if command -v cygpath > /dev/null; then
  bin=$(cygpath -w "$bin")
fi
echo "$bin" >> "$GITHUB_PATH"
