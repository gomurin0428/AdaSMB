#!/usr/bin/env bash
# Download alr 2.1.1 for this runner into DIR, check it against the SHA-256
# published with the release, and print the path of the alr executable.
# Usage: fetch-alr.sh DIR
set -euo pipefail

dir=$1
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

mkdir -p "$dir"
archive="$dir/alr.zip"
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
unzip -q -o "$archive" -d "$dir/alr"
chmod +x "$dir/alr/bin/alr" 2> /dev/null || true
echo "$dir/alr/bin/alr"
