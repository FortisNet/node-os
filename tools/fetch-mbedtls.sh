#!/usr/bin/env sh
# Fetch the pinned Mbed TLS source archive into .deps and verify it.
# This repository builds its own copy with its own configuration header, so it
# needs nothing from outside this folder except this one download.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=3.6.7
checksum=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
archive=$root/.deps/mbedtls-$version.tar.bz2
mkdir -p "$root/.deps"
if [ ! -f "$archive" ]; then
  curl -fsSL "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$version/mbedtls-$version.tar.bz2" \
    -o "$archive.download"
  mv "$archive.download" "$archive"
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
fi
if [ "$actual" != "$checksum" ]; then
  echo "Mbed TLS archive checksum mismatch: $actual" >&2
  exit 1
fi
