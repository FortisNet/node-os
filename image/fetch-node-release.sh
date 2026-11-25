#!/usr/bin/env sh
# Fetch the node release the images are built with, and check it.
#
#   fetch-node-release.sh [OUTPUT_FOLDER]      default: dist/node-release
#
# Which release is decided by two files in this folder, both kept in the
# repository so that a change to either is reviewed like any other change:
#
#   node-release.conf     where the release is and exactly which one
#   release-public.pem    the public half of the key node releases are signed
#                         with; the images trust this key and no other
#
# node-release.conf holds KEY=VALUE lines:
#
#   source=https://...              where its six files are: fortis-node-ARCH,
#                                   fortis-node-ARCH.manifest and
#                                   fortis-node-ARCH.manifest.sig for each
#                                   architecture (a GitHub release of this
#                                   repository, written by
#                                   tools/publish-node-release.sh)
#   version=1.2.3                   the node release to put in the images
#   manifest_sha256_x86_64=...      the SHA-256 of each architecture's manifest;
#   manifest_sha256_aarch64=...     a manifest names the program's own hash
#
# Three things must hold for each architecture, or nothing is kept: the
# manifest is the pinned one, it is signed by the key, and the program is the
# one the manifest names. The place it is downloaded from is not trusted.
set -eu
image_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
conf=$image_dir/node-release.conf
key=$image_dir/release-public.pem
output=${1:-$image_dir/../dist/node-release}
[ -f "$conf" ] || { echo "Missing $conf: no node release is pinned yet." >&2; exit 2; }
[ -f "$key" ] || { echo "Missing $key: the release public key." >&2; exit 2; }

setting() { sed -n "s/^$1=//p" "$conf" | head -n 1; }
digest() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi; }
store=$(setting source)
version=$(setting version)
case "$store" in https://*) ;; file:///*) [ "${FORTIS_ALLOW_LOCAL_STORE:-}" = 1 ] || { echo 'The source must be an https address.' >&2; exit 2; } ;; *) echo 'The source must be an https address.' >&2; exit 2 ;; esac
case "$version" in ''|*[!a-zA-Z0-9._-]*|.|..) echo 'node-release.conf names no valid version.' >&2; exit 2 ;; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
for architecture in x86_64 aarch64; do
  pinned=$(setting "manifest_sha256_$architecture")
  case "$pinned" in ''|*[!0-9a-f]*) echo "node-release.conf pins no manifest for $architecture." >&2; exit 2 ;; esac
  mkdir "$work/$architecture"
  for file in fortis-node manifest manifest.sig; do
    case "$file" in fortis-node) name=fortis-node-$architecture ;; *) name=fortis-node-$architecture.$file ;; esac
    curl --fail --silent --show-error --location --retry 3 --proto '=https,file' \
      --output "$work/$architecture/$file" "$store/$name"
  done
  manifest=$work/$architecture/manifest
  [ "$(digest "$manifest")" = "$pinned" ] ||
    { echo "The downloaded $architecture manifest is not the pinned one." >&2; exit 1; }
  openssl dgst -sha256 -verify "$key" -signature "$manifest.sig" "$manifest" >/dev/null ||
    { echo "The $architecture manifest is not signed by the release key." >&2; exit 1; }
  described="$(sed -n 's/^version=//p' "$manifest") $(sed -n 's/^architecture=//p' "$manifest")"
  [ "$described" = "$version $architecture" ] ||
    { echo "The $architecture manifest describes another release." >&2; exit 1; }
  [ "$(digest "$work/$architecture/fortis-node")" = "$(sed -n 's/^sha256=//p' "$manifest")" ] ||
    { echo "The $architecture program is not the one its manifest names." >&2; exit 1; }
done
mkdir -p "$output"
for architecture in x86_64 aarch64; do
  mkdir -p "$output/$architecture"
  for file in manifest manifest.sig fortis-node; do
    cp "$work/$architecture/$file" "$output/$architecture/$file"
  done
done
echo "Node release $version, verified: $output"
