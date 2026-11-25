#!/usr/bin/env sh
# Publish a signed node release as a GitHub release of this repository, and
# pin it for the images.
#
#   publish-node-release.sh NODE_RELEASE
#
#   NODE_RELEASE   a node release folder holding x86_64/ and aarch64/, each
#                  with fortis-node, manifest and manifest.sig, signed with
#                  the key whose public half is image/release-public.pem
#
# Run it on the computer where the release was signed, with the GitHub CLI
# logged in. It never reads the private key: signing is done beforehand.
#
# It creates the release "node-VERSION" with six files:
#
#   fortis-node-ARCH                the program
#   fortis-node-ARCH.manifest       its manifest
#   fortis-node-ARCH.manifest.sig   the signature over the manifest
#
# and writes image/node-release.conf, which pins exactly these two manifests.
# Commit that file: the next build puts this node release into the images.
# A published node release is never replaced; publish the next version.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
release=$(CDPATH='' cd -- "${1:?usage: publish-node-release.sh NODE_RELEASE}" && pwd)
key=$root/image/release-public.pem
repository=${FORTIS_NODE_OS_REPOSITORY:-FortisNet/node-os}
[ -f "$key" ] || { echo "Missing $key: commit the public half of the release key first." >&2; exit 2; }
command -v gh >/dev/null || { echo 'The GitHub CLI (gh) is required.' >&2; exit 2; }
field() { sed -n "s/^$1=//p" "$2"; }
digest() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi; }

version=$(field version "$release/x86_64/manifest")
case "$version" in ''|*[!a-zA-Z0-9._-]*|.|..) echo 'The manifest names no valid version.' >&2; exit 2 ;; esac
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
for architecture in x86_64 aarch64; do
  folder=$release/$architecture
  for file in fortis-node manifest manifest.sig; do
    [ -f "$folder/$file" ] || { echo "Missing $folder/$file" >&2; exit 2; }
  done
  described="$(field version "$folder/manifest") $(field architecture "$folder/manifest")"
  [ "$described" = "$version $architecture" ] || { echo "$folder is not release $version for $architecture." >&2; exit 1; }
  openssl dgst -sha256 -verify "$key" -signature "$folder/manifest.sig" "$folder/manifest" >/dev/null ||
    { echo "The $architecture manifest is not signed by the key in image/release-public.pem." >&2; exit 1; }
  [ "$(digest "$folder/fortis-node")" = "$(field sha256 "$folder/manifest")" ] ||
    { echo "The $architecture program is not the one its manifest names." >&2; exit 1; }
  cp "$folder/fortis-node" "$staging/fortis-node-$architecture"
  cp "$folder/manifest" "$staging/fortis-node-$architecture.manifest"
  cp "$folder/manifest.sig" "$staging/fortis-node-$architecture.manifest.sig"
done

tag=node-$version
if gh release view "$tag" --repo "$repository" >/dev/null 2>&1; then
  echo "$tag is already published. A node release is never replaced; publish the next version." >&2
  exit 1
fi
gh release create "$tag" --repo "$repository" --latest=false \
  --title "FortisNet node $version" \
  --notes "The FortisNet node, release $version, for x86-64 and ARM64. Each manifest is signed with the release key whose public half is \`image/release-public.pem\` in this repository. The images are built with it; you do not need to download it yourself." \
  "$staging"/*

{
  echo "# The node release the images are built with. Written by"
  echo "# tools/publish-node-release.sh; see docs/releasing.md."
  echo "source=https://github.com/$repository/releases/download/$tag"
  echo "version=$version"
  echo "manifest_sha256_x86_64=$(digest "$release/x86_64/manifest")"
  echo "manifest_sha256_aarch64=$(digest "$release/aarch64/manifest")"
} > "$root/image/node-release.conf"
echo "Published $tag and wrote image/node-release.conf. Commit it to build images with this release."
