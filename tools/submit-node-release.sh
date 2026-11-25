#!/usr/bin/env sh
# Hand an unsigned node release to GitHub to be signed and published.
#
#   submit-node-release.sh NODE_RELEASE
#
#   NODE_RELEASE   a node release folder holding x86_64/ and aarch64/, each
#                  with fortis-node and manifest, as the node's release build
#                  writes them. Any signature in it is ignored.
#
# It uploads the two programs and their manifests as the draft release
# "node-VERSION" of this repository, which only maintainers can see, and
# starts the "Sign node release" workflow. That workflow checks the draft,
# waits for a reviewer to approve the signing, signs the manifests with the
# release key, publishes the release and proposes it for the images.
#
# Needs the GitHub CLI, logged in with write access. No key is involved here.
set -eu
release=$(CDPATH='' cd -- "${1:?usage: submit-node-release.sh NODE_RELEASE}" && pwd)
repository=${FORTIS_NODE_OS_REPOSITORY:-FortisNet/node-os}
command -v gh >/dev/null || { echo 'The GitHub CLI (gh) is required.' >&2; exit 2; }
field() { sed -n "s/^$1=//p" "$2"; }
digest() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi; }

version=$(field version "$release/x86_64/manifest")
case "$version" in ''|*[!a-zA-Z0-9._-]*|.|..) echo 'The manifest names no valid version.' >&2; exit 2 ;; esac
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
for architecture in x86_64 aarch64; do
  folder=$release/$architecture
  for file in fortis-node manifest; do
    [ -f "$folder/$file" ] || { echo "Missing $folder/$file" >&2; exit 2; }
  done
  described="$(field version "$folder/manifest") $(field architecture "$folder/manifest")"
  [ "$described" = "$version $architecture" ] || { echo "$folder is not release $version for $architecture." >&2; exit 1; }
  [ "$(digest "$folder/fortis-node")" = "$(field sha256 "$folder/manifest")" ] ||
    { echo "The $architecture program is not the one its manifest names." >&2; exit 1; }
  cp "$folder/fortis-node" "$staging/fortis-node-$architecture"
  cp "$folder/manifest" "$staging/fortis-node-$architecture.manifest"
done

tag=node-$version
if gh release view "$tag" --repo "$repository" >/dev/null 2>&1; then
  echo "$tag already exists. A node release is never replaced; build the next version." >&2
  exit 1
fi
gh release create "$tag" --repo "$repository" --draft --latest=false \
  --title "FortisNet node $version" \
  --notes "The FortisNet node, release $version, for x86-64 and ARM64. Each manifest is signed with the release key whose public half is \`image/release-public.pem\` in this repository. The images are built with it; you do not need to download it yourself." \
  "$staging"/*
gh workflow run sign-node-release.yml --repo "$repository" --ref main -f "version=$version"
echo "Submitted $tag. Approve the signing here: https://github.com/$repository/actions/workflows/sign-node-release.yml"
