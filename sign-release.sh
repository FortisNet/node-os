#!/usr/bin/env sh
# Sign a release of this repository. Run only on a trusted signing machine; the
# private key never goes to a host.
set -eu
release=${1:?usage: sign-release.sh RELEASE_DIRECTORY PRIVATE_KEY}
key=${2:?missing private signing key}
[ -f "$key" ] || exit 2
umask 077
for manifest in controller.manifest sandbox.manifest; do
  [ -f "$release/$manifest" ] || { echo "Missing $manifest" >&2; exit 2; }
  openssl dgst -sha256 -sign "$key" -out "$release/.$manifest.sig-$$" "$release/$manifest"
  mv "$release/.$manifest.sig-$$" "$release/$manifest.sig"
done
