#!/usr/bin/env sh
# Reviewed native C++ host controller. Configuration is data, never sourced.
set -eu
umask 077
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
controller=${FORTIS_NATIVE_CONTROLLER:-$script_dir/native-controller}
if [ ! -x "$controller" ]; then
  # In a source checkout: this repository's own build.
  controller=$(CDPATH='' cd -- "$script_dir/../.." && pwd)/build/native-controller
fi
[ -x "$controller" ] || { echo 'Build/install the native C++ controller first' >&2; exit 2; }
exec "$controller" "$@"
