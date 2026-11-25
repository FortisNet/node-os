#!/usr/bin/env sh
# OpenRC owns this long-lived C++ supervisor; the web container has no updater.
set -eu
export FORTIS_NATIVE_WAIT_LOCK=1
manager=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/manage-native-node.sh
exec "$manager" "${1:?usage: run-native-service.sh CONFIG}" supervise
