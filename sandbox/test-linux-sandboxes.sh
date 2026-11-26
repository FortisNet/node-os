#!/usr/bin/env sh
# Privileged sandbox tests, confined to disposable private Docker control groups.
#
#   test-linux-sandboxes.sh [NODE_BINARY]
#
# With NODE_BINARY (a Linux build of the node for this machine's architecture)
# the broker test also runs: the real node, unprivileged, asking a root broker
# to run a job. Without it that one test is skipped and reported as skipped.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
node=${1:-}
cd "$root"
results=$root/build/sandbox
mkdir -p "$results"
./tools/fetch-mbedtls.sh
image=fortis-sandbox-integration:local
docker build -f sandbox/tests/Dockerfile.sandbox --target reduced -t "$image" sandbox
docker build -f sandbox/tests/Dockerfile.sandbox --target full -t fortis-sandbox-full:local sandbox
build=build/sandbox-test
docker run --rm --mount "type=bind,source=$root,target=/work" "$image" sh -eu -c '
  make -j4 BUILD="$1" CC=clang-18 CXX=clang++-18 "CXXFLAGS=$(make -s print-default-flags) -stdlib=libc++" all unit-tests
  python3 sandbox/tests/sandbox_cli_test.py "$1/fortis-sandbox"
' sh "$build"
for profile in full reduced; do
  selected_image=$image
  if [ "$profile" = full ]; then selected_image=fortis-sandbox-full:local; fi
  docker run --rm --privileged --cgroupns=private --network=none \
    -e FORTIS_DISPOSABLE_SANDBOX_TEST=1 -e FORTIS_AUDIT_GVISOR=1 \
    --mount "type=bind,source=$root,target=/work,readonly" \
    "$selected_image" python3 sandbox/tests/sandbox_runtime_test.py "$build/fortis-sandbox" gvisor \
    > "$results/gvisor-$profile-results.json"
  cat "$results/gvisor-$profile-results.json"
done
docker run --rm --privileged --cgroupns=private --network=none \
  -e FORTIS_DISPOSABLE_SANDBOX_TEST=1 \
  --mount "type=bind,source=$root,target=/work,readonly" \
  "$image" python3 sandbox/tests/sandbox_runtime_test.py "$build/fortis-sandbox" process \
  > "$results/process-results.json"
cat "$results/process-results.json"

if [ -z "$node" ]; then
  echo "Broker test skipped: no node binary given." >&2
  exit 0
fi
node=$(CDPATH='' cd -- "$(dirname -- "$node")" && pwd)/$(basename -- "$node")
# The real node controls a root broker without privileges. No host sockets or network.
docker run --rm --privileged --cgroupns=private --network=none \
  -e FORTIS_DISPOSABLE_SANDBOX_TEST=1 \
  --mount "type=bind,source=$root,target=/work,readonly" \
  --mount "type=bind,source=$node,target=/node/fortis-node,readonly" \
  "$image" python3 sandbox/tests/sandbox_broker_test.py "$build/fortis-sandbox" /node/fortis-node \
  > "$results/broker-results.json"
cat "$results/broker-results.json"
