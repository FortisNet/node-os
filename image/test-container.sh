#!/usr/bin/env sh
# Try a container image of the node host on this computer, from first start
# to a node answering over HTTPS, without a public address and without
# asking a real certificate authority for anything.
#
#   test-container.sh IMAGE [--keep]
#
#   IMAGE    a loaded container image of this computer's own processor
#            architecture, for example fortis-node-os:COMMIT-aarch64
#   --keep   leave it running afterwards and print how to reach it
#
# A stand-in certificate authority (the one the orchestrator's tests use)
# runs beside the container and shares its network, so the authority's check
# of port 80 arrives the way a real one does. Everything else is the image
# as it ships: first boot, the certificate request, the install of the node
# release inside, the node in its own container under its system call filter.
#
# An image of another architecture cannot be tested this way: the program
# that starts the node does not work under processor emulation.
set -eu
image=${1:?usage: test-container.sh IMAGE [--keep]}
keep=${2:-}
image_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tests=$(CDPATH='' cd -- "$image_dir/../tests" && pwd)
tools_image=alpine@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35
name=fortis-host-test-$$
authority=$name-authority
node=$name-node
shared=$name-shared
rights='--cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add SYS_PTRACE --security-opt apparmor=unconfined --cgroupns private'

docker image inspect "$image" >/dev/null 2>&1 || { echo "No such image here: $image" >&2; exit 2; }
wanted=$(docker image inspect "$image" --format '{{.Architecture}}')
own=$(docker version --format '{{.Server.Arch}}')
[ "$wanted" = "$own" ] ||
  { echo "$image is built for $wanted and this computer's Docker runs $own: test it on a $wanted computer." >&2; exit 2; }

cleanup() {
  docker rm -f "$node" "$authority" >/dev/null 2>&1 || true
  docker volume rm "$shared" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
docker volume create "$shared" >/dev/null

# The stand-in authority. The node container joins this container's network,
# so 127.0.0.1 is the same place for both.
docker run -d --name "$authority" -p 127.0.0.1::443 -v "$shared:/shared" -v "$tests:/tests:ro" "$tools_image" sh -euc '
  apk add --no-cache python3 openssl >/dev/null
  exec python3 -c "
import sys, time
from pathlib import Path
sys.path.insert(0, \"/tests\")
from acme_fixture import Authority
from tls_ca import create_certificates
shared = Path(\"/shared\")
tls = shared / \"tls\"
tls.mkdir()
ca, certificate, key, _ = create_certificates(tls, \"IP:127.0.0.1\")
authority = Authority(shared / \"authority\", ca, tls / \"ca.key\", certificate, key, 80)
tls.chmod(0o755)
ca.chmod(0o644)
(shared / \"ca\").write_text(str(ca))
(shared / \"directory\").write_text(authority.url(\"/dir\"))
time.sleep(10 ** 7)
"' >/dev/null
attempts=0
until docker exec "$authority" test -s /shared/directory 2>/dev/null; do
  attempts=$((attempts + 1))
  [ "$attempts" -lt 60 ] || { echo 'The stand-in authority did not start:' >&2; docker logs "$authority" >&2; exit 1; }
  sleep 1
done
directory=$(docker exec "$authority" cat /shared/directory)
ca=$(docker exec "$authority" cat /shared/ca)
port=$(docker port "$authority" 443/tcp | sed -n 's/.*://p' | head -n 1)

# The rights the README tells people to give it; FORTIS_TEST_RIGHTS tries others.
# shellcheck disable=SC2086
docker run -d --name "$node" --network "container:$authority" ${FORTIS_TEST_RIGHTS:-$rights} --init --stop-timeout 240 \
  -v "$shared:/shared:ro" \
  -e FORTIS_HTTPS_IP=127.0.0.1 -e FORTIS_NATIVE_ACME_LOOPBACK=1 \
  -e "FORTIS_NATIVE_ACME_DIRECTORY=$directory" -e "FORTIS_NATIVE_TLS_CA=$ca" \
  -e FORTIS_NATIVE_REQUIRE_CLOCK=0 "$image" >/dev/null

trust=$(mktemp)
docker cp "$authority:$ca" "$trust" >/dev/null
report=
attempts=0
while [ "$attempts" -lt 40 ]; do
  attempts=$((attempts + 1))
  sleep 3
  # The certificate is checked against the stand-in authority, as a browser
  # checks a real one.
  report=$(curl --silent --max-time 3 --cacert "$trust" "https://127.0.0.1:$port/health.json" || true)
  case "$report" in *'"status":200'*'"state":"serving"'*) break ;; esac
  report=
done
unlink "$trust"
if [ -z "$report" ]; then
  echo 'FAILED: the node did not come up healthy over HTTPS. The container said:' >&2
  docker logs "$node" 2>&1 | tail -n 40 | uniq -c >&2
  # The orchestrator only knows that the container runtime refused. Ask the
  # runtime itself why, with the first bundle the orchestrator prepared.
  echo 'The container runtime, asked directly:' >&2
  docker exec "$node" sh -c '
    for bundle in /var/lib/fortis/state/run/*/; do
      [ -f "$bundle/config.json" ] || continue
      (cd "$bundle" && crun --root /tmp/crun-why run --no-new-keyring --bundle . why </dev/null 2>&1 | head -n 5)
      break
    done
    grep -E "^(CapEff|Seccomp):" /proc/self/status
    grep " /sys/fs/cgroup " /proc/mounts; cat /sys/fs/cgroup/cgroup.subtree_control' >&2 || true
  exit 1
fi
filtered=$(docker exec "$node" sh -c 'grep -l "^Seccomp:.2" /proc/[0-9]*/status 2>/dev/null | wc -l')
[ "$filtered" -ge 1 ] || { echo 'FAILED: no process runs under the system call filter.' >&2; exit 1; }
echo "PASSED after about $((attempts * 3)) s"
docker exec "$node" sed -n '1,3p' /etc/fortis-image
printf '%s\n' "$report" | sed -n 's/.*\("runsIn":"[a-z]*"\).*/\1/p'
printf '%s\n' "$report" | sed -n 's/.*"node":{"state":"\([a-z]*\)","version":"\([^"]*\)".*/node \1, version \2/p'
echo "node process under the system call filter: yes"
docker logs "$node" 2>&1 | grep -v 'Page server not started' | head -n 8
if [ "$keep" = --keep ]; then
  trap - EXIT HUP INT TERM
  echo "Left running. Page: https://127.0.0.1:$port/ (its certificate is from the stand-in authority, so a browser will warn)."
  echo "Remove with: docker rm -f $node $authority && docker volume rm $shared"
fi
