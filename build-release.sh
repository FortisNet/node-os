#!/usr/bin/env sh
# Build an unsigned release of the orchestrator and the sandbox manager:
# static, hardened programs for Linux, for one processor architecture. Sign
# it on a trusted machine with sign-release.sh.
#
#   build-release.sh VERSION [x86_64|aarch64]   output: dist/VERSION/ARCHITECTURE/
#
# The architecture defaults to x86_64. `make release` builds both.
#
# It builds only from files that passed `make verify` unchanged, in
# an isolated volume, recording every compiler invocation so the hardening
# profile can be checked against what was actually run.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
version=${1:?usage: build-release.sh VERSION [x86_64|aarch64]}
architecture=${2:-x86_64}
case "$architecture" in
  x86_64) platform=linux/amd64 ;;
  aarch64) platform=linux/arm64 ;;
  *) echo 'Architecture must be x86_64 or aarch64' >&2; exit 2 ;;
esac
case "$version" in ''|*[!a-zA-Z0-9._-]*|.|..) echo 'Invalid release version' >&2; exit 2;; esac
[ "${#version}" -le 64 ] || exit 2
cd "$root"
python3 verify.py --check-inputs
./tools/fetch-mbedtls.sh
output=$root/dist/$version/$architecture
[ ! -e "$output" ] || { echo 'Release already exists' >&2; exit 1; }
image=fortis-node-os-release:local-$architecture
docker build --platform "$platform" -t "$image" - < tools/Dockerfile.release
volume=fortis-node-os-build-$(date -u +%Y%m%dT%H%M%SZ)-$$
docker volume create "$volume" >/dev/null
trap 'docker volume rm "$volume" >/dev/null' EXIT HUP INT TERM
mkdir -p "$output"
docker run --rm --platform "$platform" --network none -v "$volume:/work" \
  --mount "type=bind,source=$root,target=/input,readonly" \
  --mount "type=bind,source=$output,target=/output" \
  -e FORTIS_BUILD_JOBS="${FORTIS_BUILD_JOBS:-4}" -e "ARCHITECTURE=$architecture" -e "VERSION=$version" "$image" sh -eu -c '
    [ "$(uname -m)" = "$ARCHITECTURE" ]
    [ "$(gcc -dumpfullversion)" = 15.2.0 ]
    apk info -v | grep -q "^musl-1.2.6-"
    for entry in Makefile orchestrator sandbox lib tests tools image assets verify.py; do cp -a "/input/$entry" /work/; done
    mkdir -p .deps && cp /input/.deps/mbedtls-3.6.7.tar.bz2 .deps/
    hardening_c=$(make -s -f tools/hardening.mk c)
    hardening_cxx=$(make -s -f tools/hardening.mk cxx)
    hardening_link=$(make -s -f tools/hardening.mk link)
    make -j"$FORTIS_BUILD_JOBS" BUILD=build-release ORCHESTRATOR_VERSION="$VERSION" \
      CXX="python3 /work/tools/compiler_audit.py /output/compiler-commands.jsonl g++" \
      CC="python3 /work/tools/compiler_audit.py /output/compiler-commands.jsonl gcc" \
      DEPENDENCY_CFLAGS="$hardening_c" \
      CXXFLAGS="-Os -std=c++23 -fno-rtti -ffp-contract=off -flto -ffunction-sections -fdata-sections $hardening_cxx $hardening_link -Wl,--gc-sections -Wl,-z,stack-size=2097152 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wundef -Wcast-align -Woverloaded-virtual -Wnon-virtual-dtor" \
      all unit-tests
    python3 sandbox/tests/sandbox_cli_test.py build-release/fortis-sandbox
    for program in native-controller fortis-sandbox; do
      cp "build-release/$program" "/output/$program.debug"
      strip --strip-all -o "/output/$program" "build-release/$program"
      # Fail closed if a loader or shared library reached the release.
      ! readelf -l "/output/$program" | grep -q INTERP
      ! readelf -d "/output/$program" | grep -q NEEDED
      readelf -h -l -d "/output/$program" > "/output/$program.elf.txt"
      python3 tools/hardening.py /output /output/compiler-commands.jsonl --binary "$program" --architecture "$ARCHITECTURE"
      chmod 555 "/output/$program"
    done
    mkdir -p /output/licenses
    cp /input/LICENSE /input/NOTICE /output/licenses/
    cp /input/third_party/native-runtime/* /output/licenses/
    cp build-release/mbedtls-3.6.7/LICENSE /output/licenses/mbedtls.LICENSE
  '
# Refuse a release whose inputs changed while it was being built.
python3 verify.py --check-inputs
python3 - "$output" "$version" "$architecture" <<'PYMANIFEST'
import hashlib, json, pathlib, sys
release, version, architecture = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
report = json.loads(pathlib.Path('build-verify/report.json').read_text())
inputs = hashlib.sha256(json.dumps(report['input_sha256'], sort_keys=True).encode()).hexdigest()
for program, name in (('native-controller', 'controller.manifest'), ('fortis-sandbox', 'sandbox.manifest')):
    binary = (release / program).read_bytes()
    (release / name).write_text(f'format=1\nartifact={program}\nversion={version}\narchitecture={architecture}\n'
                                f'sha256={hashlib.sha256(binary).hexdigest()}\nbytes={len(binary)}\n'
                                f'verified_inputs_sha256={inputs}\n')
PYMANIFEST
printf 'Unsigned release: %s\n' "$output"
