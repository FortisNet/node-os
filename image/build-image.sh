#!/usr/bin/env sh
# Build the FortisNet node host images: a machine or container made from one
# configures itself, obtains a certificate for its address, installs the node
# release baked in here and shows its first page, with nobody logging in.
#
#   build-image.sh NODE_RELEASE RELEASE_PUBLIC_KEY ORCHESTRATOR_RELEASE
#
#   NODE_RELEASE          a node release folder, node/dist/native-releases/VERSION,
#                         holding x86_64/ and aarch64/, each signed (fortis-node,
#                         manifest, manifest.sig)
#   RELEASE_PUBLIC_KEY    the public half of the key that signed them; the
#                         images will trust releases signed by this key, and
#                         no other
#   ORCHESTRATOR_RELEASE  a release of this repository folder, dist/VERSION,
#                         holding x86_64/ and aarch64/
#
# Output, in dist/image/, always all three, named after the commit
# they were built from, as every image is:
#
#   fortis-node-os-x86_64-COMMIT.qcow2            a disk a cloud boots
#   fortis-node-os-x86_64-COMMIT.docker.tar.gz    the same files as a container image
#   fortis-node-os-aarch64-COMMIT.docker.tar.gz   the container image for ARM servers
#
# A container image is a disk's root filesystem without the kernel and
# bootloader, which a container cannot use. The ARM one is made the same way,
# from Alpine's ARM disk image. The orchestrator finds out at start whether
# it runs in a container or on a machine.
#
# The exact version of every package is pinned in packages.x86_64.lock and
# packages.aarch64.lock; a build that would install anything else fails.
# FORTIS_UPDATE_PACKAGE_LOCK=1 rewrites the two files instead, for review.
#
# Unlike the boot check image, these add packages, so the root filesystem is
# mounted while it is built: the build container runs privileged for that.
# Nothing from the image is executed.
set -eu

image_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -ne 3 ]; then
  sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
node_release=$(CDPATH='' cd -- "$1" && pwd)
public_key=$(CDPATH='' cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")
orchestrator=$(CDPATH='' cd -- "$3" && pwd)
field() { sed -n "s/^$1=//p" "$2"; }
[ -f "$public_key" ] || { echo "Missing $public_key" >&2; exit 2; }
for architecture in x86_64 aarch64; do
  for file in "$node_release/$architecture/fortis-node" "$node_release/$architecture/manifest" \
    "$node_release/$architecture/manifest.sig" "$orchestrator/$architecture/native-controller" \
    "$orchestrator/$architecture/controller.manifest"; do
    [ -f "$file" ] || { echo "Missing $file" >&2; exit 2; }
  done
  # The images trust exactly this key: refuse to bake in a release it did not sign.
  openssl dgst -sha256 -verify "$public_key" -signature "$node_release/$architecture/manifest.sig" \
    "$node_release/$architecture/manifest" >/dev/null ||
    { echo "The $architecture node release is not signed by the given key." >&2; exit 1; }
  # Each release must be what its folder says: a host refuses the other kind.
  for manifest in "$node_release/$architecture/manifest" "$orchestrator/$architecture/controller.manifest"; do
    [ "$(field architecture "$manifest")" = "$architecture" ] ||
      { echo "$manifest is not an $architecture release" >&2; exit 1; }
  done
done
[ "$(field version "$node_release/x86_64/manifest")" = "$(field version "$node_release/aarch64/manifest")" ] ||
  { echo 'The two node releases are different versions.' >&2; exit 1; }

output_dir=${FORTIS_IMAGE_DIR:-$image_dir/../dist/image}
base_url=https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud
base_sha512_x86_64=82908bad6166949b41be00264c1990952c0df0e746a71d6051e9f8a6dadae56cac505f54fcf61b38db9c32d32face832c7cc9879e44bb935ff804fdc5741d93a
base_sha512_aarch64=0476de642495fd3a328c79284bfd8389410a12975562862fe2d21931adb5a71b0622b117208d2799fafafdfc442a5a5765f09d970e373b19219e39cd1c8ae678
tools_image=alpine@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35

# Named after its commit and carrying it inside, like every image (README.md).
commit=$(git -C "$image_dir" rev-parse HEAD 2>/dev/null || echo unknown)
case "$commit" in unknown) short=unknown ;; *) short=$(printf '%s' "$commit" | cut -c1-12) ;; esac
modified=no
if [ "$commit" = unknown ] || [ -n "$(git -C "$image_dir" status --porcelain -- "$image_dir/.." 2>/dev/null)" ]; then
  modified=yes
  short=$short-modified
fi
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
digest() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi; }

command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Docker daemon is unavailable.' >&2; exit 1; }
mkdir -p "$output_dir"
output_dir=$(CDPATH='' cd -- "$output_dir" && pwd)

# build_one ARCHITECTURE DISK: one root filesystem, saved as a container
# image and, when DISK is yes, as a disk image too.
build_one() {
architecture=$1
base_name=alpine-3.24.3-$architecture-tiny-r0.qcow2
case "$architecture" in
  x86_64) expected_sha512=$base_sha512_x86_64 platform=linux/amd64 ;;
  aarch64) expected_sha512=$base_sha512_aarch64 platform=linux/arm64 ;;
esac
output_name=fortis-node-os-$architecture-$short.qcow2
container_name=fortis-node-os-$architecture-$short.docker.tar.gz
container_tag=fortis-node-os:$short-$architecture
base=$output_dir/$base_name
if [ ! -s "$base" ]; then
  curl --fail --location --retry 3 --output "$base.download" "$base_url/$base_name"
  mv "$base.download" "$base"
fi
if command -v sha512sum >/dev/null 2>&1; then
  actual_sha512=$(sha512sum "$base" | cut -d ' ' -f 1)
else
  actual_sha512=$(shasum -a 512 "$base" | cut -d ' ' -f 1)
fi
[ "$actual_sha512" = "$expected_sha512" ] || { echo "Pinned Alpine $architecture tiny image SHA-512 mismatch." >&2; exit 1; }

docker run --rm --privileged \
  -v "$output_dir:/out" \
  -v "$image_dir:/image:ro" \
  -v "$node_release/$architecture:/node-release:ro" \
  -v "$public_key:/release-public.pem:ro" \
  -v "$orchestrator/$architecture:/orchestrator:ro" \
  -e "BASE_NAME=$base_name" -e "OUTPUT_NAME=$output_name" -e "ARCHITECTURE=$architecture" -e "DISK=$2" \
  -e "IMAGE_COMMIT=$commit" -e "IMAGE_MODIFIED=$modified" -e "IMAGE_BUILT=$built" \
  -e "UPDATE_LOCK=${FORTIS_UPDATE_PACKAGE_LOCK:-0}" \
  -e "ORCHESTRATOR_VERSION=$(field version "$orchestrator/$architecture/controller.manifest")" \
  -e "ORCHESTRATOR_SHA256=$(digest "$orchestrator/$architecture/native-controller")" \
  -e "NODE_VERSION=$(field version "$node_release/$architecture/manifest")" \
  -e "NODE_SHA256=$(field sha256 "$node_release/$architecture/manifest")" \
  -e "KEY_SHA256=$(digest "$public_key")" \
  "$tools_image" sh -euc '
    apk add --no-cache qemu-img e2fsprogs-extra sfdisk python3 zerofree >/dev/null
    cd /tmp
    qemu-img convert -O raw "/out/$BASE_NAME" disk.raw
    geometry=$(sfdisk --dump disk.raw | awk -F"[=, ]+" "/type=0FC63DAF-8483-4772-8E79-3D69D8477DE4/ {print \$4, \$6}")
    start=${geometry% *}
    sectors=${geometry#* }
    case "$start$sectors" in ""|*[!0-9]*) echo "Root partition not found" >&2; exit 1;; esac
    dd if=disk.raw of=root.img bs=512 skip="$start" count="$sectors" status=none
    [ "$(dumpe2fs -h root.img 2>/dev/null | sed -n "s/^Filesystem volume name: *//p")" = / ] ||
      { echo "Unexpected root filesystem label" >&2; exit 1; }
    mkdir /mnt/root
    mount -o loop root.img /mnt/root
    trap "umount /mnt/root 2>/dev/null || true" EXIT

    # Packages. The image is told what to keep by its own package manager,
    # working on the mounted files; no script from any package is run.
    root="apk --root /mnt/root --no-scripts --no-cache"
    # Security fixes Alpine has published since the base image was made.
    # The kernel and the bootloader stay as the base has them: replacing
    # them needs their install scripts, and nothing from the image is run.
    held=$(sed -n "s/^P://p" /mnt/root/lib/apk/db/installed | grep -E "^(linux-|limine-|mkinitfs$)" | tr "\n" " ")
    $root upgrade --ignore $held >/dev/null
    $root add crun nftables openssh-server >/dev/null
    $root del $(sed -n "s/^\([a-z0-9+._-]*\).*/\1/p" /image/packages.remove | grep -v "^+" | grep -v "^$") >/dev/null
    [ "$(cat /mnt/root/etc/apk/arch)" = "$ARCHITECTURE" ] || { echo "Base image is not $ARCHITECTURE" >&2; exit 1; }
    # Reasons: the base, what the host adds, and what differs on this
    # architecture ("-name" there takes a package of the base list out).
    cat /image/packages.why /image/packages.host.why > why.all
    if [ -f "/image/packages.$ARCHITECTURE.why" ]; then
      sed -n "s/^-//p" "/image/packages.$ARCHITECTURE.why" > absent
      awk -F"\t" "NR==FNR {absent[\$1]=1; next} !(\$1 in absent)" absent why.all > why
      grep -v "^-" "/image/packages.$ARCHITECTURE.why" >> why
    else
      cp why.all why
    fi
    : > none
    python3 /image/trim_packages.py /mnt/root/lib/apk/db/installed /mnt/root/etc/apk/world none why plan >/dev/null
    cp plan/packages.tsv "/out/$OUTPUT_NAME.packages.tsv"
    # Every package and its exact version must be the reviewed list, so one
    # commit always builds the same system (packages.ARCHITECTURE.lock).
    awk -F: "/^P:/ {name=\$2} /^V:/ {print name \"\t\" \$2}" /mnt/root/lib/apk/db/installed | sort > "/out/$OUTPUT_NAME.packages.lock"
    if [ "$UPDATE_LOCK" != 1 ] && ! cmp -s "/out/$OUTPUT_NAME.packages.lock" "/image/packages.$ARCHITECTURE.lock"; then
      echo "The packages are not the ones of image/packages.$ARCHITECTURE.lock (- locked, + found):" >&2
      diff -U 0 "/image/packages.$ARCHITECTURE.lock" "/out/$OUTPUT_NAME.packages.lock" | grep "^[-+][^-+]" >&2 || true
      echo "Alpine has probably published an update. Review it, then rebuild with FORTIS_UPDATE_PACKAGE_LOCK=1 and commit the lock files." >&2
      exit 1
    fi
    for path in /usr/bin/ssh /usr/bin/sgdisk /usr/share/zoneinfo/UTC; do
      [ ! -e "/mnt/root$path" ] || { echo "$path is still in the image" >&2; exit 1; }
    done

    # The orchestrator, the one key it trusts, and one node release.
    install -d -m 755 /mnt/root/usr/libexec/fortis /mnt/root/usr/share/fortis /mnt/root/usr/share/fortis/node-release
    install -m 755 /orchestrator/native-controller /image/files/manage-native-node.sh \
      /image/files/run-native-service.sh /mnt/root/usr/libexec/fortis/
    install -m 755 /image/files/container-start.sh /mnt/root/usr/libexec/fortis/container-start.sh
    install -m 755 /image/files/fortis /mnt/root/usr/sbin/fortis
    install -m 644 /release-public.pem /mnt/root/usr/share/fortis/release-public.pem
    install -m 555 /node-release/fortis-node /mnt/root/usr/share/fortis/node-release/fortis-node
    install -m 444 /node-release/manifest /node-release/manifest.sig /mnt/root/usr/share/fortis/node-release/
    # Services: the firewall early, the orchestrator once the host is up.
    install -m 755 /image/files/fortis-native.openrc /mnt/root/etc/init.d/fortis-native
    install -m 644 /image/files/nftables.nft /mnt/root/etc/nftables.nft
    install -m 600 /image/files/sshd-fortis.conf /mnt/root/etc/ssh/sshd_config.d/10-fortis.conf
    ln -sf /etc/init.d/nftables /mnt/root/etc/runlevels/boot/nftables
    ln -sf /etc/init.d/fortis-native /mnt/root/etc/runlevels/default/fortis-native
    printf "image=fortis-node-os\narchitecture=%s\ncommit=%s\nmodified=%s\nbuilt=%s\nbase=%s\norchestrator=%s\norchestrator_sha256=%s\nnode=%s\nnode_sha256=%s\nrelease_key_sha256=%s\n" \
      "$ARCHITECTURE" "$IMAGE_COMMIT" "$IMAGE_MODIFIED" "$IMAGE_BUILT" "${BASE_NAME%.qcow2}" "$ORCHESTRATOR_VERSION" \
      "$ORCHESTRATOR_SHA256" "$NODE_VERSION" "$NODE_SHA256" "$KEY_SHA256" > /mnt/root/etc/fortis-image
    chmod 644 /mnt/root/etc/fortis-image
    for path in /usr/bin/crun /usr/sbin/nft /usr/sbin/sshd /usr/libexec/fortis/native-controller /usr/sbin/fortis \
      /usr/share/fortis/node-release/fortis-node /etc/runlevels/default/fortis-native /etc/runlevels/boot/nftables; do
      [ -e "/mnt/root$path" ] || [ -L "/mnt/root$path" ] || { echo "Missing $path in image" >&2; exit 1; }
    done
    df -m /mnt/root | tail -n 1
    # The second packaging: the same files, for a container runtime.
    tar -C /mnt/root --numeric-owner --exclude=./boot --exclude=./lib/modules -cf "/out/$OUTPUT_NAME.rootfs.tar" .
    umount /mnt/root
    trap - EXIT
    [ "$DISK" = yes ] || exit 0
    e2fsck -fy root.img >/dev/null
    zerofree root.img
    dd if=root.img of=disk.raw bs=512 seek="$start" conv=notrunc status=none
    qemu-img convert -O qcow2 -c disk.raw "/out/$OUTPUT_NAME.tmp"
    qemu-img check "/out/$OUTPUT_NAME.tmp" >/dev/null
    qemu-img info "/out/$OUTPUT_NAME.tmp" | sed -n "1,4p"
  '
if [ "${FORTIS_UPDATE_PACKAGE_LOCK:-0}" = 1 ]; then
  cp "$output_dir/$output_name.packages.lock" "$image_dir/packages.$architecture.lock"
  echo "Updated $image_dir/packages.$architecture.lock"
fi
unlink "$output_dir/$output_name.packages.lock"
if [ "$2" = yes ]; then
  mv "$output_dir/$output_name.tmp" "$output_dir/$output_name"
  (cd "$output_dir" && printf '%s  %s\n' "$(digest "$output_name")" "$output_name" > "$output_name.sha256")
  echo "Disk image: $output_dir/$output_name"
fi
rootfs=$output_dir/$output_name.rootfs.tar
docker import --platform "$platform" \
  --change 'ENTRYPOINT ["/usr/libexec/fortis/container-start.sh"]' \
  --change 'VOLUME /var/lib/fortis' --change 'EXPOSE 80 443' --change 'STOPSIGNAL SIGTERM' \
  --change "LABEL io.fortisnet.image.commit=$commit" \
  "$rootfs" "$container_tag" >/dev/null
unlink "$rootfs"
docker save "$container_tag" | gzip > "$output_dir/$container_name.tmp"
mv "$output_dir/$container_name.tmp" "$output_dir/$container_name"
(cd "$output_dir" && printf '%s  %s\n' "$(digest "$container_name")" "$container_name" > "$container_name.sha256")
echo "Container image: $output_dir/$container_name (also loaded here as $container_tag)"
}

build_one x86_64 yes
build_one aarch64 no
