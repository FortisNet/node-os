#!/usr/bin/env sh
# Build the boot check image: the base of the node host image with nothing of
# FortisNet's running in it, used to prove the base on a new cloud.
#
# It is Alpine's pinned "tiny" cloud image (tiny-cloud, no cloud-init, no
# Python), with the packages the host does not need taken out (README.md),
# SSH limited to the operator's key, plus one first-boot report service. No FortisNet program runs in
# it; the report also runs a throwaway container under crun with the node's
# isolation settings. Boot it once on a real Droplet and read the report to decide whether the
# first host image can drop cloud-init.
#
# The root filesystem is edited offline with debugfs: no loop device, no mount,
# no privileged container and no guest code execution are needed.
set -eu

image_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Output goes beside the other build output.
output_dir=${FORTIS_IMAGE_DIR:-$image_dir/../dist/image}
base_name=alpine-3.24.3-x86_64-tiny-r0.qcow2
base_url=https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/$base_name
expected_sha512=82908bad6166949b41be00264c1990952c0df0e746a71d6051e9f8a6dadae56cac505f54fcf61b38db9c32d32face832c7cc9879e44bb935ff804fdc5741d93a
tools_image=alpine@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35
# Every image carries the commit it was built from, inside it
# (/etc/fortis-image) and in its file name, so an image, a Droplet made from
# it and a report from that Droplet can always be traced to exact sources.
# Uncommitted changes in the repository are recorded and shown in the name: an
# image whose name ends in "-modified" cannot be rebuilt from its commit.
commit=$(git -C "$image_dir" rev-parse HEAD 2>/dev/null || echo unknown)
case "$commit" in unknown) short=unknown ;; *) short=$(printf '%s' "$commit" | cut -c1-12) ;; esac
modified=no
if [ "$commit" = unknown ] || [ -n "$(git -C "$image_dir" status --porcelain -- "$image_dir/.." 2>/dev/null)" ]; then
  modified=yes
  short=$short-modified
fi
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
output_name=fortis-bootcheck-x86_64-$short.qcow2

if [ "${1:-}" = --help ]; then
  echo 'Build the bare tiny-cloud boot test image for a DigitalOcean Droplet.'
  echo 'Usage: ./image/build-bootcheck-image.sh'
  echo 'Output: dist/image/fortis-bootcheck-x86_64-COMMIT.qcow2, COMMIT being the'
  echo '        first 12 characters of the commit it was built from'
  exit 0
fi
if [ "$#" -ne 0 ]; then
  echo 'Unexpected arguments; use --help.' >&2
  exit 2
fi
command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Docker daemon is unavailable.' >&2; exit 1; }

mkdir -p "$output_dir"
output_dir=$(CDPATH='' cd -- "$output_dir" && pwd)
base=$output_dir/$base_name
if [ ! -s "$base" ]; then
  curl --fail --location --retry 3 --output "$base.download" "$base_url"
  mv "$base.download" "$base"
fi
if command -v sha512sum >/dev/null 2>&1; then
  actual_sha512=$(sha512sum "$base" | cut -d ' ' -f 1)
else
  actual_sha512=$(shasum -a 512 "$base" | cut -d ' ' -f 1)
fi
if [ "$actual_sha512" != "$expected_sha512" ]; then
  echo 'Pinned Alpine tiny image SHA-512 mismatch; refusing to customize it.' >&2
  exit 1
fi

docker run --rm \
  -v "$output_dir:/out" \
  -v "$image_dir/bootcheck:/bootcheck:ro" \
  -v "$image_dir:/image:ro" \
  -e "BASE_NAME=$base_name" -e "OUTPUT_NAME=$output_name" \
  -e "IMAGE_COMMIT=$commit" -e "IMAGE_MODIFIED=$modified" -e "IMAGE_BUILT=$built" \
  "$tools_image" sh -euc '
    apk add --no-cache qemu-img e2fsprogs-extra sfdisk python3 zerofree >/dev/null
    cd /tmp
    qemu-img convert -O raw "/out/$BASE_NAME" disk.raw
    # The root filesystem is the only "Linux filesystem" partition. Read its
    # position from the partition table instead of assuming it.
    geometry=$(sfdisk --dump disk.raw | awk -F"[=, ]+" "/type=0FC63DAF-8483-4772-8E79-3D69D8477DE4/ {print \$4, \$6}")
    start=${geometry% *}
    sectors=${geometry#* }
    case "$start$sectors" in ""|*[!0-9]*) echo "Root partition not found" >&2; exit 1;; esac
    dd if=disk.raw of=root.img bs=512 skip="$start" count="$sectors" status=none
    [ "$(dumpe2fs -h root.img 2>/dev/null | sed -n "s/^Filesystem volume name: *//p")" = / ] ||
      { echo "Unexpected root filesystem label" >&2; exit 1; }
    # Take out the packages the host does not need (packages.remove), and
    # require a stated reason for every package that stays (packages.why).
    debugfs -R "cat /lib/apk/db/installed" root.img 2>/dev/null > installed.old
    debugfs -R "cat /etc/apk/world" root.img 2>/dev/null > world.old
    python3 /image/trim_packages.py installed.old world.old /image/packages.remove /image/packages.why plan
    { cat plan/remove.debugfs
      echo "rm /lib/apk/db/installed"; echo "write plan/installed.new /lib/apk/db/installed"
      echo "sif /lib/apk/db/installed mode 0100644"
      echo "rm /etc/apk/world"; echo "write plan/world.new /etc/apk/world"
      echo "sif /etc/apk/world mode 0100644"
    } > trim.debugfs
    debugfs -w -f trim.debugfs root.img >/dev/null 2>trim.err
    if grep -v "^debugfs " trim.err | grep -q .; then cat trim.err >&2; exit 1; fi
    for path in /usr/bin/ssh /usr/bin/sgdisk /usr/share/zoneinfo/UTC; do
      if debugfs -R "stat $path" root.img 2>/dev/null | grep -q "Inode:"; then
        echo "$path is still in the image" >&2; exit 1
      fi
    done
    cp plan/packages.tsv "/out/$OUTPUT_NAME.packages.tsv"
    printf "image=fortis-bootcheck\ncommit=%s\nmodified=%s\nbuilt=%s\nbase=%s\n" \
      "$IMAGE_COMMIT" "$IMAGE_MODIFIED" "$IMAGE_BUILT" "${BASE_NAME%.qcow2}" > fortis-image
    debugfs -w root.img >/dev/null 2>debugfs.err <<EOF
write fortis-image /etc/fortis-image
sif /etc/fortis-image mode 0100644
sif /etc/fortis-image uid 0
sif /etc/fortis-image gid 0
write /image/files/sshd-fortis.conf /etc/ssh/sshd_config.d/10-fortis.conf
sif /etc/ssh/sshd_config.d/10-fortis.conf mode 0100600
sif /etc/ssh/sshd_config.d/10-fortis.conf uid 0
sif /etc/ssh/sshd_config.d/10-fortis.conf gid 0
write /bootcheck/fortis-bootcheck.initd /etc/init.d/fortis-bootcheck
sif /etc/init.d/fortis-bootcheck mode 0100755
sif /etc/init.d/fortis-bootcheck uid 0
sif /etc/init.d/fortis-bootcheck gid 0
write /bootcheck/fortis-bootcheck.sh /usr/local/bin/fortis-bootcheck
sif /usr/local/bin/fortis-bootcheck mode 0100755
sif /usr/local/bin/fortis-bootcheck uid 0
sif /usr/local/bin/fortis-bootcheck gid 0
write /bootcheck/crun-check.json /etc/fortis-bootcheck-crun.json
sif /etc/fortis-bootcheck-crun.json mode 0100644
sif /etc/fortis-bootcheck-crun.json uid 0
sif /etc/fortis-bootcheck-crun.json gid 0
symlink /etc/runlevels/default/fortis-bootcheck /etc/init.d/fortis-bootcheck
EOF
    # debugfs reports command failures on stderr and still exits zero.
    if grep -v "^debugfs " debugfs.err | grep -q .; then cat debugfs.err >&2; exit 1; fi
    for path in /etc/fortis-image /etc/ssh/sshd_config.d/10-fortis.conf /usr/sbin/sshd /etc/init.d/fortis-bootcheck /usr/local/bin/fortis-bootcheck /etc/fortis-bootcheck-crun.json /etc/runlevels/default/fortis-bootcheck; do
      debugfs -R "stat $path" root.img 2>/dev/null | grep -q "Inode:" ||
        { echo "Missing $path in image" >&2; exit 1; }
    done
    e2fsck -fn root.img >/dev/null
    # Freed blocks still hold the removed files; zero them so they compress away.
    zerofree root.img
    dd if=root.img of=disk.raw bs=512 seek="$start" conv=notrunc status=none
    qemu-img convert -O qcow2 -c disk.raw "/out/$OUTPUT_NAME.tmp"
    qemu-img check "/out/$OUTPUT_NAME.tmp" >/dev/null
    qemu-img info "/out/$OUTPUT_NAME.tmp" | sed -n "1,4p"
  '
mv "$output_dir/$output_name.tmp" "$output_dir/$output_name"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_dir" && sha256sum "$output_name" > "$output_name.sha256")
else
  (cd "$output_dir" && shasum -a 256 "$output_name" > "$output_name.sha256")
fi
echo "Upload: $output_dir/$output_name"
echo "Checksum: $output_dir/$output_name.sha256"
