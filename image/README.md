# The images

This folder builds the images a FortisNet node host is made from. There are
two kinds:

- The **node host image** is the real one. A machine created from it sets
  itself up with nobody logging in: it obtains a certificate for its address,
  installs the node release it carries and shows the first page. See
  [The node host image](#the-node-host-image).
- The **boot check image** is the same base plus a report service, used to
  prove the base on a new cloud before a node is put on it.

```sh
./image/build-image.sh NODE_RELEASE RELEASE_PUBLIC_KEY ORCHESTRATOR_RELEASE
# Output, always all three, in dist/image/, each with its checksum:
#   fortis-node-os-x86_64-COMMIT.qcow2            a disk a cloud boots
#   fortis-node-os-x86_64-COMMIT.docker.tar.gz    the same files as a container image
#   fortis-node-os-aarch64-COMMIT.docker.tar.gz   the container image for ARM servers
./image/build-bootcheck-image.sh
# Output: dist/image/fortis-bootcheck-x86_64-COMMIT.qcow2 and its checksum
```

**Every image is named after its commit and carries it inside.** `COMMIT` is
the first 12 characters of the commit the image was built from. The full
hash is in the image at `/etc/fortis-image`, with the build time, the base
image and whether the sources had uncommitted changes:

```
image=fortis-bootcheck
commit=0123456789abcdef0123456789abcdef01234567
modified=no
built=2026-11-25T12:30:00Z
base=alpine-3.24.3-x86_64-tiny-r0
```

An image built with uncommitted changes in the repository is named
`...-COMMIT-modified.qcow2` and says `modified=yes`: it cannot be rebuilt
from its commit, so do not publish one. The boot report prints these values
first, so a report can always be matched to an image and its sources. Build
from a clean, committed tree; commit first, then build.

The builds need Docker and network access, and execute nothing from the
image. The boot check build edits the base without mounting it. The node host
build adds packages, so it mounts the root filesystem in a privileged build
container.

## What is in the image, and why

### The base

Alpine Linux 3.24.3, the "tiny" cloud image, pinned by SHA-512 in the build
script. It was chosen because it has no cloud-init and no Python: first boot
is done by `tiny-cloud`, a 0.09 MB shell tool. Alpine is small, uses the musl
C library the node is already built for, and gets security updates through
its package manager.

There is no Docker, no compiler, no Python, no `curl` and no `git` in it.

### Not tied to one cloud

The image must boot on any cloud or virtual machine host, not only the one
it is first tested on. Three rules keep it that way:

- **Cloud differences are handled only by `tiny-cloud`.** It detects the
  cloud at first boot and ships providers for AWS, Azure, DigitalOcean,
  Google Cloud, Hetzner, Oracle, OpenStack, Scaleway, Incus and "nocloud"
  (any other virtual machine, with settings on a seed disk). Nothing this
  project adds to the image calls one cloud's own service, except the boot
  report's clearly marked DigitalOcean section.
- **No package or kernel driver is removed because one cloud does not use
  it.** The NVMe tools stay although DigitalOcean has no NVMe disks, because
  AWS does. Kernel drivers are trimmed only against a list that covers every
  supported cloud's disks and network cards, and none are removed until that
  list exists and has been boot-tested.
- **One build, several disk formats.** The same disk converts to qcow2, raw
  and VHD for the clouds that want each.

A cloud counts as supported once the boot check image has booted on it and
its report has been read. So far: an emulator only; DigitalOcean is pending.

### Packages

Every installed package is listed with the reason it is there. The build
fails if a package is installed without a reason, so this table cannot fall
behind the image. Sizes are as installed, read from the built image.

<!-- packages:begin -->

**Kernel and boot**

| Package | Size | Why it is in the image |
| --- | ---: | --- |
| `linux-virt` | 49.41 MB | The kernel, built for virtual machines |
| `limine-bios` | 0.28 MB | Bootloader for BIOS boot |
| `limine-efi-x86_64` | 0.30 MB | Bootloader for UEFI boot |
| `limine-tool` | 57 KB | Installs the bootloader after a kernel update |
| `limine-bios-updater` | 1 KB | Reinstalls the BIOS bootloader after an update |
| `limine-efi-updater` | 3 KB | Reinstalls the UEFI bootloader after an update |
| `mkinitfs` | 83 KB | Builds the early boot image after a kernel update |
| `cryptsetup-libs` | 0.46 MB | Required by mkinitfs |
| `device-mapper-libs` | 0.29 MB | Required by mkinitfs |
| `json-c` | 62 KB | Required by cryptsetup-libs and the NVMe tools |
| `kmod` | 0.13 MB | Loads kernel modules |
| `kmod-libs` | 81 KB | Library of kmod |
| `lddtree` | 9 KB | Used by mkinitfs to collect libraries |
| `scanelf` | 65 KB | Used by lddtree |
| `dosfstools` | 0.16 MB | Maintains the UEFI boot partition |

**Base system**

| Package | Size | Why it is in the image |
| --- | ---: | --- |
| `alpine-base` | none | Alpine's minimal base set |
| `alpine-baselayout` | 6 KB | Directory layout and base configuration |
| `alpine-baselayout-data` | 18 KB | Base configuration files |
| `alpine-conf` | 0.18 MB | Alpine's system setup scripts, used at first boot |
| `alpine-release` | 1 KB | Version file |
| `musl` | 0.64 MB | The C library |
| `musl-utils` | 54 KB | C library tools |
| `busybox` | 0.78 MB | The shell and the standard commands |
| `busybox-binsh` | 1 KB | Makes the busybox shell /bin/sh |
| `busybox-suid` | 13 KB | The few busybox commands that need elevated rights |
| `busybox-openrc` | 2 KB | Service files for busybox daemons (system log, console) |
| `busybox-mdev-openrc` | 1 KB | Service file for the device manager |
| `mdev-conf` | 9 KB | Device manager rules |
| `openrc` | 1.30 MB | The service manager; also provides the control group setup crun needs |
| `openrc-user` | 14 KB | Part of the service manager |
| `libcap2` | 47 KB | Required by the service manager and the clock service |
| `libeconf` | 64 KB | Required by util-linux tools |
| `libncursesw` | 0.33 MB | Required by sfdisk |
| `ncurses-terminfo-base` | 100 KB | Terminal descriptions for the console and SSH sessions |

**Package management and trust**

| Package | Size | Why it is in the image |
| --- | ---: | --- |
| `apk-tools` | 0.11 MB | Installs security updates for the host |
| `libapk` | 0.26 MB | Library of apk-tools |
| `alpine-keys` | 12 KB | Keys that verify Alpine packages |
| `ca-certificates-bundle` | 0.17 MB | Trust anchors: the certificate authority and the release store are verified against these |
| `ssl_client` | 14 KB | HTTPS for the built-in download command |
| `zlib` | 0.10 MB | Compression, required by apk-tools and OpenSSH |
| `xz-libs` | 0.22 MB | Compression, required by kmod |
| `zstd-libs` | 0.68 MB | Compression, required by kmod |
| `libcrypto3` | 4.98 MB | Cryptography library, required by OpenSSH and apk-tools |
| `libssl3` | 0.80 MB | TLS library, required by apk-tools and the built-in download command |

**Remote access**

| Package | Size | Why it is in the image |
| --- | ---: | --- |
| `openssh-server` | 1.79 MB | The SSH server: how the operator reaches the host |
| `openssh-server-common` | 3 KB | SSH server configuration |
| `openssh-server-common-openrc` | 4 KB | SSH service file |
| `openssh-keygen` | 0.35 MB | Creates the host's SSH keys at first boot |
| `doas` | 34 KB | Lets the operator's account act as administrator |

**Network and time**

| Package | Size | Why it is in the image |
| --- | ---: | --- |
| `dhcpcd` | 0.34 MB | Gets the network address |
| `dhcpcd-openrc` | 1 KB | Its service file |
| `ifupdown-ng` | 0.13 MB | Brings network interfaces up |
| `bridge` | 2 KB | Part of the network setup scripts |
| `chrony` | 0.29 MB | Keeps the clock right; certificates and signatures need it |
| `chrony-common` | 1 KB | Clock service files |
| `chrony-openrc` | 1 KB | Clock service file |

**Disk and first boot**

| Package | Size | Why it is in the image |
| --- | ---: | --- |
| `tiny-cloud` | 88 KB | First boot: network, SSH key, host name, disk growth |
| `tiny-cloud-openrc` | 1 KB | Its service files |
| `yx` | 13 KB | Reads settings for tiny-cloud |
| `yaml` | 0.10 MB | Required by yx |
| `e2fsprogs` | 0.38 MB | Filesystem check at boot |
| `e2fsprogs-extra` | 0.56 MB | Grows the filesystem to the disk at first boot |
| `e2fsprogs-libs` | 0.43 MB | Library of e2fsprogs |
| `libcom_err` | 17 KB | Required by e2fsprogs |
| `sfdisk` | 82 KB | Grows the partition at first boot |
| `partx` | 50 KB | Tells the kernel about the grown partition |
| `libfdisk` | 0.26 MB | Required by sfdisk |
| `libsmartcols` | 0.12 MB | Required by sfdisk |
| `libblkid` | 0.19 MB | Identifies disks and partitions |
| `libuuid` | 29 KB | Required by the disk tools |
| `nvme-cli` | 1.20 MB | NVMe disk tools: AWS and other clouds present disks as NVMe |
| `libnvme` | 0.17 MB | Required by nvme-cli |
| `libnvmemi` | 33 KB | Required by nvme-cli |
| `mount` | 38 KB | Mounts filesystems |
| `libmount` | 0.28 MB | Library of mount |
| `libseccomp` | 0.16 MB | System call filtering: required by the clock service, and by crun for the node's filter |

76 packages, 69.4 MB installed.

**Removed from the Alpine base**

| Package | Why it was removed |
| --- | --- |
| `openssh` | group package: server, client and file transfer helper together |
| `openssh-client-default` | the host never connects out by SSH |
| `openssh-client-common` |  |
| `libedit` | line editing for the SSH client only |
| `openssh-sftp-server` | sshd uses its built-in file transfer server |
| `tzdata` | the host runs in UTC |
| `sgdisk` | tiny-cloud grows the disk with sfdisk and partx |
| `popt` | only sgdisk used it |
| `libstdc++` | only sgdisk used it |
| `libgcc` | only sgdisk used it |

<!-- packages:end -->

The kernel is nearly three quarters of the installed size, and most of that
is drivers no cloud uses. They all stay for now: see "Not tied to one cloud"
above. Leaving out a needed one gives a host that does not boot.

### Services that start at boot

| Service | Why |
| --- | --- |
| Device manager, system log, host name, clock from hardware, kernel settings, modules, swap | Alpine's standard boot |
| `tiny-cloud` (four stages) | First boot only: network, the operator's SSH key, host name, growing the disk |
| `networking` with `dhcpcd` | The network address |
| `chronyd` | Correct time, needed before any certificate or signature is checked |
| `sshd` | Operator access |
| Console login prompt | The cloud's recovery console. No account has a password, so it cannot be used to log in over the network |
| `fortis-bootcheck` | Boot check image only: writes the report |
| `nftables` | Node host image only: the firewall, loaded before the network is up |
| `fortis-native` | Node host image only: configures a new host once, then runs the orchestrator |

### SSH

The operator logs in as `alpine` with the SSH key chosen when the Droplet is
created, and becomes administrator with `doas`.
[files/sshd-fortis.conf](files/sshd-fortis.conf) is installed as
`/etc/ssh/sshd_config.d/10-fortis.conf` and sets, explicitly instead of
relying on defaults:

| Setting | Value | Why |
| --- | --- | --- |
| Password login | off | Only a key can log in |
| Keyboard-interactive login | off | The other route to a password prompt |
| Root login | off | Administrators arrive as `alpine` and are logged |
| Authentication | public key only | States the rule directly |
| TCP, agent, X11 forwarding and tunnels | off | The host is not a relay |

The SSH client, the separate file transfer helper and the group package that
pulled them in are removed; `sshd` serves file transfer itself.

### Files added by this project

| File in the image | From | What it is |
| --- | --- | --- |
| `/etc/fortis-image` | written by the build | Which image this is: commit, build time, base, and whether the sources were modified |
| `/etc/ssh/sshd_config.d/10-fortis.conf` | [files/sshd-fortis.conf](files/sshd-fortis.conf) | The SSH settings above |
| `/usr/local/bin/fortis-bootcheck` | [bootcheck/fortis-bootcheck.sh](bootcheck/fortis-bootcheck.sh) | Boot check image only: collects the report |
| `/etc/init.d/fortis-bootcheck` | [bootcheck/fortis-bootcheck.initd](bootcheck/fortis-bootcheck.initd) | Boot check image only: runs it once networking is up |
| `/etc/fortis-bootcheck-crun.json` | [bootcheck/crun-check.json](bootcheck/crun-check.json) | Boot check image only: the node's isolation settings, tried on a throwaway container |

## The node host image

`build-image.sh` takes the base described above and adds everything a node
host needs, so that creating a machine from the image is the whole
installation.

```sh
./image/build-image.sh NODE_RELEASE RELEASE_PUBLIC_KEY ORCHESTRATOR_RELEASE
```

| Argument | What it is |
| --- | --- |
| `NODE_RELEASE` | A signed node release folder: `fortis-node`, `manifest`, `manifest.sig` |
| `RELEASE_PUBLIC_KEY` | The public half of the key that signed it. The host trusts releases signed by this key and no other, for its whole life |
| `ORCHESTRATOR_RELEASE` | A release of this repository, `dist/VERSION`, from `make release VERSION=...`. It holds `x86_64/` and `aarch64/` |

The build refuses a node release that the given key did not sign.

`NODE_RELEASE` likewise holds `x86_64/` and `aarch64/`, from
`make native-release VERSION=...`, each signed. The build refuses a
release whose manifest names another architecture than its folder, and two
node releases of different versions.

Every build writes **three images**: the x86 disk image for clouds, and a
container image for each processor family (x86 and ARM) for a server that
already runs Docker. A container image is a packaging of the same files as a
disk. See [The container packaging](#the-container-packaging).

### What it adds to the base

| In the image | From | What it is |
| --- | --- | --- |
| `crun` (package) | Alpine | Starts the node and the orchestrator's helpers, each in its own container. There is no container daemon |
| `nftables` and its five libraries (packages) | Alpine | The firewall. Reasons are in [packages.host.why](packages.host.why); the build fails when an added package has none |
| `/etc/nftables.nft` | [files/nftables.nft](files/nftables.nft) | The rules: from outside, only ports 22, 80 and 443 are reachable |
| `/usr/libexec/fortis/native-controller` | the orchestrator release | The orchestrator |
| `/usr/libexec/fortis/manage-native-node.sh`, `run-native-service.sh` | [files/](files/) | Its two launch scripts |
| `/usr/libexec/fortis/container-start.sh` | [files/container-start.sh](files/container-start.sh) | The start command of the container packaging; unused on a machine |
| `/usr/sbin/fortis` | [files/fortis](files/fortis) | The operator's command: `doas fortis status` |
| `/etc/init.d/fortis-native` | [files/fortis-native.openrc](files/fortis-native.openrc) | The service that configures a new host and runs the orchestrator |
| `/usr/share/fortis/release-public.pem` | the given key | The one release key the host trusts |
| `/usr/share/fortis/node-release/` | the given release | The node release installed on first boot |
| `/etc/fortis-image` | written by the build | As in every image, plus the orchestrator version and hash, the node version and hash, and the hash of the release key |

### What a new machine does by itself

1. `tiny-cloud` sets up the network, the operator's SSH key and the disk, as
   in the base. The firewall is loaded before the network comes up.
2. The `fortis-native` service runs `native-controller first-boot`. It finds
   the machine's address, creates the folders under `/var/lib/fortis` and
   writes `/etc/fortis/orchestrator.conf` and `/etc/fortis/node.env`. It does
   this once; later boots leave the configuration alone.
3. The orchestrator starts and shows the first page on port 80 straight
   away. The page says what the host is waiting for.
4. Once the clock is set, it asks Let's Encrypt for a certificate for the
   machine's address. If that fails it tries again every ten minutes, and the
   node release is not blamed for it.
5. With the certificate in place it verifies and installs the node release
   from the image, and the first page is served over HTTPS on port 443.

Nothing is asked of the operator. Everything is logged to
`/var/log/fortis-orchestrator.log`.

### Settings at creation, when wanted

The defaults need no input. To change one, give the machine user data whose
first line is `#fortis-settings`, followed by `KEY=VALUE` lines. Names that
start with `FORTIS_NATIVE_` are the orchestrator's; any other name goes to
the node. They are used on first boot only.

```
#fortis-settings
FORTIS_HTTPS_DOMAIN=node.example.org
```

### The firewall

| From outside | Allowed |
| --- | --- |
| TCP 22 | SSH, key only |
| TCP 80 | The certificate authority's check, and the redirect to HTTPS |
| TCP 443 | The node |
| ICMP | Ping and the messages networks need to work |
| Everything else, including the node's health port 8081 | Dropped |

Connections the host starts itself (releases, certificates, time, names) are
allowed out, and their answers back in. The rules name no cloud and no
network interface, so they are the same everywhere.

## The container packaging

A cloud boots a disk; Docker runs a folder of files on the server's own
kernel. No single file serves both, so the build writes the same root
filesystem out twice. The container image is the disk's files without `/boot`
and the kernel modules, which a container cannot use. Both carry the same
`/etc/fortis-image`, so both name the same commit.

```sh
docker load -i fortis-node-os-x86_64-COMMIT.docker.tar.gz    # the aarch64 file on an ARM server
docker run -d --name fortis-node --restart unless-stopped \
  --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add SYS_PTRACE \
  --security-opt apparmor=unconfined --cgroupns private \
  --init --stop-timeout 240 \
  -p 80:80 -p 443:443 \
  -v fortis-data:/var/lib/fortis \
  fortis-node-os:COMMIT-x86_64          # or COMMIT-aarch64 on an ARM server
docker logs -f fortis-node
```

| Option | Why |
| --- | --- |
| `--cap-add SYS_ADMIN` | The orchestrator starts the node in a container of its own with `crun`, which makes namespaces and mounts, and it makes the container's own control groups writable. The node itself still runs without any privilege, as user 10001, under its system call filter |
| `--cap-add NET_ADMIN` | `crun` switches on the loopback interface of the node's own network namespace. It applies to the container's network only, not the server's |
| `--cap-add SYS_PTRACE` | Before trusting a running node, the orchestrator hashes the program that process is really running (`/proc/PID/exe`), which Linux allows across users only with this right |
| `--security-opt apparmor=unconfined` | On servers with AppArmor, Docker's default profile forbids every mount, including the ones `crun` makes for the node |
| `--cgroupns private` | The container gets control groups of its own, which is what makes handing them to it safe. It is Docker's default on current systems; saying so makes it certain |
| `--init` | Collects processes that end, the job the init system has on a machine |
| `--stop-timeout 240` | Gives the node time to close its database when the container is stopped |
| `-p 80:80 -p 443:443` | The certificate authority's check and the node. The health port is not published |
| `-v fortis-data:/var/lib/fortis` | The database, backups, certificates and the orchestrator's state. Everything that must outlive the container is here |
| `-e FORTIS_HTTPS_IP=...` | Optional. The server's public address. From inside a container only a private address is visible; without this setting the host asks two public services which address it is seen under ([docs/first-boot.md](../docs/first-boot.md#how-a-host-finds-its-public-address)) |

Any `FORTIS_*` variable is a setting, exactly like the `#fortis-settings`
lines of a machine. They are read when the container is first created.

**The orchestrator works out where it runs.** At start it tells a container
from a machine (the markers container runtimes leave: `/.dockerenv`,
`/run/.containerenv`, or the `container` variable of the first process) and
says so:

| Where | What it shows |
| --- | --- |
| The log | `Orchestrator supervising; runs in: container` (or `machine`) |
| `health.json` | `"orchestrator": {"runsIn": "container", ...}` |
| The health page | "Supervising this host. It runs in a container." |

What differs between the two, and who does the job instead:

| Job | On a machine | In a container |
| --- | --- | --- |
| Start at boot, restart | OpenRC service `fortis-native` | [files/container-start.sh](files/container-start.sh) and Docker's restart policy |
| Network, SSH key, disk | `tiny-cloud` | Docker and the server |
| Firewall | `nftables` in the image | Only the published ports are reachable; the server's own firewall |
| Clock | `chronyd` in the image | The server's clock |
| Control groups for the node | OpenRC | `container-start.sh` moves the container's processes into a group of their own and hands the controllers down |
| Operator access | SSH as `alpine`, `doas fortis status` | `docker exec fortis-node fortis status`, `docker logs fortis-node` |
| Log of the orchestrator | `/var/log/fortis-orchestrator.log` | `docker logs` |

The container does **not** run with `--privileged`. Compared with that, it
has no access to the server's disks and devices, keeps Docker's system call
filter, and lacks the rights to load kernel modules, set the clock or
reboot. `--privileged` still works, for a runtime where the options above
are not available.

A machine of its own remains the stronger arrangement: `SYS_ADMIN` is the
broadest single right Linux has, and a container shares the server's kernel.

## The boot report

On first boot the boot check image writes `/var/log/fortis-bootcheck.txt` and
prints it on the console. It checks the network, which cloud was detected, the
SSH key and settings, disk growth, the clock, that the removed programs are
gone and how many files differ from the package database, and that a container gets the
node's isolation under `crun`. It prints no secrets.

```sh
ssh alpine@DROPLET_ADDRESS cat /var/log/fortis-bootcheck.txt
```

## How packages are removed without running the image

The package manager cannot be run on an image that is never mounted or
booted during the build. [trim_packages.py](trim_packages.py) reads the
image's package database instead, deletes exactly the files the removed
packages own, and writes the database back without them. It refuses when a
package that stays needs one that goes. The boot report then asks the package
manager, on the running host, whether the database still matches the files.

| File | Purpose |
| --- | --- |
| [packages.remove](packages.remove) | What is taken out, with reasons |
| [packages.why](packages.why) | Why each remaining package is there |
| [packages.x86_64.lock](packages.x86_64.lock), [packages.aarch64.lock](packages.aarch64.lock) | The exact version of every package in the node host images. A build that would install anything else fails, so one commit always builds the same system; `FORTIS_UPDATE_PACKAGE_LOCK=1 ./build-image.sh ...` rewrites them for review |
| [readme_packages.py](readme_packages.py) | Writes the table above from those two files and the built image; `make verify` checks it |
