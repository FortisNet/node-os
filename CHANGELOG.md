# Changelog

What changed for someone who runs a node or builds the images. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and version
numbers follow [Semantic Versioning](https://semver.org). Until 1.0.0,
anything may change between minor versions.

Node releases (`node-VERSION` on the releases page) are the FortisNet node
itself and have their own history in the node's repository.

## Unreleased

### Added

- Automatic updates of the node. A host that is given a release store
  (`FORTIS_NATIVE_RELEASE_STORE`) finds, downloads, verifies and installs
  the newest node release it can run by itself: on first start, before the
  release in its image, and afterwards at a regular check. Before an install
  it waits a random time, so hosts do not all restart together. A release
  that fails to install is undone and not tried again. **No store is set by
  default**, so a host changes nothing until it is given one.
- `/node.json`, and a "Node" entry on the first page and the health page:
  which release runs, what this Node OS can run, and what the host is doing
  about newer releases (looking, waiting with a countdown, downloading,
  verifying, installing, or which release it skipped and why).
- Compatibility by host interface number. A node release may name the host
  interface it needs (`host_interface=N` in its manifest); an orchestrator
  refuses a release outside the range it offers, and stays on the newest
  release it can run.
- Release list format 2: lists now expire, name their channel and carry the
  host interface of every release. Format 1 lists are still accepted.
- Release channels: `FORTIS_NATIVE_CHANNEL` is `stable` (the default) or
  `edge`. Having exactly these two is provisional and expected to change.
- A second store layout, `flat:https://host/prefix`, and its short form
  `github:OWNER/REPO`, so the downloads of GitHub releases can be a release
  store. Redirects to another HTTPS address are followed, as GitHub needs.
- Settings: `FORTIS_NATIVE_AUTO_UPDATE` (default 1),
  `FORTIS_NATIVE_UPDATE_CHECK_SECONDS` (default 3600) and
  `FORTIS_NATIVE_UPDATE_DELAY_SECONDS` (default 300).
- `tools/publish_release.py` writes format 2 lists and the flat layout:
  `--channel`, `--expires-days`, `--layout` and `--format`.

### Changed

- On a host that updates itself, the health check "Releases" no longer
  reports the host as waiting when the store has not answered: an
  unreachable store is said, but does not make a host unhealthy. Without
  automatic updates the check is as before.
- `fortis releases` marks releases this Node OS cannot run, and
  `fortis fetch` refuses them before downloading.
- A release store's address may no longer hold a user name, a password or a
  query: the address is shown on the host's pages.

### Fixed

- A request to stop the supervisor that arrived while it was installing a
  release was forgotten once the install had been undone; the supervisor
  kept running until it was asked again.

## [0.1.0] - 2026-11-26

The first numbered release.

### Added

- Three images from one build: a disk image for x86-64 virtual machines and
  container images for x86-64 and ARM64, also at `ghcr.io/fortisnet/node-os`.
- First start with nobody logging in: the host finds its public address,
  obtains a certificate from Let's Encrypt, installs the signed node release
  inside the image and serves it over HTTPS.
- The orchestrator: installs, updates, watches and recovers the node; undoes
  an update that does not hold; backs up the database before every update.
- A status page on port 80 from the first second, and `/health` and
  `/health.json` for people and for monitoring.
- Node releases signed on GitHub behind a reviewer's approval, and pinned in
  the repository by hash.
- For every download: checksums, signed build provenance, a cosign signature
  and a list of the software inside (SPDX).
- The exact version of every Alpine package in the images is pinned.
- The image build installs the security fixes Alpine has published since
  its base image was made (the kernel and bootloader excepted).

### Known limits

- The node inside runs in development mode.
- Container images run without `--privileged` but still hold `SYS_ADMIN`.
- The orchestrator and the Alpine base are updated only by a new image.
- The status page is plain HTTP until the certificate is issued.
- The disk image has been started in an emulator, not yet on a real cloud.

[0.1.0]: https://github.com/FortisNet/node-os/releases/tag/v0.1.0
