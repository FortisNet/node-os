# Changelog

What changed for someone who runs a node or builds the images. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and version
numbers follow [Semantic Versioning](https://semver.org). Until 1.0.0,
anything may change between minor versions.

Node releases (`node-VERSION` on the releases page) are the FortisNet node
itself and have their own history in the node's repository.

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
