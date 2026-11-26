# Developing Node OS

## Layout

| Folder | What it holds |
| --- | --- |
| [orchestrator/](../orchestrator) | One C++ program with several modes: it installs, starts, updates and recovers the node, owns the public ports, obtains certificates and serves a page when no node does |
| [sandbox/](../sandbox) | The sandbox manager for running untrusted jobs under gVisor. Not part of the images yet |
| [lib/](../lib) | Source files copied from the node: an HTTPS client, a JSON reader and small support headers. `ORIGIN.json` records where each came from |
| [image/](../image) | Builds the disk and container images. [image/README.md](../image/README.md) lists exactly what is in them and why |
| [assets/](../assets) | The design of the page the orchestrator serves: one HTML file, the logo and one image |
| [tests/](../tests) | Tests of the above, including a stand-in certificate authority and a stand-in release store |
| [tools/](../tools) | Build and release tools: the toolchain images, the hardening audit, the release publisher |

## Building and testing

You need Docker, Python 3 and `make`. Nothing else is installed on your
computer: compilers and checkers run in a container the gate builds itself.

```sh
make verify                       # the full gate, about five minutes
make release VERSION=1.2.3        # hardened static releases: dist/1.2.3/x86_64 and dist/1.2.3/aarch64
```

`make verify` runs these stages, with the network switched off:

| Stage | What it does |
| --- | --- |
| `clang` | Builds with Clang and libc++, runs every test |
| `gcc` | Builds with GCC, runs every test |
| `sanitizers` | Builds with AddressSanitizer and UndefinedBehaviorSanitizer, runs every test under them, then fuzzes the parsers of unverified text (both release list formats among them) for a minute ([tests/parser_fuzz.cpp](../tests/parser_fuzz.cpp)) |
| `analyzer` | The Clang Static Analyzer on every source file |
| `lint` | clang-tidy on every source file, clang-format on all but `lib/` |
| `cppcheck` | cppcheck on every source file |
| `python` | pyflakes on every Python file |

`python3 verify.py --stage NAME` runs one of them. To fuzz for longer, use
the sanitizer build: `make fuzz FUZZ_SECONDS=3600` with the flags that stage
prints.

It writes `build-verify/report.json`: one result per
stage and the hash of every input file. **A release can only be built from
files whose report is complete, passing and unchanged**; `build-release.sh`
checks this before and after it builds.

With a C++23 compiler, Python 3, `openssl` and `shellcheck` installed you can
also build and test directly: `make` and `make test`.

### The release build

[build-release.sh](../build-release.sh) produces static, position-independent
programs with musl and GCC. Every compiler invocation is recorded and
[tools/hardening.py](../tools/hardening.py) checks that each source file was
compiled with the hardening profile ([tools/hardening.mk](../tools/hardening.mk):
stack protector, stack clash protection, fortify, full RELRO, no executable
stack) and that the finished file is what it should be: no interpreter, no
shared library, no writable and executable segment.

### Building the images

```sh
./image/build-image.sh NODE_RELEASE RELEASE_PUBLIC_KEY dist/1.2.3
```

`NODE_RELEASE` is a signed release of the FortisNet node holding `x86_64/`
and `aarch64/`. The exact version of every Alpine package is pinned in
`image/packages.x86_64.lock` and `image/packages.aarch64.lock`; when Alpine
publishes an update the build stops and shows the difference. (The build
installs Alpine's newest packages over the base image, except the kernel
and the bootloader, whose replacement needs scripts the build does not run.) Review it,
rebuild with `FORTIS_UPDATE_PACKAGE_LOCK=1` and commit the two files. See [image/README.md](../image/README.md) for the arguments
and [images.md](images.md) for what comes out.

### Trying a container image on your own computer

[image/test-container.sh](../image/test-container.sh) starts a container image
beside a stand-in certificate authority and checks the whole path: first
boot, the certificate, the install of the node, the node answering over
HTTPS under its system call filter.

```sh
./image/test-container.sh fortis-node-os:COMMIT-aarch64          # on an ARM computer
./image/test-container.sh fortis-node-os:COMMIT-x86_64 --keep    # on an Intel or AMD one; leave it running
```

It only runs the image built for the computer's own processor. Docker can
run programs of the other family by translating them, but the program that
puts the node in its container (`crun`) does not survive that translation.


## Rules this code keeps

These are the decisions the design rests on. A change that breaks one needs
a very good reason.

- **Small, and separate from the node.** This is the part that runs as
  administrator, so it is kept small enough to review. It builds from this
  repository and Mbed TLS alone and includes nothing from the node.
- **The orchestrator runs no other program, except `crun`.** Signatures and
  hashes are checked with Mbed TLS, HTTPS is spoken by the client in `lib/`,
  and files are copied in-process. There is no shell, `curl`, `openssl` or
  package manager in the path of an update.
- **Whatever talks to the network has no privileges.** Certificate requests,
  downloads and the address lookup run as their own unprivileged users. The
  administrator's side verifies everything they bring back before using it.
- **Nothing is trusted but signatures.** The release store, the certificate
  authority's answers and the address lookup are all checked. A host accepts
  only node releases signed by the key that was built into its image.
- **Not tied to one cloud.** Nothing in `orchestrator/` or `image/` may
  depend on one cloud. Cloud differences are handled by `tiny-cloud` in the
  image; no package or kernel driver is removed because one cloud does not
  need it. [image/README.md](../image/README.md) has the rules.
- **Every image names its commit.** In its file name and inside, in
  `/etc/fortis-image`.

## The copies in lib/

`lib/` holds copies of a few files from the node. They are copies on
purpose, so this repository builds alone. [lib/ORIGIN.json](../lib/ORIGIN.json)
records where each came from and its hash at the time.
[tools/check_lib_origin.py](../tools/check_lib_origin.py) runs in the gate
and checks that every copy has an entry. Given a checkout of the node, it
also fails when a file a copy was taken from has changed since: someone must
then port the change into the copy, or decide it does not apply, and record
the new hash.

## The contract with the node

What this repository and the node agree on is a contract, not shared code:

- how listening sockets are handed to the node (`FORTIS_LISTEN_FDS`);
- the layout of the certificate folder;
- the node's health answers on its loopback port;
- the signed release format (`manifest`, `manifest.sig`, `fortis-node`);
- the four page files the orchestrator writes and the node serves at `/`,
  `/health` and `/health.json` ([operating.md](operating.md#the-first-page-and-health)),
  and a fifth, `node.json`, written beside them for the node to serve at
  `/node.json`. Node releases made before that file existed do not serve it;
- the host interface number: a release manifest may say `host_interface=N`,
  and this orchestrator runs only releases whose number it offers
  ([releases.md](releases.md#which-releases-a-host-can-run)). The number
  goes up whenever a change to anything in this list would stop an existing
  release from working.
