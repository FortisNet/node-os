# Developing Node OS

## Layout

| Folder | What it holds |
| --- | --- |
| [orchestrator/](../orchestrator) | One C++ program with several modes: it installs, starts, updates and recovers the node, owns the public ports, obtains certificates and serves a page when no node does |
| [keys/](../keys) | The key service, `fortis-keyd`, which holds the node's identity keys, and in [keys/client/](../keys/client) the library the node uses to reach it ([fortis-did.md](fortis-did.md)). Not in the images yet |
| [third_party/crypto/](../third_party/crypto) | ML-DSA-87 and SQIsign-V reference code, copied unchanged, only the files the key service links; [MANIFEST.json](../third_party/crypto/MANIFEST.json) pins each by hash |
| [sandbox/](../sandbox) | The sandbox manager for running untrusted jobs under gVisor. Not part of the images yet |
| [lib/](../lib) | Source files copied from the node: an HTTPS client, a JSON reader and small support headers. `ORIGIN.json` records where each came from |
| [image/](../image) | Builds the disk and container images. [image/README.md](../image/README.md) lists exactly what is in them and why |
| [assets/](../assets) | The design of the page the orchestrator serves: one HTML file, the logo and one image |
| [tests/](../tests) | Tests of the above, including a stand-in certificate authority and a stand-in release store |
| [tools/](../tools) | Build and release tools: the toolchain images, the hardening audit, the release publisher |

## How the orchestrator runs

The orchestrator is one program, `native-controller`, built from the files
in `ORCHESTRATOR_SOURCES` in the [Makefile](../Makefile) and installed as
`/usr/libexec/fortis/native-controller`. Its `main()` is at the end of
[orchestrator/native_update.cpp](../orchestrator/native_update.cpp).

### One program, many modes

It is always started as `native-controller CONFIG ACTION [ARGUMENT]`, where
`CONFIG` is `/etc/fortis/orchestrator.conf`. The action chooses what it is:

| Action | What it does | Runs as | Where |
| --- | --- | --- | --- |
| `first-boot` | Lays out a new host and writes its settings, once | root | `FirstBoot`, [first_boot.cpp](../orchestrator/first_boot.cpp) |
| `supervise` | The orchestrator proper: a loop that runs while the host is up | root | `main`, [native_update.cpp](../orchestrator/native_update.cpp) |
| `keeper` | Starts the node in its container through `crun` and holds its listening sockets | root, started by `supervise` | `RunKeeper`, [node_keeper.cpp](../orchestrator/node_keeper.cpp) |
| `fetch-worker` | Downloads release lists and releases | its own unprivileged user | `FetchWorker`, [native_update.cpp](../orchestrator/native_update.cpp) |
| `certificate-worker` | Asks Let's Encrypt for a certificate | its own unprivileged user | `CertificateWorker`, [native_update.cpp](../orchestrator/native_update.cpp) and [acme_client.cpp](../orchestrator/acme_client.cpp) |
| `page-server` | Serves the status page while no node runs | in a container of its own | `RunPageServer`, [page_server.cpp](../orchestrator/page_server.cpp) |
| `status`, `update`, `fetch`, `releases`, `backup`, `restore`, `stop`, `start`, `recover`, `retry`, `adopt`, `certificates` | One command, then exit: what `fortis ...` runs for an administrator | root | `Controller::Action`, [native_update.cpp](../orchestrator/native_update.cpp) |

The helpers are this same program run again in another mode. That is how
the rule "the orchestrator runs no other program, except `crun`" holds: a
worker that talks to the network is the orchestrator itself, re-run after
`fork()`, which gives up root (`setuid` to the worker's user) before it does
anything else. What a worker brings back is checked by the side that stayed
root.

### From boot to the loop

On a machine:

```text
boot
 └─ OpenRC service fortis-native                  image/files/fortis-native.openrc
     ├─ start_pre: native-controller CONFIG first-boot     a new host only
     └─ supervise-daemon, which restarts what it runs if it stops:
         run-native-service.sh CONFIG                     image/files/run-native-service.sh
          └─ manage-native-node.sh CONFIG supervise       image/files/manage-native-node.sh
              └─ exec native-controller CONFIG supervise
```

In a container there is no OpenRC.
[container-start.sh](../image/files/container-start.sh) prepares the control
groups, runs `native-controller CONFIG first-boot`, then
`exec run-native-service.sh CONFIG`, as above.

The two scripts only choose the program (`FORTIS_NATIVE_CONTROLLER` points
them at another one, as the tests do) and set `FORTIS_NATIVE_WAIT_LOCK=1`.
The `fortis` command an administrator types ([image/files/fortis](../image/files/fortis))
runs `manage-native-node.sh` too, with a one-off action: `fortis status` is
`native-controller /etc/fortis/orchestrator.conf status`.

### The supervise loop

```cpp
while (!interrupted) {
  Controller controller(Configure(config, false));  // the settings, read again every round
  controller.Action("tick");                        // one round of work
  // five crashes of the node within a minute each, or five failed rounds: stop, for an operator
  Pause(...);                                       // a second; five when the data must be on a mount
}
```

Each tick does what the host needs at that moment:

- **The node.** Starts it if it is not running, through the keeper. Watches
  its health, and undoes an update that does not hold.
- **The certificate.** Obtains and renews it, through `certificate-worker`.
- **Releases.** When a release store is set, looks for releases, downloads
  and verifies them (through `fetch-worker`), and installs one after a
  backup.
- **The pages.** Writes the five page files (`PublishPages`,
  [pages.cpp](../orchestrator/pages.cpp)); the facts on them are gathered
  by `Controller::Facts`.

A failed tick costs one round: the loop catches it and tries again. If the
whole process stops, OpenRC's `supervise-daemon` (or, in a container,
Docker's restart policy) starts it again.

### Where to start reading

- **To change what a command does:** `Controller::Action`.
- **To change what a tick does:** the `tick` branch at the end of the same
  function.
- **To change a page or the JSON:** [pages.cpp](../orchestrator/pages.cpp);
  the facts it shows come from `Controller::Facts`.
- **To change how the node is started:** [node_keeper.cpp](../orchestrator/node_keeper.cpp),
  including its container description and system call filter.
- **To change the settings:** `Configure` in [native_update.cpp](../orchestrator/native_update.cpp)
  reads them, and [first_boot.cpp](../orchestrator/first_boot.cpp) writes
  their defaults on a new host.

## Things that are easy to get wrong

Five things that look harmless and are not. Each says what it is, why it
matters, and what to do.

### 1. There is one program, not a set of services

- **What.** The orchestrator, the keeper, the download and certificate
  workers, the page server and every `fortis` command are all
  `native-controller`, started with a different action
  ([How the orchestrator runs](#how-the-orchestrator-runs)).
- **Why it matters.** There is no separate certificate daemon or page server
  program to find. A helper added as a new program breaks the rule that the
  orchestrator runs no other program except `crun`.
- **What to do.** Read the `if (action == ...)` lines of `main()` for the
  complete list of modes. Add a helper as a new action that the program runs
  of itself after `fork()`, and give up root first if it touches the network,
  as `FetchWorker` does.

### 2. The node lives in a sealed container and gets only what it is handed

- **What.** The node runs under `crun` as an ordinary user: no capabilities,
  a read-only filesystem, its own mount, process and IPC namespaces, and a
  system call filter ([node_keeper.cpp](../orchestrator/node_keeper.cpp)).
- **Why it matters.** It cannot see the host's files or sockets. "The node
  reads a file under `/var/lib`" or "the node connects to a socket under
  `/run`" fails, because inside its container those paths do not exist.
- **What to do.** Hand the node an open file descriptor, as the listening
  sockets are handed over (`crun --preserve-fds`, `FORTIS_LISTEN_FDS`), or
  add an explicit mount to its container description. Either is part of
  [the contract with the node](#the-contract-with-the-node), so it also needs
  a new host interface number.

### 3. The gate is the truth, and it runs only on Linux

- **What.** The orchestrator does not compile on macOS (it uses Linux-only
  parts of `struct stat`, such as `st_atim`). `make verify` runs everything
  in a container on Ubuntu, and clang-tidy treats every warning as an error.
  Its report counts only if no file changed while it ran.
- **Why it matters.** A plain `make` failing on a Mac is not a bug in your
  change. A change that builds and passes its tests can still fail the lint
  stage: an empty `catch`, a `push_back` in a loop without `reserve`, `atoi`.
  Editing any file, documentation included, while the gate runs wastes the
  run: it ends with "an input file changed while the gate ran".
- **What to do.** Format first with the gate's own `clang-format-18`, from
  its container image. Run `python3 verify.py`, change nothing until it
  ends, then check with `python3 verify.py --check-inputs`. Read
  `build-verify/logs/STAGE.log` to see that your tests really ran, not only
  that the stage says PASS.

### 4. The gate uses glibc, the images use musl

- **What.** The gate tests on Ubuntu with glibc. The images run Alpine with
  musl, and release programs are built with their own flags
  ([build-release.sh](../build-release.sh)).
- **Why it matters.** The two differ where nobody looks:
  - a thread's default stack is 8 MiB with glibc and 128 KiB with musl, and
    SQIsign signing reaches about 195 KB. The key service therefore gives its
    threads `kSigningStack` (2 MiB) itself, verifying threads need
    `kVerifyStack` (512 KiB, both in
    [key_algorithms.h](../keys/client/key_algorithms.h)), and
    [tests/keys_test.cpp](../tests/keys_test.cpp) measures what every
    operation uses ([fortis-did.md](fortis-did.md#131-threads), section 13.1).
    The release build's `-Wl,-z,stack-size` must not be what keeps a thread
    alive;
  - Linux resets a Unix socket connection that is closed with unread data in
    it, where macOS ends it cleanly;
  - anything else that rests on a C library's default.

  A change can pass the gate and fail on a real host.
- **What to do.** Never rely on a C library default: set stack sizes,
  timeouts and flags yourself. Treat a passing gate as necessary, not
  enough: for anything that runs on a host, also run
  [image/test-container.sh](../image/test-container.sh), which starts the
  real Alpine image end to end.

### 5. Some files are pinned: do not quietly change them

- **What.** Several things are frozen on purpose, and checked:
  - **[lib/](../lib)** holds copies of the node's files, each recorded in
    `ORIGIN.json` ([The copies in lib/](#the-copies-in-lib)). A new file
    there without an entry fails the gate.
  - **Copied upstream code and test vectors** are kept byte for byte, each
    pinned by its SHA-256 in a `MANIFEST.json` beside it, checked by a tool
    in the gate. The license notices in
    [third_party/native-runtime/](../third_party/native-runtime) are the
    same kind of copy.
  - **The images' Alpine packages** are pinned in
    `image/packages.x86_64.lock` and `image/packages.aarch64.lock`. When
    Alpine publishes an update, the image build stops until someone reviews
    it ([Building the images](#building-the-images)).
  - **The build's flags stamp** rebuilds every object when `CC`, `CXX`,
    `CXXFLAGS`, `DEPENDENCY_CFLAGS` or `ORCHESTRATOR_VERSION` change, and
    for nothing else. Changing `CPPFLAGS`, or another variable in the
    [Makefile](../Makefile), leaves objects built with the old values.
- **Why it matters.** "Fixing" a copied file, or adding a helper to `lib/`,
  looks harmless and breaks the gate, or the promise that a copy is what its
  upstream published. A stale object makes a test pass against old code.
- **What to do.** Change your own code, never a copy. Put new shared code in
  a folder of its own, not in `lib/`. After changing a build variable, run
  `make clean`, or make the objects that use it depend on the Makefile, and
  check in the build output that the compiler command really contains the
  new flags.

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
  repository and Mbed TLS alone and includes nothing from the node. The key
  service is a separate program, under its own user, so the much larger
  post-quantum code it needs never runs as administrator; it builds from this
  repository, Mbed TLS and the unchanged copies in `third_party/crypto/`.
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
- how the node reaches the key service (`FORTIS_KEYS_FD`) and the key
  service's wire format and labelled signing ([fortis-did.md](fortis-did.md),
  sections 9 to 11), once the orchestrator hands the connection over;
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
