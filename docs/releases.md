# Node releases: publishing and fetching

Node releases reach a host from a **release store**: a plain HTTPS file tree
(any object store or static file host that honours range requests). The
store is not trusted. Only signatures are, checked against the public keys
installed on the host.

```
STORE/ARCH/index                         sequence, date, one line per release
STORE/ARCH/index.sig                     signature over the exact index bytes
STORE/ARCH/releases/VERSION/manifest     as written by the node's release build
STORE/ARCH/releases/VERSION/manifest.sig
STORE/ARCH/releases/VERSION/fortis-node
```

`ARCH` is the processor architecture, `x86_64` or `aarch64`. A release is
built and signed once for each, under the same version, and each
architecture has its own index. A host reads only the tree of its own
architecture, and refuses a release built for the other one.

On the signing machine, [tools/publish_release.py](../tools/publish_release.py)
adds a signed release to a local copy of the store and re-signs the index
with the next sequence number; the folder is then uploaded as it is.

On the host:

```sh
native-controller CONFIG releases          # check the store, list what it offers
native-controller CONFIG fetch VERSION     # download and stage one release
native-controller CONFIG update VERSION    # install a staged release
```

- **The part that talks to the network installs nothing.** Downloads are
  done by an unprivileged process that gives up administrator rights first
  and can only write its own staging folder.
- **The administrator side verifies everything it was handed:** the index
  signature; that the index is not older than one already accepted, and not
  a different index under the same sequence; that the downloaded manifest is
  the one the index names; then the release's own signature, hash, size,
  architecture and storage format, on a private copy that cannot be swapped
  afterwards. Anything that fails is discarded and the running node is not
  touched.
- **Staged is not installed.** `fetch` only stages; the operator decides when
  to run `update`, which then does what an update always does: preflight,
  backup, switch, observe, and roll back on failure.
- **Two keys.** A release or index may be signed by the release key or, when
  `FORTIS_NATIVE_RECOVERY_KEY` is set, by an offline recovery key, so a lost
  release key can be replaced without reinstalling hosts.

Settings: `FORTIS_NATIVE_RELEASE_STORE` (the store's https address; without
it, releases are installed from folders as before),
`FORTIS_NATIVE_FETCH_STATE` and `FORTIS_NATIVE_FETCH_USER` for the
unprivileged process.

One gap is accepted for now: whoever controls the store can keep serving an
old, validly signed index and so hide newer releases. The date of the last
accepted index is recorded for the first page to show.
