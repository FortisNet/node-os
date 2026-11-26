# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/FortisNet/node-os/security/advisories/new> (the
**Security** tab, then **Report a vulnerability**). Say what is affected, how
to reproduce it and what an attacker gains. Do not include private keys,
credentials or data from a real host.

## What happens next

- We aim to acknowledge a report within 5 working days.
- We tell you whether we can reproduce it and what we plan to do, and keep
  you informed until it is fixed.
- Fixes are made on the `main` branch and published as a new release. The
  problem is then described in a
  [security advisory](https://github.com/FortisNet/node-os/security/advisories),
  with credit to you unless you prefer otherwise.
- Please give us up to 90 days before publishing details yourself.

Only the newest release is supported with fixes.

## What is in scope

- The orchestrator, the sandbox manager and the copied library files.
- The image build and what ends up in the images.
- The update path: signatures, the release index, staging, rollback.
- Certificate handling and the page server.

The FortisNet node itself lives in another repository; report problems in
the node there.

## What the design assumes

- The administrator of a host is trusted, and so is whoever holds the
  release signing key. A host runs any node release that key signs.
- The release store, the certificate authority's answers, the address
  lookup services and the network are not trusted.
- A container image runs with `--privileged`, which is close to being
  administrator of the server it runs on. A machine of its own is the
  stronger arrangement.
- Backups are not encrypted. Protecting a backup that leaves the host is the
  operator's job.
