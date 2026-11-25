# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting for this repository: the
**Security** tab, then **Report a vulnerability**. Say what is affected, how
to reproduce it and what an attacker gains. Do not include private keys,
credentials or data from a real host.

No response time is promised yet. Reports are read, and fixes are made on
the `main` branch.

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
