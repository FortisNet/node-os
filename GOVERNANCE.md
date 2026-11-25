# Governance

How decisions are made in this repository, and who makes them.

## Maintainers

The maintainers are the members of the
[FortisNet organisation](https://github.com/FortisNet) with write access to
this repository. They review and merge changes, make releases and answer
security reports.

## How a change gets in

- Every change arrives as a pull request and must pass the whole pipeline:
  the gate, the release builds, the images and their end-to-end tests.
- A maintainer other than the author reviews it. Changes to what a host
  trusts (the release key, the pinned node release, the update path, the
  workflows that sign or publish) need particular care and are never merged
  on the author's word alone.
- Disagreements are settled by discussion on the pull request or issue. When
  that does not settle it, the maintainers decide.

## Releases and signing

- A numbered release is a tag made by a maintainer on a green `main`
  ([docs/releasing.md](docs/releasing.md)).
- A node release is signed only after a maintainer has looked at what is
  about to be signed and approved it. The signing key is held by GitHub's
  environment `release-signing` and by nobody's computer.

## Becoming a maintainer

Maintainers are added by the existing maintainers, from people whose
contributions have shown care with this kind of code. There is no formal
process yet; ask in an issue.

## Changing this document

By pull request, like everything else.
