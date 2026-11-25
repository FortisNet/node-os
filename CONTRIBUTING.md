# Contributing

Thank you for helping. This repository is the part of a FortisNet node that
runs as administrator on a host, so changes are reviewed with that in mind:
small, explained, and tested.

## Before you start

- For anything larger than a fix, open an issue first and say what you want
  to change and why. It saves work on both sides.
- Security problems do not go in public issues. See [SECURITY.md](SECURITY.md).

## Building and testing

You need Docker, Python 3 and `make`.

```sh
make verify
```

This is the gate. It builds with Clang and GCC, runs every test with both,
then the Clang Static Analyzer, clang-tidy, clang-format and cppcheck. It
takes about three minutes and writes `build-verify/report.json`. A change is
ready for review when every stage passes.

- Do not silence a finding to get through. Fix it, or explain in the pull
  request why the tool is wrong, next to the narrowest possible suppression.
- A change in behaviour comes with a test that fails without it.
- If you change what goes into an image, build it and try it:
  `./image/test-container.sh` runs a container image end to end on your own
  computer.

[docs/development.md](docs/development.md) describes the layout and the
rules the design keeps. Please read "Rules this code keeps" before changing
the orchestrator.

## Style

- C++23. Formatting is decided by `.clang-format`; the gate checks it. The
  files in `lib/` are copies from the node and keep its formatting.
- Prefer standard facilities, ownership through objects, and small
  functions that say what they do. Comments explain why, and what can fail.
- Shell scripts are POSIX `sh` and pass `shellcheck`.
- Documentation is written in plain English, for a reader who is new to the
  project.

## Pull requests

- One subject per pull request.
- Say what changed, why, how you tested it, and what is left undone.
- Commit messages describe the resulting behaviour.
- Never include private keys, credentials, tokens or data from a real host.

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), as the rest of the repository is.
