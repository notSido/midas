# midas

A **Themida VM-analysis toolkit** for Linux, written in Rust and built on
Unicorn CPU emulation. midas emulates a protected PE64 far enough to observe
post-OEP execution, records a trace, locates the Themida VM interpreter, and
lifts VM handler bodies to a readable IR.

## Scope

midas is an **analysis toolkit**, not a one-click unpacker.

### What midas does NOT claim

These are open research directions, not promises. None is claimed to work until
an artifact in `STATUS.md` proves it does:

- Reconstructing a working Import Address Table.
- Emitting a runnable, statically-unpacked PE.
- Handling every Themida version/configuration.

## Status

See [`STATUS.md`](STATUS.md). It lists **only** capabilities backed by a
reproducing artifact (a green test, a captured CLI run, a decodable trace). It
contains no forward-looking claims. If a capability is not listed there, it does
not exist yet.

## Project discipline

This repository is a clean-room rebuild under strict anti-hallucination rules,
documented in [`docs/CHARTER.md`](docs/CHARTER.md):

- Nothing is "done" without a committed reproducing artifact.
- `STATUS.md` lists only artifact-backed capabilities; CI asserts this.
- CI fails on unverifiable hype language in docs and comments.

## Building

```sh
cargo build
cargo test
```

Building the `unicorn-engine` dependency requires `cmake` and a C toolchain.

## Samples

Test samples are real Themida-protected binaries. They are **gitignored** and
never committed. See [`samples/SAMPLES.md`](samples/SAMPLES.md) for the metadata
and provenance of each sample.

## License

See [`LICENSE`](LICENSE).
