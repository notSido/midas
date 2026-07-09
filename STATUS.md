# STATUS

This file lists **only** capabilities backed by a reproducing artifact
(a green `cargo test`, a captured CLI invocation, a decodable trace, or a file a
third-party tool can open). No forward-looking or aspirational claims appear
here. If a capability is not listed, it is not implemented.

## Verified capabilities

| Capability | Artifact | Verified |
|---|---|---|
| Crate builds; no analysis implemented yet | `cargo build` succeeds; `cargo test` runs (see M0 PR) | M0 |

## Not yet implemented

Everything else in `docs/CHARTER.md`, including: PE parsing, the Unicorn
emulation harness, Win64 environment stubs, OEP detection, trace recording, VM
detection, and the IR lifter. None of these has a passing acceptance artifact
yet.
