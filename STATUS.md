# STATUS

This file lists **only** capabilities backed by a reproducing artifact
(a green `cargo test`, a captured CLI invocation, a decodable trace, or a file a
third-party tool can open). No forward-looking or aspirational claims appear
here. If a capability is not listed, it is not implemented.

## Verified capabilities

| Capability | Artifact | Verified |
|---|---|---|
| Crate builds | `cargo build` succeeds; `cargo test` runs (see M0 PR) | M0 |
| PE64 parse + section model (goblin-based): image base, entry point, size-of-image, subsystem, sections; RVA containment / RVA→file-offset | `cargo test pe::` green: parses a synthetic minimal PE64 with asserted fields, serde round-trips, and parses the real Themida sample asserting structural invariants only. Cross-checked against `objdump -p`/`-h` on the sample (image_base `0x140000000`, entry RVA `0x30b058`, 23 sections all match). | M1 |

## Not yet implemented

Everything else in `docs/CHARTER.md`, including: the Unicorn emulation harness,
Win64 environment stubs, OEP detection, trace recording, VM detection, and the
IR lifter. None of these has a passing acceptance artifact yet.
