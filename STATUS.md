# STATUS

This file lists **only** capabilities backed by a reproducing artifact
(a green `cargo test`, a captured CLI invocation, a decodable trace, or a file a
third-party tool can open). No forward-looking or aspirational claims appear
here. If a capability is not listed, it is not implemented.

## Verified capabilities

| Capability | Artifact | Verified |
|---|---|---|
| Crate builds | `cargo build` succeeds; `cargo test` runs (see M0 PR) | M0 |
| PE64 parse + section model (goblin-based): image base, entry point, size-of-image, subsystem, sections; RVA containment / RVA→file-offset | `cargo test pe::` green: parses a synthetic minimal PE64 with asserted fields, serde round-trips, and parses the real Themida samples asserting structural invariants only. Cross-checked against `objdump -p`/`-h` on a sample (image_base `0x140000000`, entry RVA `0x30b058`, 23 sections all match). | M1 |
| Unicorn x86-64 emulation harness: create a 64-bit emulator, map stack/TEB/PEB, map code (RX), set GS base, read/write registers and memory, run to a stop address with an instruction cap, and trace executed instruction addresses | `cargo test emu::` green: hand-written arithmetic shellcode runs to a known halt state (RAX=13, RIP=stop addr); push/pop shellcode balances RSP and writes the expected stack bytes; a code hook records the exact instruction addresses executed. | M2 |
| PE-image mapping into the emulator: map headers + each section at its RVA with permissions derived from section characteristics, copying raw bytes | `cargo test emu::map_image` green: a synthetic PE's section bytes land at the correct VA and headers are mapped. | M3 (groundwork) |
| Execution-observation harness: run to an instruction cap and report the stop reason (cap / memory fault with kind+address / invalid instruction), plus final RIP, instruction count, a bounded recent-RIP ring buffer, and a register snapshot | `cargo test emu::run_observed` green: synthetic shellcode faults on a deliberately-unmapped read (reported as ReadUnmapped at the encoded address) and an infinite loop stops exactly at the cap. | M3 (groundwork) |

## Not yet implemented

The Win64 environment itself is **not** implemented: no PEB/TEB module list, no
export/`GetProcAddress` resolution, and no API stubs. `docs/FINDINGS-M3-import-wall.md`
records the reproducible finding (both samples reach an unresolved-kernel32 import
wall ~26–28M instructions in) that justifies and scopes that work; building it is
the remainder of M3.

Also not implemented (per `docs/CHARTER.md`): OEP detection, trace recording, VM
detection, and the IR lifter. None has a passing acceptance artifact yet.
