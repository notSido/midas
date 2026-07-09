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
| Windowed detailed trace (`run_traced`) and full-run memory-range watch (`run_watching`): interleaved instruction + memory-access events over a window, and access logging within given address ranges over a full run | `cargo test emu::run_traced`/`run_watching` green: a synthetic write/read window is captured with correct values; a watched stack range records the expected read and write with plausible RIP. | M3 (groundwork) |
| Minimal TEB/PEB population: TEB `NtTib.Self`, `StackBase`/`StackLimit`, `TEB.ProcessEnvironmentBlock`, `PEB.BeingDebugged`, and `PEB.ImageBaseAddress` (set on image map) — justified by both samples reading `gs:[0x30]` | `cargo test emu::` green: `new()` populates the TEB self-pointer, PEB pointer, and stack bounds (GS_BASE = TEB_BASE); `map_image` sets `PEB.ImageBaseAddress`. | M3 (groundwork) |
| Import-call trap + `GetModuleHandleA`: run the loader, and on a fetch-fault at an unbound IAT thunk (an image RVA landing on a valid `IMAGE_IMPORT_BY_NAME`), resolve the function name from the PE's import table, emulate the API, set `RAX`, return to the on-stack address, and continue (`emu::Emu::resume` enables the fault-and-resume loop) | `cargo test win64::` green: import-by-name resolution from a synthetic image; `GetModuleHandleA` returns a non-null base and performs the return; end-to-end trap handles a synthetic unbound-import call. | M3 |
| Synthetic kernel32 module + export-call trap: `GetModuleHandleA("kernel32.dll")` maps a minimal synthetic PE32+ with a real export directory (seeded export names); the loader's manual export walk resolves a function, and a call to a resolved export stub is trapped and dispatched by export name (`GetModuleHandleA(NULL)` returns the process image base) | `cargo test win64::` green: the synthetic kernel32 is parseable via guest reads (MZ/e_lfanew/`PE`/export names), `GetModuleHandleA` exposes `[base+0x3c]`, stub addresses reverse-map to export names, and the trap reports an unimplemented export call by name. | M3 |

## Not yet implemented

The Win64 environment is only **partially** implemented: the import-call trap,
`GetModuleHandleA`, and the synthetic kernel32 module + export-call trap exist
(above). What remains for the win64 layer: readable-but-non-executable export
stubs (so the loader's inspection of a resolved function's bytes succeeds while a
call still traps), seeding the export names from the real `samples/kernel32.dll`
for complete resolution, and the actual API stubs the loader calls next
(`LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, …), each added when observed.
`docs/FINDINGS-M3-import-wall.md` records the reproducible chain and the current
frontier (after `GetModuleHandleA` the loader parses the synthetic export table
and reads a resolved function's bytes).

Also not implemented (per `docs/CHARTER.md`): OEP detection, trace recording, VM
detection, and the IR lifter. None has a passing acceptance artifact yet.
