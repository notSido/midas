# PROJECT CHARTER

## What midas is
A **Themida VM-analysis toolkit** for Linux, in Rust, built on Unicorn CPU
emulation. It emulates a protected PE64 far enough to observe post-OEP
execution, records a trace, locates the Themida VM interpreter, and lifts VM
handler bodies to a readable IR. It is **not** a one-click unpacker and makes no
claim to produce a runnable de-protected binary.

## What midas explicitly does NOT claim (open research, not promises)
- Reconstructing a working Import Address Table.
- Emitting a runnable, statically-unpacked PE.
- Handling every Themida version/configuration.
These may be attempted later; until an artifact proves one works, it stays here.

## Architecture (bottom-up; each layer independently tested)
1. `pe` — PE64 parse + section model (use `goblin`; do not hand-roll header
   parsing). Acceptance: round-trip parse of a known PE, asserted fields.
2. `emu` — Unicorn x86-64 harness: map image, stack, PEB/TEB, run with hooks.
   Acceptance: execute a hand-written shellcode fixture to a known halt state.
3. `win64` — minimal PEB/TEB + the API/syscall stubs actually exercised by the
   samples, added **only when a sample demonstrably calls them** (no speculative
   39-API layer). Each stub has a test asserting its emulated effect.
4. `oep` — reach and **prove** OEP: define OEP detection with a falsifiable
   criterion and emit the RIP + a captured register snapshot. Acceptance: on a
   sample, the reported OEP is reproducible run-to-run and corroborated by
   disassembly at that RIP.
5. `trace` — post-OEP JSONL recorder (typed events; hex-encoded bytes).
   Acceptance: a decode-round-trip test + a real captured trace committed as a
   fixture (truncated).
6. `vm/detect` — locate the VM dispatcher/opcode-fetch and return a descriptor
   (VM_PC offset, handler-table offset) with **zero hardcoded per-sample
   constants**. Acceptance: descriptor for each sample re-confirmed against
   disassembly, not just asserted.
7. `ir` — `Expr`/`Effect` model + iced-x86 lifter + simplifier + concrete
   evaluator + pseudo-C emitter. **Mandatory differential test**: for each
   supported instruction, lift → evaluate → compare register/flag results to an
   independent reference (this is the test the old code lacked, which let a
   double-applied-flag bug survive). Flag effects must be emitted before the
   register write that aliases their operands.

## Test samples (required for M3–M7; provided out-of-band)
- Real Themida 3.x **x64** PE samples live in `samples/` on this machine. They
  are **gitignored** — never commit the binaries. Commit only
  `samples/SAMPLES.md`: for each sample, its filename, `sha256`, the Themida
  version/config it was protected with, and provenance.
- At minimum **one** sample is required to begin M3; **two distinct** samples are
  required to satisfy the "sample-agnostic, zero hardcoded per-sample constants"
  acceptance criterion (you cannot prove generality with one).
- Sample paths available to you: `samples/<NAME-1>.exe` (and `<NAME-2>.exe`).
  [FILL IN the actual filenames before handing off.]
- Sample-free work (M0, M1, M2, and the M7 differential lift→eval unit tests)
  proceeds without them and runs in CI. Sample-dependent acceptance (M3–M7) runs
  **locally**; capture the command + output in the milestone PR — do not add the
  sample to CI.
- **Hard stop:** if you reach the M3→M4 boundary and no sample is present in
  `samples/`, STOP and request it. Do not mock a Themida binary, do not
  synthesize a fake OEP, and do not report any OEP/trace/VM-detection milestone
  as done without a real-sample artifact.
- Any OEP address, VM_PC offset, or handler-table offset you were given as a
  prior finding is a **hypothesis to confirm against disassembly of the sample**,
  never a constant to hardcode.

## Guardrails encoded in the repo
- `STATUS.md` lists only artifact-backed capabilities; CI regenerates/asserts it.
- CI runs `cargo test` + `cargo clippy -D warnings` + a cringe-grep
  (`🎉|✅|SUCCESS|BREAKTHROUGH|MAJOR|FINALLY` in docs/comments) that fails the build.
- Every milestone PR must link its acceptance artifact.

## Appendix — Themida facts to RE-VERIFY (do not trust; confirm against disasm)
These came from prior analysis of two samples and were reportedly hand-checked,
but you must re-confirm them before relying on them:
- Two-layer architecture: a classical `[rbp+X]` VM interpreter (fetch encrypted
  16-bit opcode → rolling-key decrypt → handler-table indirect → `jmp reg`) plus
  a threaded-dispatch layer (`jmp r<reg>` / `ret <var>` sites).
- Reported VM_PC / handler-table offsets — sample A: `rbp+0x9a` / `rbp+0x26`;
  sample B: `rbp+0x15c`/`+0x58`. Treat as leads; derive them yourself.
- Reported blocker: both samples crash post-OEP on unresolved imports (IAT holds
  original Import-Name-Table string pointers, not resolved addresses). Confirm
  before designing around it.
- OEP reaching one sample reportedly needs ~195M emulated instructions — budget
  the instruction cap accordingly, but verify.
