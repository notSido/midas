# midas — project guide for Claude Code

midas is a **clean-room Themida VM-analysis toolkit** in Rust, built on Unicorn
CPU emulation. The spec of record is [`docs/CHARTER.md`](docs/CHARTER.md). This
file is the durable working agreement and the resume protocol. Read it, then
follow **Resuming work** below.

This file is auto-loaded every session in this repository. It intentionally
points at the live sources of truth (STATUS.md, the findings docs, git history)
rather than duplicating state that would go stale.

## Non-negotiable rules (see docs/CHARTER.md)

- **Clean-room.** Implement only from `docs/CHARTER.md` and verified findings. Do
  NOT read or resurrect the discarded pre-rebuild implementation from git history
  (it was removed for hallucinated assumptions; a safety tag `archive/pre-rebuild`
  may exist locally — do not mine it for code).
- **Verification.** Nothing is "done" / "working" without a committed reproducing
  artifact: a green `cargo test`, a captured CLI invocation, or a decoded trace.
  `STATUS.md` lists ONLY artifact-backed capabilities. No forward-looking or
  aspirational claims anywhere.
- **No hype.** CI greps docs and comments for
  `🎉|✅|SUCCESS|BREAKTHROUGH|MAJOR|FINALLY` and fails on a match. State
  uncertainty plainly ("not yet verified", "hypothesis").

## How we work (working agreement)

- **Delegate implementation to `codex exec`**, one focused slice at a time; then
  independently review the diff and re-run the tests yourself. Never trust a
  self-report — your own `cargo test` / `cargo clippy` run is the verification.
  Invocation: `codex exec --sandbox workspace-write -C <repo> -` (prompt on stdin;
  `codex login status` must show logged in).
- **One slice per PR onto `main`.** Branch, implement, verify locally, open a PR.
  CI (build, test, `clippy -D warnings`, no-hype gate) must be green before merge.
- **The human merges PRs; the assistant does not self-merge.** For larger or
  trickier slices, an Opus and/or GPT-5.5 (`codex exec -m gpt-5.5 -c
  model_reasoning_effort=high`) code review before merge has been useful.
- **Anti-overfitting (important).** The *mechanism* must be sample-agnostic:
  detect at runtime, with zero hardcoded per-sample constants. Windows/API
  behaviour is implemented as *general* semantics and added ONLY when a sample
  demonstrably exercises it (observation-driven, verified on both samples). The
  Themida loader is shared code across same-version samples, so "the sample needs
  API X" is evidence about Themida, not overfitting. Sample-specific addresses
  live only in the findings docs as evidence, never as behaviour in `src`.
- Update `STATUS.md` when a capability gains an artifact; record reproducible
  findings in `docs/FINDINGS-*.md`.

## Environment

- Rust stable via rustup. `unicorn-engine` builds native code: needs `cmake`,
  `clang`/`libclang` (bindgen), and a C toolchain.
- `samples/` is gitignored (only `samples/SAMPLES.md` is tracked). It holds the
  real Themida x64 samples and a `kernel32.dll` used **for its export names only**
  (bitness-independent; midas never maps or runs it). See `samples/SAMPLES.md`.
- Sample-dependent work runs locally (never in CI). Diagnostic example probes:
  `probe_sample`, `trace_resolution`, `watch_peb_teb`, `run_loader` —
  `cargo run --release --example <name> -- samples/<file> [args]`.

## Resuming work

When asked to continue/resume midas, do this first — do not assume prior state:

1. Read `STATUS.md` (what is verified now), `docs/CHARTER.md` (spec + milestone
   list), and the newest `docs/FINDINGS-*.md` (current frontier + methodology).
2. Run `git log --oneline -20` and `gh pr list` for live state (what is merged vs
   an open PR awaiting review/merge).
3. Continue the current milestone from the frontier described in the findings,
   following the working agreement above. For large or ambiguous next steps,
   confirm the plan with the human before building.

**Current milestone:** M3, the `win64` layer — in progress. The exact frontier is
always in `STATUS.md` and the last section of `docs/FINDINGS-M3-import-wall.md`.
The layer order and later milestones (OEP, trace, VM detect, IR lifter) are in
`docs/CHARTER.md`.
