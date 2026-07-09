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
- **Every PR gets two independent reviews before merge:** an **Opus** review
  (max-rigor prompt) **and** a **GPT-5.5 at xhigh** review
  (`codex exec -m gpt-5.5 -c model_reasoning_effort="xhigh" --sandbox read-only`),
  run concurrently on the checked-out branch. Relay a side-by-side comparison and
  address real findings (fix + re-verify). **The human merges PRs; the assistant
  does not self-merge** — this holds for every PR, doc-only ones included.
- **One slice per PR onto `main`.** Branch, implement, verify locally, open a PR.
  For **code** PRs, CI (build, test, `clippy -D warnings`, no-hype gate) must be
  green before merge. **Doc-only** PRs skip the CI wait — after the two reviews
  above, do a local no-hype check over the changed docs
  (`grep -rnE '🎉|✅|SUCCESS|BREAKTHROUGH|MAJOR|FINALLY' <changed .md files> |
  grep -vF '🎉|✅|SUCCESS|BREAKTHROUGH|MAJOR|FINALLY'` returns nothing) — then it
  is ready for the human to merge.
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

**Current state and frontier:** do not rely on this file for the current
milestone — read `STATUS.md` (verified capabilities) and the newest
`docs/FINDINGS-*.md` (the active frontier and methodology); those are
authoritative and always current. The milestone list and bottom-up layer order
(pe → emu → win64 → oep → trace → vm/detect → ir) are in `docs/CHARTER.md`.
