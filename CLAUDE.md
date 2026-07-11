# midas — project guide for coding agents

midas is a **clean-room Themida VM-analysis toolkit** in Rust, built on Unicorn
CPU emulation. The spec of record is [`docs/CHARTER.md`](docs/CHARTER.md). This
file is the durable working agreement and the resume protocol for any coding
agent. Read it, then follow **Resuming work** below.

This is the canonical project guide. Claude Code loads it directly; other agent
environments should reach it through their repository entrypoint (for example,
`AGENTS.md`). It intentionally points at the live sources of truth (`STATUS.md`,
the findings docs, git history) rather than duplicating state that would go stale.

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

- **Use subagents proactively.** Delegate independent, well-bounded research,
  implementation, review, and diagnostic work whenever parallelism materially
  improves speed or confidence. Prefer native subagent orchestration; delegation
  is not tied to any particular CLI or subprocess. The lead agent may implement
  tiny or tightly coupled work directly and always owns integration, final diff
  review, and local verification.
- **Choose models by task.** When model selection is available, prefer
  `gpt-5.3-codex-spark` for contained implementation or diagnostic tasks with
  explicit acceptance criteria. Keep cross-cutting architecture, ambiguous work,
  integration, and final verification with the lead agent. This is a preference,
  not a gate; model availability must not block progress.
- **Keep changes coherent and reviewable.** Prefer focused branches and PRs, but
  tightly coupled changes may ship together when splitting them would obscure the
  objective or add ceremony without reducing risk.
- **Match review depth to risk.** Every change gets a self-review and relevant
  local verification. Seek an independent review for significant behavior
  changes, security-sensitive work, or milestone-sized changes; use additional
  reviewers when complexity warrants it or the human asks. The unavailability of
  a particular model, tool, or reviewer is not by itself a blocker.
- **Work locally without ceremony.** Creating a branch, editing, testing, and
  making a focused local commit are normal implementation steps and do not need a
  separate checkpoint.
- **Publish and merge within granted authority.** Push, open or update PRs, and
  merge when the human has authorized those external actions explicitly or through
  a standing instruction. Before merging code, CI must be green, including build,
  tests, `clippy -D warnings`, and the no-hype gate. For doc-only changes, run the
  relevant local checks, including the no-hype gate; CI or extra review is needed
  only when the change's risk justifies it.
- **Keep moving with bounded assumptions.** Do not pause merely because several
  reasonable next steps exist. Choose the smallest evidence-producing path and
  state consequential assumptions. Ask the human only when a missing decision
  would materially change scope, acceptance criteria, security, or external
  effects, or when new authority is required.
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
   following the working agreement above. Proceed autonomously with bounded,
   evidence-producing steps; ask only at the material decision points described
   above.

**Current state and frontier:** do not rely on this file for the current
milestone — read `STATUS.md` (verified capabilities) and the newest
`docs/FINDINGS-*.md` (the active frontier and methodology); those are
authoritative and always current. The milestone list and bottom-up layer order
(pe → emu → win64 → oep → trace → vm/detect → ir) are in `docs/CHARTER.md`.
