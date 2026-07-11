# Development velocity review — 2026-07-11

Scope: the ~24 hours ending 2026-07-11 14:42 UTC, plus a forward slice plan.
This is a working note, not a capability claim; nothing here belongs in
`STATUS.md`. Updated later the same day after the pivot's first slice
(`e8cea10`) landed — see "The pivot, and that it worked."

## What shipped in the review window

Merged PRs #29–#33 plus four direct-to-`main` commits (`ce16825`, `db132ea`,
`5fa5c6a`, `19e3fd9`), against #20–#28 in the ~10 hours immediately prior. Unit
of work, almost without exception:

- **One more Win64 API stub**, seeded because a sample demonstrably calls it:
  `GetProcessHeap`, `RtlAllocateHeap`, `GetCurrentThreadId`, `OpenThread`,
  `GetCurrentDirectoryW`, `GetModuleFileNameW`, `SetCurrentDirectoryW`,
  `RtlAddVectoredExceptionHandler`, `GetVersion`, `CreateThread`, `Sleep`,
  `timeGetTime`, `LoadCursorA`, `RegisterClassExA`, `WideCharToMultiByte`.
- **One more child post-mortem leg** in `examples/trace_child_postmortem.rs`
  (now 3,767 lines; rewritten by 1,800+ line diffs several times).
- The CPU-context primitive (#31) and persistent cross-resume watch (#33), which
  are genuine reusable infrastructure.

That is real, disciplined, well-tested clean-room work. The problem was not
quality. It was **direction and cost-per-slice**.

## Efficacy: the treadmill was not moving the milestone

The M3→M4 gate is: **the main thread's poll loop releases and execution proceeds
toward OEP.** Across the whole window that gate did not move. STATUS and the
findings said so in the team's own words (line refs as of the review):

- The main thread spins on `cmp byte [r12],dil`; every `Sleep(1)` returns to the
  same API after 3,527 instructions (`STATUS.md`, "Not yet implemented").
- `CreateThread` records a **runnable-*unscheduled*** thread; `Sleep` elides;
  nothing runs the child (`src/win64.rs:388`, `:743`).
- Most damning — a committed control already tested the obvious fix and refuted
  it: *"A scheduler alone releases the main poll → Not supported… even the
  advanced direct child leaves the next main leg exact and reaches a distinct
  child null"* (`docs/FINDINGS-M3-import-wall.md:3102`, restated at `:3131`).

So there was documented evidence that **advancing the child does not release the
main loop**, and yet ~10 of the window's slices did exactly that — add the next
API the child calls. The child crept ~26k RIPs forward; OEP reportedly needs
~195M instructions. High commit velocity, ~zero milestone velocity.

This is the local-gradient trap. Each API stub is a perfect fit for the
guardrails — bounded, sample-driven, green tests, an artifact, a clean review —
so it always *feels* like the right next step. But the sum was not converging,
because the load-bearing question had been deferred behind the stubs:

> **What does the main thread's poll condition actually require to become true —
> and who, on real Windows, makes it true?** Interleaved child scheduling (not a
> one-shot run), a timer/APC, a vectored-exception callback, or a loader event?

That question was named as "the next bounded question" at
`docs/FINDINGS-M3-import-wall.md:3138` and then not taken up; the following slice
added another API instead.

## Cost-per-slice was inflated and is itself a drag

- **`STATUS.md` rows are 400–800 words each.** STATUS is meant to be a one-line
  index of artifact-backed capabilities; it now reads like a second findings
  doc. Every slice must extend it *and* keep the whole wall internally
  consistent.
- **`docs/FINDINGS-M3-import-wall.md` is 3,156 lines / 162 KB**, append-only, one
  section per API. It is past the point where a new contributor can load the
  frontier quickly.
- **`trace_child_postmortem.rs` is rewritten wholesale** (1,800+ line diffs)
  rather than extended — pure churn, and it hides what actually changed.
- **Two independent max-rigor reviews per no-op stub.** `GetProcessHeap` returns
  a constant handle and drew two maximum-rigor reviews. The working agreement
  says match review depth to risk; in practice every stub got milestone-grade
  scrutiny.
- Mid-window, `ce16825` relaxed the workflow — but the relaxation dropped
  *review* (the last commits went straight to `main`) while the *per-slice bloat
  grew* (`5fa5c6a` = 3,472 lines, `db132ea` = 2,120). We loosened the wrong knob.

## The pivot, and that it worked

The redirection above was executed as `e8cea10` ("M3: identify the poll release
writer"), and it moved the gate that 24 hours of stubs could not:

- It answered the deferred question instead of adding an API. The poll byte is
  set by a **child-thread store immediately after `CreateWindowExA` returns**
  (`mov [r9],r8b`, `R9` = poll cell, `R8B` = 1) — not a timer/APC/VEH/loader
  initializer.
- Sample-agnostic and clean-room: discovered at runtime by selecting the unique
  `cmp r/m8,r8` at the Sleep boundary — sample 1 uses `cmp [r12],dil`, sample 3
  `cmp [rsi],al`; no assumed address or register allocation.
- **North-star went 0 → 64,695 instructions past the poll.** Under a bounded
  treatment (return a diagnostic HWND, let the child run through the store,
  restore the main CPU context), main reads `1` and leaves the Sleep loop for
  the first time, then hits a *distinct, not-yet-classified* null control
  transfer.
- It reconciled the old negative control rather than ignoring it: the earlier
  "scheduler alone doesn't release the poll" child had stopped *before* the
  `CreateWindowExA` return, so it never reached the writer. The picture is now
  coherently **two prerequisites**: a scheduler to run the child in production,
  *and* the window-creation boundary handled.

One focused slice produced the first genuine milestone movement in ~24h. The
plan below carries that forward.

## Working principles (standing)

1. **North-star metric on every run.** Emit **instructions executed past the
   main poll loop** from `run_loader`/postmortem (0 before `e8cea10`). Every
   slice is judged against it. A stub that doesn't move it is reconnaissance,
   labelled as such — not milestone progress.
2. **Batch reconnaissance stubs.** When a post-mortem shows the child needs N
   APIs before the next wall, add them in **one** slice, not N PRs. The stubs
   are individually trivial and mutually independent. One review sized to risk
   per batch; reserve two independent max-rigor reviews for real behavior
   changes (the scheduler, the OEP criterion).
3. **Cut per-slice paperwork.** `STATUS.md` rows → one sentence + artifact link,
   detail pushed to findings; target a capability table readable in one screen.
   Roll resolved findings sections into `FINDINGS-M3-archive.md`, keeping only
   the live frontier active. **Extend** `trace_child_postmortem.rs` additively;
   stop rewriting it (restructure once, deliberately, as its own commit if ever).
4. **Keep the clean-room discipline — it was never the problem.** Sample-driven
   API addition with zero hardcoded constants stays. What changed is *when* and
   *in what batch size* stubs are added, and that they stay subordinate to the
   poll-release / OEP question rather than substituting for it.

## Forward slice plan (M3 completion → M4)

Frontier after `e8cea10`: the poll releases via a child store after
`CreateWindowExA` returns; under a hand-driven diagnostic, main then runs 64,695
instructions past the poll and hits an unclassified null. Production still has
no scheduler — `CreateThread` only records unscheduled threads and the
CPU-context primitive (#31) is unused by any run path. Three slices close the
line to OEP.

### Slice A — Classify the post-release null (diagnostic only; do first)

Apply `e8cea10`'s own move to the new terminal. Is the null at +64,695 (a) a
*second* child-dependent poll/wait (→ real ping-pong interleaving needed),
(b) another missing API/return, or (c) a genuine transfer toward original code
we are mishandling? Extend `trace_child_postmortem.rs`; no production code.

- *Why first:* it decides Slice B's architecture — coarse cooperative yield vs.
  fine-grained interleaving. `e8cea10` ran the child to completion through the
  store, so the required switch granularity is still unknown.
- *Acceptance:* the null is classified with a runtime-derived artifact,
  sample-agnostic across samples 1 and 3. Small.

### Slice B — Minimal production cooperative scheduler + batched child-path stubs

Build the smallest thing that, in a **normal** `run_loader` run (no diagnostic
scaffolding), runs the created thread from its recorded start via a fresh CPU
context (#31), so the main poll releases on its own. **Batch** every stub the
child needs to reach the release store — `CreateWindowExA` (return an HWND),
`RtlFreeHeap`, and whatever Slice A surfaces — into this one slice.

- *Acceptance:* a normal run leaves the Sleep loop; north-star
  `instructions-past-poll > 0` **in production**, not just the diagnostic;
  reproducible on both samples.
- *Ceremony:* dual max-rigor review is warranted — first real behavior change
  since the stubs. Extend the example; don't rewrite it.

### Slice C — Drive to an OEP candidate + define the falsifiable OEP criterion (M4)

With main running past the poll in production, continue under an instruction cap
toward a natural transfer into non-`.themida` code. Define the M4 OEP criterion
(reproducible run-to-run, corroborated by disassembly at the RIP) and resolve
whatever the +64,695 null becomes.

- *Acceptance (per CHARTER M4):* reproducible OEP RIP + register snapshot,
  disasm-corroborated, on sample 1; corroborated on sample 3.

## One-line summary

The window shipped a high volume of correct, well-tested slices the project's
own evidence said could not move the M3 gate; the pivot to characterizing the
poll release (`e8cea10`) moved it in a single slice. Keep the north-star metric,
batch the stubs, cut the paperwork, and drive Slice A → B → C to OEP.
