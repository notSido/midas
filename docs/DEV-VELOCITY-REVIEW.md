# Development velocity review — 2026-07-11

Scope: the ~24 hours ending 2026-07-11 14:42 UTC. This is a working note, not a
capability claim; nothing here belongs in `STATUS.md`.

## What actually shipped in the window

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

That is real, disciplined, well-tested clean-room work. The problem is not
quality. It is **direction and cost-per-slice**.

## Efficacy: the treadmill is provably not moving the milestone

The M3→M4 gate is: **the main thread's poll loop releases and execution proceeds
toward OEP.** After 24 hours of slices, that gate is exactly where it started.
STATUS and the findings say so in the team's own words:

- The main thread spins on `cmp byte [r12],dil`; every `Sleep(1)` returns to the
  same API after 3,527 instructions (`STATUS.md`, "Not yet implemented").
- `CreateThread` records a **runnable-*unscheduled*** thread; `Sleep` elides;
  nothing runs the child (`src/win64.rs:388`, `:743`).
- Most damning — a committed control already tested the obvious fix and refuted
  it: *"A scheduler alone releases the main poll → Not supported… even the
  advanced direct child leaves the next main leg exact and reaches a distinct
  child null"* (`docs/FINDINGS-M3-import-wall.md:3102`, restated at `:3131`).

So we have documented evidence that **advancing the child does not release the
main loop**, and yet ~10 of the window's slices did exactly that — add the next
API the child calls. The child crept ~26k RIPs forward; OEP reportedly needs
~195M instructions. High commit velocity, ~zero milestone velocity.

This is the local-gradient trap. Each API stub is a perfect fit for the
guardrails — bounded, sample-driven, green tests, an artifact, a clean review —
so it always *feels* like the right next step. But the sum is not converging,
because the load-bearing question has been deferred behind the stubs:

> **What does the main thread's poll condition actually require to become true —
> and who, on real Windows, makes it true?** Interleaved child scheduling (not a
> one-shot run), a timer/APC, a vectored-exception callback, or a loader event?

That question is named as "the next bounded question" at
`docs/FINDINGS-M3-import-wall.md:3138` and then not taken up; the following slice
added another API instead.

## Cost-per-slice is inflated and is itself a drag

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
  says match review depth to risk; in practice every stub gets milestone-grade
  scrutiny.
- Mid-window, `ce16825` relaxed the workflow — but the relaxation dropped
  *review* (the last commits went straight to `main`) while the *per-slice bloat
  grew* (`5fa5c6a` = 3,472 lines, `db132ea` = 2,120). We loosened the wrong knob.

## Plan to move faster

### 1. Pivot from "advance the child" to "characterize the poll release" (highest leverage)
Stop adding the next child-called API as a reflex. Instead, spend the next
session answering the deferred question directly:
- Identify the exact producer of the poll byte at `[r12]` on a real run: watch
  that cell for its writer across the *whole* run (the persistent-watch
  infrastructure from #33 already does this), and classify the writer — child
  thread store, timer/APC, VEH callback, or loader.
- That classification decides the milestone path. If it's the child thread, the
  need is **interleaved cooperative scheduling** (run child, yield on its poll,
  resume main), not the one-shot direct run the control already refuted. Build
  the minimal scheduler on top of the CPU-context primitive (#31) that is
  already in place for exactly this.
- Acceptance for the slice: the main poll loop releases and the run advances past
  the Sleep loop into new code — measured in *instructions past the loop*, not
  "which API call number."

### 2. Make the north-star metric visible on every run
Add one number to the `run_loader`/postmortem output: **instructions executed
past the main poll loop** (0 today). Every slice is judged against it. An API
stub that doesn't move it is reconnaissance, labelled as such — not milestone
progress.

### 3. Batch reconnaissance stubs; reserve ceremony for behavior changes
- When a post-mortem shows the child needs N APIs before the next wall, add them
  in **one** slice, not N PRs. The stubs are individually trivial and mutually
  independent.
- One review, sized to risk, for a batch of stubs. Two independent max-rigor
  reviews are for the scheduler and other real behavior changes.

### 4. Put STATUS on a diet; stop rewriting the example
- `STATUS.md` rows → one sentence + artifact link. Push the caveats/detail into
  findings. Target: the whole capability table readable in one screen.
- Cap or roll the findings doc (archive resolved sections to
  `FINDINGS-M3-archive.md`); keep only the live frontier in the active file.
- **Extend** `trace_child_postmortem.rs` with additive functions; stop
  rewriting it. If it must be restructured, do it once, deliberately, as its own
  commit.

### 5. Keep the clean-room discipline — it is not the problem
Sample-driven API addition with zero hardcoded constants is correct and should
continue. The change is *when* and *in what batch size* we add them, and making
sure they are subordinate to the poll-release question rather than a substitute
for it.

## One-line summary
We are shipping a high volume of correct, well-tested slices that the project's
own evidence says cannot move the M3 gate. Redirect the next session at the poll
release condition, batch the stubs, and cut the per-slice paperwork.
