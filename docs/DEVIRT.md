# Devirtualization — plan & progress

The unpacker (main pipeline) reaches OEP on both `samples/` entries but
execution lands on Themida-VM-mutated micro-ops, not the original
program. The `devirt` subsystem, in-tree under `src/devirt/`, is a
pure-Rust analysis pipeline that turns the VM execution back into
readable code.

## Ground rules

- **Pure Rust, in-tree.** No Triton, no miasm, no z3/boolector C++
  bindings. If we need a SAT/SMT solver later, use `varisat`
  (pure-Rust SAT); defer until an algebraic simplifier proves
  insufficient.
- **Dev branch: `dev`.** Main stays at the "unpacker reaches OEP"
  checkpoint.
- **Commit at every milestone slice.** Each commit should compile,
  pass its own tests, and describe the *why* not just the *what*.
- **Both `samples/` must keep passing.** Each milestone has to run
  against both sample files. "Works on sample X" is not progress.

## Milestones

The devirt pipeline decomposes into eight milestones. Near-term stops
(M0–M4) yield a research-grade analysis of the VM. M5–M7 are where we'd
reconstruct readable original code — realistically several days of work
each against a commercial packer like Themida 3.x.

| M   | What                         | Status | Commit     |
| --- | ---------------------------- | ------ | ---------- |
| M0  | Per-instruction trace (JSONL, armed at OEP) | ✅ done | `16094ba`, `70ded59` |
| M1  | VM dispatcher candidate finder (offline trace analysis) | ✅ done | `a3fc9ce` |
| M2  | Handler discovery, basic-block cluster & dedup | ✅ done | `2dab0b4` |
| M3  | IR (`Expr` + `Effect`) + iced-x86 → IR lifter | ✅ done — all GPR widths, ZF/SF flags, cmp/test, je/jne/js/jns, unconditional jmp, push/pop/inc/dec/lea/movzx. 99.9% on sample 2 top handler |            |
| M4  | Per-handler semantics via simplification | ☐ required for semantic dedup (RIP-seq too strict) | |
| M5  | VM bytecode stream lifter (stretch)        | ☐      |            |
| M6  | IR simplifier — constant fold + algebraic peephole | ☐ |            |
| M7  | Output emitter — pseudo-C / lifted x86     | ☐      |            |
| M8  | (If ever needed) `varisat` SAT for predicate resolution | ☐ |            |

## Module layout

```
src/devirt/
  mod.rs            public entry points
  trace.rs          TraceBuilder (M0) — JSONL recorder, armed at OEP
  trace_events.rs   Event enum: OepReached, Exec, …
  vm/
    regions.rs      dispatcher candidate finder (M1)
    handlers.rs     handler discovery, clustering, hashing (M2)
    bytecode.rs     VM bytecode stream reader (M5)
  ir/
    expr.rs         Expr AST + RegId/MemCell (M3)
    lifter.rs       iced-x86 Instruction → Expr (M3)
    simplify.rs     constant fold + algebraic peephole (M6)
    emit.rs         IR → pseudo-C or lifted x86 (M7)
  semantics.rs      per-handler input/output effects (M4)

src/bin/analyze-trace.rs     offline trace analyzer CLI (M1)
```

Directories under `vm/`, `ir/` that don't exist yet will be created as
their milestone starts.

## End-to-end usage (today, M0+M1 wired)

```sh
# Produce a post-OEP execution trace:
midas \
  --input samples/4e26b769...exe \
  --output /tmp/s1_unpacked.exe \
  --devirt-trace /tmp/s1.trace.jsonl \
  --devirt-trace-limit 1000000

# Analyze it offline (no Unicorn needed):
analyze-trace --input /tmp/s1.trace.jsonl --top 10 --successors-per-candidate 16
```

Reaching OEP on sample 1 needs ~195M instructions, so the default
`--max-instructions` is 500M. Pass a smaller value if you want a
faster fail.

## What each milestone produces

- **M0** — A JSONL trace, one event per line, starting with an
  `OepReached` marker and continuing with `Exec` events up to the
  configured limit. Cheap to read; adding new event types (mem r/w,
  reg delta) is a tagged-enum variant away.

- **M1** — `TraceAnalysis::dispatcher_candidates(n)` returns a ranked
  list of `{rip, fan_out, exec_count, successors[]}`. The top entry
  is the best guess at the VM dispatcher's indirect-branch
  instruction; its successors are candidate handler entry points.

- **M2** — For each handler entry from M1, extract the basic block(s)
  up to the next jump back to the dispatcher. Hash each block's
  `(mnemonic, reg-role)` sequence to dedupe equivalent variants.
  Output: a small set of unique handler addresses and their basic
  blocks.

- **M3** — An `Expr` AST covering `Const`, `Reg`, `MemLoad`, and
  arithmetic/bitwise/shift binops. A lifter that consumes an
  `iced_x86::Instruction` and emits `Vec<Effect>` (`SetReg` /
  `MemStore`). Scope: the ~20 mnemonics Themida handlers actually
  use (`mov`, `add`, `sub`, `xor`, `and`, `or`, `shl`, `shr`, `not`,
  `neg`, `inc`, `dec`, `push`, `pop`, `lea`, `cmp`, conditional
  jumps, `call`, `ret`, `jmp`).

- **M4** — Per-handler semantic signature: input registers/memory →
  output registers/memory, as a post-simplification
  `Vec<Effect>`. Two handlers that look different textually but
  have the same semantics collapse to one.

- **M5 / M6 / M7** — Walk the VM bytecode stream from a known
  interpreter state, emit per-opcode lifted IR, simplify, and
  serialize. This is where "original code" comes out the other end.

## MAJOR FINDING — the prior "dispatcher" is a helper trampoline (M5 recon)

Revises, again, the earlier M1/M2 conclusion. Empirical disassembly
of sample 2's hot regions at OEP (using a new `analyze-trace
--dump-region-start/--dump-region-end` subcommand) shows the
following:

- **`0x14105b029` is `ret 0` — not a VM dispatcher.** The block from
  `0x14105aecc .. 0x14105b029` is a shared trampoline reached via
  `call 0x1410aa300 → jmp 0x14105aecc`. Its behaviour: push all 15
  GPRs, mutate `dword ptr [rbp+0xDA]` and `dword ptr [rbp+0x1D2]`
  with fixed AND/OR/SUB/XOR masks, pop all 15 GPRs, `ret`. The
  `ret` returns to the *instruction after the original call*,
  continuing the caller's handler body. This is an integrity/
  anti-tamper helper, not a dispatcher. Fan-out 13 observed at
  `0x14105b029` = 13 distinct `call 0x1410aa300` sites in the
  trace.

- **M2's "handler catalog" is mislabelled.** Segmentation at
  `0x14105b029` actually cuts a single VM handler into multiple
  sub-segments at every helper call. The 4183-instruction "top
  handler" includes the helper's own 111-instruction body; the
  apparent 986 unique handlers reflect caller-site variation, not
  13 VM opcodes. **Do not treat the M2 catalog as VM handlers.**

- **The real VM interpreter exists at `0x141048839`.** Canonical
  Themida opcode-fetch+dispatch:
  ```
  mov r11, [rbp+0x9A]                ; VM_PC
  movzx r11, word ptr [r11+4]        ; fetch encrypted opcode
  sub   r11d, [rbp+0xD4]             ; decrypt with rolling key
  sub   r11d, 0x11B4411F             ; constant part of decrypt
  xor   [rbp+0xD4], r11d             ; advance rolling key
  and   r11, 0xFFFF                  ; mask opcode to 16 bits
  shl   r11, 3                       ; handler index * 8
  mov   r10, [[rbp+0x26] + r11]      ; handler_table[opcode]
  ; then a VM_PC advance...
  mov   rbx, [rbp+0x9A]
  movsxd r9, [rbx]                   ; signed delta from bytecode
  add   [rbp+0x9A], r9               ; VM_PC += delta
  jmp   r10                          ; to the handler
  ```
  VM state lives at the following `[rbp + ...]` offsets:
  - `+0x9A` — VM_PC (pointer into bytecode stream)
  - `+0x26` — handler-table base pointer
  - `+0xD4` — rolling decryption key

  This matches classical Themida VM architecture. Confirmed.

- **But this interpreter fires only 3 times in the 10M-event
  trace.** Meaning: the VM-protected region of the program is
  *small*. The dominant execution layer is **threaded dispatch**
  — dozens of `jmp r<reg>` and `ret 0` sites with fan-out 13–39
  each, scattered throughout the binary. The handler pool for
  those threaded dispatches lives around `0x141048a05 ..
  0x14104bf31`, a sparse jump-table of 5-byte `jmp rel32`
  instructions that re-target into real handler bodies elsewhere
  in the image.

- **Practical implication for Deliverable B.** Applying classical
  M5 (locate VM_PC, walk bytecode, substitute handler semantics)
  produces a very small cleaned-up region — only the 3-hit VM
  slice. The vast majority of the code reached by the trace is
  *not* VM-protected; it is *control-flow-obfuscated* by threaded
  dispatch + instruction mutation. The non-VM-native
  deobfuscation pass (item 5 on HANDOFF's numbered path) is
  therefore the bigger lever — and arguably the M5 work should be
  re-scoped. See the open question logged in HANDOFF's "when to
  check in" list.

## Sample 1 recon — the VM *is* the dominant layer

Same `--dump-region` analysis on `s1_check.jsonl` (1.73M post-OEP
events, OEP 0x140eb084e):

- **Top-5 dispatcher candidates are all `jmp r<reg>`.** Same
  threaded-dispatch pattern as sample 2. Fan-outs 9–16, exec
  counts 76–625. Top candidate: `0x140e9b848 jmp r8`.

- **The real VM interpreter is at `0x140f82a80 ..`.** Canonical
  pattern, heavily mutated but unmistakable:
  ```
  ; load VM_PC from [rbp + 0x15C]
  mov r12, rbp
  add r12, 0x15C
  movzx r12, word ptr [r12]      ; fetch 16-bit opcode at VM_PC
  add   r12w, 0x7F90              ; 16-bit decrypt
  ; aux state dereference via [rbp + 0x58]
  mov r8, rbp
  add r8, 0x58
  mov r8, [r8]
  ...
  (further mutation + handler-table lookup + dispatch)
  ```
  VM state offsets:
  - `+0x15C` — VM_PC
  - `+0x15F` — adjacent slot (possibly a 3-byte-packed sub-field)
  - `+0x58`  — secondary state (handler-table-related)

- **Critical quantitative difference from sample 2.** In the
  1.73M-event trace, the VM interpreter region (0x140f82a80 ..
  0x140f82c00 — ~256 bytes) saw roughly **20,000 hits across
  71 unique RIPs**. Compared to sample 2's 3-hit slice, the VM
  on sample 1 is actively driving execution — dispatching many
  hundreds of VM opcodes across the recorded trace window.

### Sample 1 vs sample 2 summary

| Aspect                        | Sample 1          | Sample 2             |
| ----------------------------- | ----------------- | -------------------- |
| VM interpreter entry          | 0x140f82a80       | 0x141048839          |
| VM_PC                         | `[rbp+0x15C]`     | `[rbp+0x9A]`         |
| Aux state                     | `+0x58, +0x15F`   | `+0x26, +0xD4`       |
| Decryption                    | `add r12w, 0x7F90` | `sub+sub+xor rolling` |
| VM fire count (10M / 1.73M)  | ~20,000 hits      | 3 hits               |
| Threaded-dispatch presence    | yes, dozens       | yes, dozens          |
| Dominant execution layer      | **VM**            | **threaded dispatch**|

### Strategic implication

The two samples require different primary strategies.

- **Sample 1.** Classical M5 is the right big lever: a bytecode-
  stream lifter walking from the VM_PC at OEP, substituting
  lifted handler semantics, producing a reconstructed native
  program. The VM is active and observable.

- **Sample 2.** Non-VM native deobfuscation (HANDOFF item 5) on
  the threaded-dispatch layer is the bigger lever. M5 on sample 2
  would clean up a tiny tail-called VM slice only.

- **Shared infrastructure.** Both approaches use the same lifter
  + simplifier pipeline on lifted IR. Building M5 for sample 1
  gives us the bytecode-walker and handler-effect composer; we
  can apply the handler-effect piece to sample 2's 3-hit slice
  essentially for free.

Recommended ordering for Deliverable B:

1. Build M5 as a general tool using **sample 1** as the testbed
   (VM is active, ground truth easy to validate).
2. Apply M5 to sample 2 as-is — produces a small cleaned region.
3. Build the non-VM native deobfuscation pass for sample 2's
   threaded-dispatch layer — reuses the same lifter + simplifier
   infrastructure on static basic blocks from the OEP dump.

Open scope negotiations with the user before committing to
either (1) or (3); both are multi-day pieces of work.

## Earlier finding — sample 2 *is* VM'd; 2M events was too short

**Retraction of earlier finding.** An earlier version of this doc
concluded from 2M-event traces that neither sample was running a
VM interpreter at OEP. That was wrong, and specifically wrong
because 2M events was too short a window. Leaving this retraction
in place so future readers see the mistake.

At **10M events**, sample 2 reveals a genuine VM dispatcher:

- Dispatcher tail: `0x14105b029`, **fan-out 13, exec_count 1317**.
  (At 2M events: fan-out 4, exec_count 7 — super-linear scaling
  once we cross a threshold.)
- Dispatcher body appears to be the contiguous block
  `0x14105aecc – 0x14105aed5` + `0x14105b029`, all at exec=1317,
  all fan-out 1 except the tail. That's the tight ~10-insn loop we
  expected from a VM interpreter.
- 1316 handler invocations segmented from the trace. 986 unique
  RIP-sequence signatures, average handler length ≈ 7600 native
  instructions.

That last figure — 7600 native insns per VM op — is large, not the
classic 30–50 insn handler. Two readings, both plausible:

1. **Themida mutates the VM handlers themselves.** Each handler
   runs a few semantically-meaningful ops wrapped in heavy junk
   (xor-zero chains, push/pop pairs, dead branches).
2. **Multi-level dispatch.** The `0x14105b029` branch picks one of
   13 *handler classes*; inside each class there may be a nested
   finer-grained dispatch we haven't located. The fan-out table
   shows other indirect branches (e.g. `0x14112463f` with fan-out
   39, exec=166) that could be the inner dispatchers.

The 986-unique-from-1316-invocations ratio also tells us
**RIP-sequence equality is too strict for semantic dedup**:
multiple handler invocations share the same entry RIP
(e.g. `0x141113557` appears as rows 2, 3, 5, 6 in the top-20 with
four distinct signatures) but differ in internal control flow
based on data. Real semantic dedup requires M3-level lifting
followed by M4 simplification.

**Both samples halt at a post-OEP fake-import crash.** Sample 1
stops with `INSN_INVALID at 0x16f08b` (1.73M post-OEP events in);
sample 2 stops with `INSN_INVALID at 0x1038083` (15.4M post-OEP
events in). Diagnostic (implemented in `unpacker.rs` — dumps
bytes at the crash RIP on error exit) shows the bytes are ASCII:

- sample 1 @ 0x6f08b: `"ateDeviceAndSwap\0"` — part of
  `D3D10CreateDeviceAndSwapChain`.
- sample 2 @ 0x1038083: `"aceIcon\0MPR.dll\0"` — part of
  `ExtractAssociatedIconA` plus the DLL name `MPR.dll`.

The programs are calling imports through the IAT, and the IAT
entries still hold their *original* values — pointers to the
Import-Name-Table strings inside the PE — rather than resolved
function addresses. Themida's unpack-phase IAT reconstruction did
not produce usable pointers in our emulator because our fake
`LoadLibrary` / `GetProcAddress` / PEB-LDR don't return values
that Themida's manual export-walk resolver accepts.

**Fix needed:** Speakeasy-style decoy DLLs with real export tables,
mapped into the emulator and hooked into the PEB's
`InLoadOrderModuleList`. Non-trivial scope — probably a day of
work for a minimal kernel32+user32+ntdll+d3d10 stub set. Tracked
as task #10 but deferred.

**Workaround for now:** both samples produce enough post-OEP
events (sample 1: 1.73M; sample 2: 15.4M at the 50M attempt) to
drive M3 IR lifting on the handler bodies we already have. We are
not blocked on devirt progress; we are blocked on full sample-1
coverage.

**Defensive fix that landed.** `unpacker.rs` now installs a
MEM_WRITE hook on the image_base range that mirrors writes into
the low-mem RVA mirror (see the `Mirror-sync hook` comment).
This does not fix the observed INSN_INVALID crashes but prevents
a separate, latent class of "bare-RVA read after image_base
write" bugs from producing wrong data. Mirror-sync writes counted
during a run (logged post-emulation) — 17.8M for sample 1, 7.9M
for sample 2 — so the hook fires heavily during the unpack phase.

Revised strategic fork (decision after diagnostic work):

1. **Push to M3 on sample 2.** Lift handler bodies to IR,
   simplify away junk ops, attempt semantic dedup. Concrete and
   testable on the 15.4M-event sample 2 trace we already have.
   Chosen path.
2. **Fix the fake-import crash (decoy DLLs).** Required for full
   sample 1 coverage and for eventually running either sample
   past the post-OEP fake-import call. Deferred to a dedicated
   session — scope is a day of work, not an afternoon.
3. **Longer trace confirmation (c).** Done — 15.4M-event run
   confirmed `0x14105b029` (fan_out 13, exec 2085, scales
   linearly) and surfaced a layer of **second-tier indirect
   branches** (`0x14112463f` etc. at fan_out 31-41, lower exec)
   suggesting a two-level VM.

## M3 lift coverage (sample 2, after M3.5 + follow-up)

After M3.5 (partial-register writes, ZF/SF, cmp/test, jcc, jmp) and
the follow-up adding `push`/`pop`/`inc`/`dec`/`lea`/`movzx`, whole-
handler coverage on sample 2's dispatcher `0x14105b029`:

| Handler | Entry         | Length | Fires | Lifted    | Coverage  |
| ------- | ------------- | ------ | ----- | --------- | --------- |
| #0      | 0x1411d6656   | 4183   | 34    | 4179/4183 | **99.90%** |
| #1      | 0x141113557   | 1892   | 22    | 1890/1892 | 99.89%    |
| #2      | 0x141113557   | 2049   | 22    | 2045/2049 | 99.80%    |

(Measured on a fresh 10M-event trace post-commit.)

The remaining four-ish unsupported instructions per handler are
all architecturally distinct features outside M3's stated scope:

- `jbe` — needs CF modelling (compares via `CF | ZF`). We emit
  ZF but not CF; deferred alongside `ja/jae/jb` until there's a
  reason.
- `pushfq` — push RFLAGS. Would require a full-flags composite
  value; niche use inside handlers.
- `call <addr>` — control-flow + implicit stack push. One per
  handler, always the same outer-dispatcher helper
  (`0x1410aa300`), pointing to the second-tier dispatcher area
  from M1 findings.

Representative real-payload excerpt, now fully lifted:

```
mov r11b, [rbx]          ← narrow mem load → blend into R11
sub r11b, 0EEh           ← narrow arithmetic → blend + ZF/SF set
or r9, rsi               ← junk write (dead — M6 will eliminate)
xor rcx, rbx             ← junk
xor rcx, rbx             ← cancels — M6 `x xor y xor y = x`
sub r11b, 50h            ← decrypt step
sub r11b, 0A8h           ← decrypt step
cmp r11b, 0              ← SetFlag(ZF, Eq(R11 & 0xff, 0))
jne <fail>               ← Branch { cond: Eq(Flag(ZF), 0), target }
```

Both `cmp` and `jne` now lift. The simplifier (M6) will forward-
propagate the flag-defining `Eq` through the branch condition and
collapse the junk arithmetic.

## Empirical observations (after M1, 2M-event traces)

Validated against both samples with a 2M-event post-OEP trace:

- **sample 1** (OEP `0x140eb084e`): trace ran 1.73M events before
  the emulator returned (unmapped access during a late runtime call,
  non-fatal because OEP was already captured). Top dispatcher
  candidate `0x140e9b848`, fan-out 16, exec count 339.
- **sample 2** (OEP `0x14125d930`): trace hit the 2M limit cleanly.
  Top candidate `0x1410eb7dd`, fan-out 19, exec count 35. Top five
  candidates all have fan-out 15–19 with heavily overlapping
  successor sets.

Takeaways that should shape M2 / M3 heuristics:

1. **Dispatcher ≠ hottest code.** The highest-exec-count addresses
   are usually tight straight-line hot blocks (contiguous insns,
   all exec=N, fan-out=1) — likely decompression or memcpy-type
   loops, not the VM. The VM dispatcher shows up with *moderate*
   exec count and *high* fan-out. The M1 ordering (fan-out first,
   exec-count tiebreak) is the right heuristic; don't "improve" it
   by weighting toward exec count.
2. **Top candidates share handlers.** Several top-ranked candidates
   emit to the same successor set. They are likely separate entry
   points into the same dispatcher, or a chain of indirect branches
   inside the VM runtime, not N distinct dispatchers. M2's handler
   clustering needs to group these candidates before deduplicating
   handlers.
3. **Traces saturate at ~2M events quickly.** 2M events ≈ 17 sec on
   the current mutex-per-insn recorder. Above that the recorder
   itself becomes the bottleneck. For M4+ we will probably want a
   binary trace format or sampled recording.

## Known gaps / future work

- **Trace recording is slow.** Each post-OEP instruction takes a
  mutex lock and writes a JSON line. Acceptable for traces up to a
  few million events; above that we want a binary trace format.
- **Register snapshots.** M0 only captures `rip` + instruction
  bytes — no register state. M3/M4 can mostly work from bytes +
  iced-x86, but memory effects need addresses. Adding a `RegDelta`
  event variant is on the list for early M3.
- **No unpack-phase trace.** Trace recorder is disarmed before OEP
  by design. If we ever need to analyze the decompression loop
  itself, we'd need a second, cheaper recorder mode.
- **Analyzer is trace-flat, not instruction-aware.** M1 doesn't
  know what an instruction *is* — it just uses trace-successor
  fan-out. A conditional branch with two taken-directions looks
  like fan-out too. Intentional: M3 gives us instruction-level
  refinement later. M1 is first-filter only.

## Things outside the scope of this project

We are **not** aiming for a fully reconstructed, executable,
devirtualized PE. That is a months-long research effort for a
skilled reverser on a commercial packer. We aim for:

- A clean trace and toolchain.
- Identification of the VM structure (dispatcher, handlers).
- Lifted IR per handler.
- Enough artifacts to inform further manual analysis.

If we get more than that, great — but M4 is the realistic finish
line for a few-session engagement.

## Why pure Rust

Triton / miasm are excellent, but adopting them means either
shelling out to Python from Rust (slow, ugly interop) or
rewriting large parts of midas in Python. In-tree pure Rust
keeps build/test/deploy simple and keeps the whole pipeline
visible in one `cargo build`.

## Session handoff

If you're a future session starting fresh:

1. Read this file (`docs/DEVIRT.md`) and the memory entry
   *"Devirt plan and status"*.
2. `git log dev` — the per-milestone commits carry detailed notes
   in their bodies.
3. Run both `samples/` through the current `midas` with
   `--devirt-trace` to reproduce today's artifacts before changing
   anything.
4. The repo-root memory file
   `/Users/sido/.claude/projects/-Users-sido-midas/memory/` has
   the current feedback/project guidance.
