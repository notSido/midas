# M3 groundwork finding: the pre-OEP import-resolution wall

Status: **observation, reproducible**. Interpretations below are labelled; items
marked *hypothesis* are not yet proven and must be confirmed before code relies
on them.

## How to reproduce

```
cargo build --release --example probe_sample
./target/release/examples/probe_sample samples/<sample>.exe <instruction-cap>
```

The probe parses the PE (`pe` layer), maps the full image into the Unicorn
harness (`emu::Emu::map_image`), sets RIP to the PE entry point, and runs with
`emu::Emu::run_observed`, which records instruction count, a bounded ring buffer
of recent RIPs, a register snapshot, and the first unmapped/again-faulting
memory access. The example disassembles the recent (decrypted) instruction
stream out of guest memory with `iced-x86` and dumps register-pointed memory.

The samples are gitignored; see `samples/SAMPLES.md`. This finding is a captured
CLI artifact, not a committed test (the run is long and sample-dependent).

## Observation (both samples, Themida 3.2.4.34 demo)

Run from the PE entry point, both samples execute a long self-contained
decryption/decompression phase with **no dependency on the emulated environment**
(no unmapped data reads, no API calls) and then transfer control to an unmapped
address:

| | `test_target_protected.exe` | `test_target2_protected.exe` |
|---|---|---|
| Entry VA | `0x14030b058` | `0x14033d058` |
| Instructions until the wall | 26,519,612 | 28,228,274 |
| Fault | fetch-unmapped `0x000000000004d00d` | fetch-unmapped `0x000000000004d00d` |
| Transfer site (`.themida` RVA) | `+0x5cb7c` | `+0x4f884` |
| `RAX`/`RCX` at fault point to | ASCII `"kernel32.dll\0"` | ASCII `"kernel32.dll\0"` |
| `RBX` at fault | `0x4d080` | `0x4d080` |

The last decrypted instructions before the fault are identical in structure in
both samples — a full context-restore trampoline:

```
  pop r8 ; pop r9 ; pop r10 ; pop r11 ; pop r12 ; pop r13 ; pop r14 ; pop r15
  pop rdi ; pop rsi ; pop rbp ; pop rbx ; pop rdx ; pop rcx ; pop rax
  popf
  ret 0
```

i.e. the loader restores a saved register context (`popf` + pop of all GPRs) and
`ret`s. The `ret` pops a target address off the stack and jumps to it; that
target is `0x4d00d`, which is not mapped, so emulation stops.

## What is shared vs per-instance

- **Shared (loader structure):** the trampoline shape, the fault target
  `0x4d00d`, `RBX = 0x4d080`, and the fact that `RAX`/`RCX` reference the string
  `"kernel32.dll"`. These are properties of the Themida 3.2.4.34 loader, not of
  either payload — they match across two independently-protected binaries.
- **Per-instance:** the transfer-site RVA (`+0x5cb7c` vs `+0x4f884`), the string
  pointer address (`0x1400cc25b` vs `0x1400fc71a`), the instruction count to
  reach the wall, and the exact stack contents.

The shared constants (`0x4d00d`, `0x4d080`) are **not** to be hardcoded as
sample constants; they are recorded here only as evidence that the mechanism is
uniform. Any address midas acts on must be derived at runtime.

## Interpretation

The loader has finished unpacking its own code and has reached its **Windows-API
resolution stage**: it holds a pointer to `"kernel32.dll"` and invokes an API
through its obfuscated context-restore `ret` trampoline. Because midas provides
no Windows loader environment (the mapped PEB/TEB are zeroed, no module list, no
resolved import thunks, no API implementations), the call target the loader
expected to be a real function address is instead an unresolved value
(`0x4d00d`), and the jump faults.

This refines the charter's "unresolved imports" appendix note: the blocker bites
**pre-OEP**, at the loader's own kernel32 resolution, well before the ~195M-
instruction OEP estimate.

*Hypothesis (not yet proven):* the loader resolves kernel32 exports by name/hash
after obtaining the module base, so getting past the wall requires (a) a module
list reachable from the PEB such that the loader's `GetModuleHandle`/`LoadLibrary`
path yields a kernel32 base, (b) an export-resolution path (`GetProcAddress` by
name and/or hash) returning callable addresses, and (c) API stubs behind those
addresses that emulate the effect. The precise resolution path (PEB->Ldr walk vs
a Themida-internal table, name vs hash) is **not yet confirmed** and must be
determined by further tracing before the win64 layer is designed around it.

## What this justifies building next (win64 layer, M3 proper)

Driven by the above and confirmed on both samples, the next work is a minimal
Windows-64 environment: an export/`GetProcAddress` mechanism and API stubs added
**only** as the loader is observed to call them — each with a test asserting its
emulated effect, and each validated against **both** samples.

## Resolution-path determination (traced, both samples)

Reproduce with:

```
cargo run --release --example trace_resolution -- samples/<sample>.exe <fault_count> <window>
cargo run --release --example watch_peb_teb    -- samples/<sample>.exe <fault_count>
```

- **The loader does NOT walk `PEB->Ldr`.** Across the entire run to the wall, the
  only PEB/TEB access observed is repeated 8-byte reads of `gs:[0x30]`
  (`NtTib.Self`, the TEB self-pointer) — ~30 reads confined to the last
  ~45k–140k instructions before the wall. The PEB is never read (no access to
  `TEB+0x60` or any PEB field). This holds identically on both samples.
- **The call target is loaded raw from an in-image table, not resolved.** The
  traced sequence computes the trampoline frame as
  `[rsp] = [[image+0xad8ca]] = 0x4d00d` (the "API address", used unrelocated) and
  `[rsp+8] = 0x1ad55d + image_base` (the return address, relocated). The `ret`
  then "calls" `0x4d00d`. `RCX` holds `"kernel32.dll"`, i.e. this is the loader's
  **bootstrap `GetModuleHandle`/`LoadLibrary("kernel32.dll")`** call.
- **`gs:[0x30]` is NOT a step toward the PEB (tested).** After populating the TEB
  (`NtTib.Self = TEB_BASE`, `StackBase/StackLimit`, `TEB.ProcessEnvironmentBlock =
  PEB_BASE`) and re-running the watch, the loader still reads **only** `gs:[0x30]`
  (32 reads), never `TEB+0x60` and never the PEB, and faults at the identical
  `0x4d00d` at the identical instruction count (26,519,612 for sample 1). Had the
  loader used the TEB self-pointer to reach the PEB (`[TEB.Self+0x60]`), a
  now-populated `TEB+0x60` would have let it read `PEB_BASE` and diverge; the
  byte-identical path rules that out. So `gs:[0x30]` is used for something else
  (pointer-decode / self-reference / anti-debug), and the wall is specifically the
  unresolved import call. The TEB population is retained as correct environment
  modeling (both samples read `gs:[0x30]`), not as a fix for the wall.

### The placeholder is an unbound IAT thunk (proven, both samples)

The value the loader calls is a **standard unbound IAT thunk**, not a
Themida-specific token. The fault address `0x4d00d`, read as an image RVA, lands
in the `.idata` section on a normal `IMAGE_IMPORT_BY_NAME`:

```
image RVA 0x4d00d  (section .idata):  00 00 "GetModuleHandleA\0"
                                      ^hint ^function name
```

so `0x4d00d` is the RVA of the import-by-name entry for **`GetModuleHandleA`**,
and the IAT/INT thunk arrays in `.idata` (e.g. at RVA `0x4d080`) hold that RVA.
On real Windows the OS loader overwrites each thunk with the resolved absolute
function address before the entry point runs; midas maps the file as-is, so the
thunk still holds the unbound `IMAGE_IMPORT_BY_NAME` RVA and the loader calls it
directly. Verified identical on both samples (RVA `0x4d00d` → `"GetModuleHandleA"`
in each); `RCX` = `"kernel32.dll"`, so the first call is
`GetModuleHandleA("kernel32.dll")`.

This **confirms** the charter appendix hypothesis ("IAT holds original
Import-Name-Table string pointers, not resolved addresses") and resolves the
earlier open sub-question: the API is identified by the PE's **own import table**,
not a Themida hash/selector.

### Design consequence (decided)

Handle the call as an **import-call trap** driven by the standard PE import table:
run until a fetch-unmapped fault; if the fault address read as an image RVA lands
on a valid `IMAGE_IMPORT_BY_NAME`, resolve the function name from the PE, emulate
that API, set `RAX`, pop the on-stack return address into RIP, and continue. This
is sample-agnostic (it reads whatever the PE imports) and mirrors the OS loader's
IAT binding. APIs are implemented one at a time, each as the loader is observed to
call it, each tested and validated on both samples.

## Progression past the first wall (both samples)

Reproduce with `cargo run --release --example run_loader -- samples/<sample>.exe`.
With the import-call trap and a `GetModuleHandleA` stub that returns a non-null
module base:

- Both samples handle exactly one API so far — `GetModuleHandleA("kernel32.dll")`
  — and then advance to a **new** fault: a `ReadUnmapped` at
  `kernel32_base + 0x3c`. `0x3c` is `e_lfanew` in the DOS header, so the loader
  **parses the PE header of the module handle it was given** and walks its export
  table itself (manual `GetProcAddress`).
- Consequence: `GetModuleHandleA` must return a base at which a **parseable
  synthetic kernel32 image** exists — a minimal PE (DOS stub + NT headers) with an
  **export directory** enumerating the functions the loader looks up, each pointing
  at a stub address the emulator can trap and dispatch. Building that synthetic
  module + export resolution is the next win64 step. This mirrors the classic
  "get `DllBase`, then parse exports" technique (cf. the PEB/Ldr write-ups),
  reached here via `GetModuleHandleA` rather than a `PEB->Ldr` walk.

## Progression through the export walk (both samples)

With a synthetic kernel32 PE (DOS + NT headers + a real export directory) mapped
at the `GetModuleHandleA` base, the loader parses the export table successfully
and advances past the `e_lfanew` read. It then resolves an export and **reads the
resolved function's code bytes**: sample 1 faults with `ReadUnmapped` at
`kernel32_base + 0x1040`, which is stub slot 4 (`stub_region_rva 0x1000 + 4*16`) =
`LoadLibraryA` (exports are name-sorted). i.e. after obtaining kernel32's base the
loader resolves `LoadLibraryA` and inspects its bytes before use (a common
anti-hook / relocation check). The absolute stub RVA is a property of the
synthetic layout, not the sample: `stub_region_rva` is the export area rounded up
to a page (`0x1000` for the current 9-name export set), so the stub region starts
at `+0x1000` and slot 4 lands at `+0x1040`.

Consequence for the design: the export **stub region must be readable** (mapped
read-only) so the loader can inspect a resolved function's bytes, while remaining
**non-executable** so that *calling* the stub still faults and is trapped/dispatched.
The slice that first observed this left the stub region unmapped (calls fault as
intended, but reads do not); the next section records making it
readable-but-non-executable and handling the execute fault
(`FetchProt`/`FetchUnmapped`) in the export-call trap. Seeding the export **names**
from the real `samples/kernel32.dll` (1664 names, see `samples/SAMPLES.md`) would
give complete resolution regardless of which function the loader wants.

## Readable stubs move the frontier to LoadLibraryA (all three samples)

Reproduce with `cargo run --release --example run_loader -- samples/<sample>.exe`.
With the synthetic kernel32 image and its export-stub region now mapped
**read-only** (`emu::Emu::map_readonly`; no EXECUTE anywhere in the module) and the
export-call trap dispatching on `FetchProt` as well as `FetchUnmapped`:

- The loader's inspection read of the resolved export's bytes now **succeeds** (the
  earlier `ReadUnmapped` at the stub is gone), and the loader proceeds to **call**
  that export. The call lands on a mapped-but-non-executable stub, faulting
  `FetchProt`, which the trap catches and dispatches by name.
- On **all three** samples the run is now identical: one handled API
  (`GetModuleHandleA`), then a stop at an unhandled export call resolved by name to
  **`LoadLibraryA`** (stub RVA `0x1040` = slot 4 in the name-sorted synthetic export
  table). So the loader's bootstrap sequence is
  `GetModuleHandleA("kernel32.dll")` → resolve/inspect/**call `LoadLibraryA`**.
- This is a captured CLI artifact, not a committed test (long, sample-dependent).
  The `FetchProt` mechanism and the readable-stub read are covered by committed
  `cargo test` cases.

### What this justifies building next

Implement `LoadLibraryA` as the next win64 API stub. It is observed on all three
bundled samples (evidence that this is shared Themida-loader behaviour rather than a
single-payload quirk, not a general proof across all Themida 3.2.4.34 binaries), so
adding it is observation-driven, not overfitting. Its argument is an ASCII module
name in `RCX`; the natural semantics mirror `GetModuleHandleA`'s module path (map /
return a synthetic module base for a known DLL), added with a test asserting the
emulated effect and re-validated on all samples via `run_loader`. The precise DLL(s)
the loader requests and what it does with the returned base are to be observed once
the stub returns.

## LoadLibraryA loads five DLLs, then the frontier is the loaded module's header (all three samples)

Reproduce with `cargo run --release --example run_loader -- samples/<sample>.exe`.
`LoadLibraryA(name)` reads the ASCII name from `RCX` and returns: the process image
base for a NULL name; the mapped synthetic kernel32 for `"kernel32.dll"`; otherwise a
stable non-null handle per DLL name (allocated once, returned again on repeat loads).
`GetModuleHandleA` now returns an already-loaded module's handle and `0` for a
never-loaded one. Only kernel32 is special-cased (it is the module whose synthetic
export table we provide); every other DLL takes the same generic handle path, so the
mechanism is sample-agnostic — the DLL names come from guest memory, none is hardcoded.

- After `GetModuleHandleA("kernel32.dll")` the loader calls `LoadLibraryA` **five**
  times, requesting — in this order, identically on all three samples —
  `user32.dll`, `advapi32.dll`, `ntdll.dll`, `shell32.dll`, `shlwapi.dll`. That the
  same fixed list appears across three independently-protected binaries is evidence
  of shared Themida-loader behaviour (not a per-payload quirk), though not a proof
  across all Themida 3.2.4.34 binaries.
- The run then stops with `ReadUnmapped` at `first_loaded_base + 0x3c` (the fault
  address decodes to `FAKE_MODULE_BASE_START + FAKE_MODULE_BASE_STEP + 0x3c`, i.e. the
  base handed back for the *first* `LoadLibraryA` (`user32.dll`) plus `0x3c`). `0x3c`
  is `e_lfanew` in the DOS header, so — exactly as it did for the kernel32 handle —
  the loader has *begun* parsing the PE header of a module it loaded (this artifact
  captures the first header read; the subsequent export walk is not yet observed
  because the image is unmapped). One level down from kernel32.
- Captured CLI artifact, not a committed test (long, sample-dependent). The
  `LoadLibraryA` handle semantics and the export-stub dispatch of `LoadLibraryA` are
  covered by committed `cargo test` cases.

### What this justifies building next

Generalise the synthetic-module machinery (today kernel32-only) so a module returned
by `LoadLibraryA` is a **mapped, parseable** PE — DOS + NT headers + an export
directory — reusing the existing `SyntheticModule` builder, seeded with each DLL's
export **names**. Then the loader's `base+0x3c` header parse succeeds and it proceeds
to walk that module's exports, revealing the next resolution/API step (observed, then
implemented, one at a time, re-validated on all samples).

## Parseable loaded modules move the frontier to GetProcAddress (all three samples)

Reproduce with `cargo run --release --example run_loader -- samples/<sample>.exe`.
`Win64Env` now keeps a registry of synthetic modules; `LoadLibraryA` maps a parseable
PE for every loaded DLL — kernel32 with its seeded export names, every other DLL with
an **empty** export table (we do not yet know which functions the loader resolves from
those DLLs; the DLL names are read from guest memory, so nothing is hardcoded). The
export-call trap reverse-maps a faulting stub across all registered modules.

- With the five loaded DLLs now parseable, the loader gets past the `user32_base+0x3c`
  read and the header/export-directory parse, and advances to resolving and **calling**
  `GetProcAddress` from kernel32 (kernel32 stub `rva=0x1030` = slot 3 in the name-sorted
  export table). Identical on all three samples. So the loader's bootstrap is the
  classic `GetModuleHandle`/`LoadLibrary` → resolve `GetProcAddress` → resolve
  everything else pattern.
- Captured CLI artifact, not a committed test (long, sample-dependent). The parseable
  empty-export module and the `LoadLibraryA`-maps-a-parseable-module capabilities are
  covered by committed `cargo test` cases.

### What this justifies building next

Implement `GetProcAddress(hModule, lpProcName)`. In this synthetic world it must return
a **callable stub address** for the requested name — resolving against the given
module's synthetic export table when the name is present, and otherwise minting a stub
on demand (implemented as a per-env by-name arena; see the next section) so the returned
address later faults and dispatches by name. `lpProcName` (in `RDX`) may be a name
pointer or an ordinal (low bits, high bits zero). Implementing this both unblocks the
loader and reveals — via the requested names — which functions it resolves from
user32/advapi32/ntdll/shell32/shlwapi, each then observed and handled one at a time,
re-validated on all samples.

## GetProcAddress resolves SetLastError/GetLastError, then the loader branches through NULL (all three samples)

Reproduce with `cargo run --release --example run_loader -- samples/<sample>.exe`.
`GetProcAddress(hModule, lpProcName)` reads `hModule` from `RCX` and `lpProcName` from
`RDX`; for a name pointer it resolves a **callable** stub — reusing the module's
built-in synthetic export stub when the name is in its table, otherwise minting a
read-only non-executable stub from a per-`Win64Env` dynamic arena (base
`0x0000_7ffe_0000_0000`, deduplicated by name). Resolution requires a valid loaded
module handle — a bogus/zero `hModule` returns `0`. A call to a resolved arena stub
faults and dispatches by name via the trap. Ordinal requests (`lpProcName < 0x10000`)
return `0` for now.

- The loader's first two `GetProcAddress` calls are `GetProcAddress(kernel32,
  "SetLastError")` and `GetProcAddress(kernel32, "GetLastError")` — both **name**
  lookups against kernel32 (`hModule` = the kernel32 synthetic base), for functions NOT
  in the seeded export list, so both take the dynamic-arena path and return non-null
  stubs (`0x7ffe00000000`, `0x7ffe00000010`). Identical on all three samples.
- The loader then transfers control to address `0` (`ReachedUntil`, i.e. `RIP` became 0),
  WITHOUT first calling either resolved stub (a call to `0x7ffe...` would have
  FetchProt-trapped and dispatched by name). So the NULL branch is a **new, distinct
  wall**, not a consequence of `GetProcAddress` resolution: after saving/restoring error
  state the loader calls or jumps through a pointer that is `0` in our environment.
- Captured CLI artifact, not a committed test. The `GetProcAddress` resolution
  behaviour (named lookup, built-in-stub reuse, ordinal → 0, and trap dispatch of a
  resolved stub) is covered by committed `cargo test` cases.

### What this justifies building next

Diagnose the NULL branch before implementing anything further: trace the last
instructions before `RIP` reaches `0` (reuse `run_observed`/`trace_resolution`) to find
the transfer site and which pointer the loader branches through — e.g. a function
pointer read from a structure we have not populated (a PEB/TEB field, a callback table,
or a value the loader expected an API such as `SetLastError`/`GetLastError` to have
side-effected). Handle that specific gap (observation-driven), then re-validate on all
samples.

## The NULL branch is a Themida VM handler-pointer that reads back 0 (diagnosed)

Reproduce with `cargo run --release --example trap_postmortem -- samples/<sample>.exe`.
After the 8 bootstrap APIs the loader runs a small Themida **bytecode interpreter**
(not more import calls). The post-mortem shows the last executed instruction is a
context-restore **trampoline** `pop r8 … pop rax ; popf ; ret 0` (sample 1:
`.themida+0x5cb64`–`0x5cb7c`) and the value the `ret` consumes is `0` — so `RIP`
becomes 0 (`ReachedUntil`). Confirmed identical on **all three** samples (each stops
with `ret` target `0`); the exact `.themida` RVAs below are per-instance evidence,
traced on sample 1.

**The dispatch mechanism (traced).** The interpreter keeps its state in a
stack-resident context `rbp`; `[rbp+0xB2]` is a bytecode cursor advanced each
iteration by a *signed* delta (`.themida+0x55344`: `[rbp+0xB2] += movsxd [cursor+2]`).
For each op the trampoline prologue computes the **handler/return target** as a
double-dereference through the context:

```
r13 = *( *(rbp + *(cursor+6)) )      ; .themida+0x5cae0 .. 0x5caf5
```

and writes it into the frame slot the final `ret` consumes (`mov [rsi], r13`,
`.themida+0x5cb1a`). So the ret target is `r13`, **not** an `RVA+base` sum (an
earlier reading of the trampoline was wrong; the `*(cursor)[u32] + *(rbp+0xBB)`
value is a *different* saved register, `r14`, which stayed valid = `0x1401ca356`).

**Where the 0 comes from (sample 1, capped-run capture at the final `0x5caf1`).**
The chain resolves to a genuine null in a handler-pointer table:

```
rbp                     = 0x14006f9e0            (VM context, in .themida)
rbp + *(cursor+6)       = 0x14006fa68            (*(cursor+6) = 0x88)
[rbp + *(cursor+6)]     = 0x14005bd08            (pointer into a .themida table)
r13 = [0x14005bd08]     = 0x0                    (the null handler -> ret target)
```

`.themida+0x5bd08` is one 8-byte slot in a handler-pointer table embedded in the
*unpacked* `.themida`; its neighbours hold valid handlers (e.g. `[0x5bd18] =
0x1400dc1f7`), but this entry is `0`. It is **not written during the traced final
leg** (the post-`GetProcAddress` segment) — it is already 0 when the interpreter
reaches it; whether it is written earlier in the run is candidate cause 3 below (an
un-run whole-run write trace). The 24 preceding VM ops read valid handlers from the
analogous slot (e.g. `[…] = 0x140053xxx`); only this 25th op reads a null.

**Open question (the crux for the fix).** Why is `[0x14005bd08]` zero — i.e. what
was supposed to populate this handler slot before the interpreter reached it. It is
resolved *right after* `GetProcAddress` returned `SetLastError`/`GetLastError`
(arena stubs `0x7ffe0000_0000`/`_0010`), and those resolved stubs are **never called**
before the stall. Candidate causes, to be tested in order:

1. The slot is filled by a VM op whose input is a value we mis-modelled — e.g. the
   arena address our `GetProcAddress` returns is not shaped as the loader expects
   (a real function pointer inside a DLL image), so a later `handler = f(resolved)`
   step produces 0 or is skipped. Test: make resolved addresses point inside the
   synthetic module image (or give the loaded DLLs real-looking export/stub layout)
   and see whether the slot becomes non-zero.
2. A prior step gated on an environment detail we don't model (e.g. `SetLastError`/
   `GetLastError` touching `TEB->LastErrorValue` at `TEB+0x68`) never runs, leaving
   the slot 0. Test: implement those APIs' side-effects and/or the missing field.
3. The slot is populated by a self-decryption/relocation pass over `.themida` that
   our run hasn't triggered. Test: trace writes to `0x14005bd08` across the *whole*
   run (not just the final leg) to find its intended writer.

The fix direction is **ambiguous** and should be chosen with the human before
building: it may be a small API-semantics gap (2) or a larger change to how resolved
addresses are modelled (1). `examples/trap_postmortem.rs` reproduces the wall; the
per-sample capture used a one-shot instruction cap at the final `0x5caf1`.

## Whole-run write trace: the loader's own VM stores the 0 (candidate 3 resolved)

Method: a temporary persistent write-watch on the 8-byte slot `0x14005bd08` that
survives the trap's per-API `resume` legs (a `MEM_WRITE` hook filtered to the slot,
recording writer RIP + value). Sample 1.

The slot **is** written during the run — 9 writes, and the last one wins:

- During initial decompression the unpacker fills the slot with **non-zero** bytes
  (`.themida+0x30b074` `mov [rdi],al` → `64 96 1e 73 …`, then `.themida+0x30b144`
  `rep movsb`).
- **Later**, a single **8-byte write** `mov [r9],rbx` at `.themida+0xaccf7`
  (`r9 = 0x14005bd08`, `rbx = 0`) **zeroes the whole slot**. Nothing writes it after
  that, so it reads back `0` when the dispatcher later loads it as a handler.

So candidate cause 3 (a self-decrypt/relocation pass we hadn't traced) is the writer,
but it does not *populate* the slot — it *nulls* it. And `0xaccf7` is itself a **VM
"store" handler**:

```
rbx = *(rbp + *(rbp+0x123))   ; read a value from a VM-context slot  -> 0
mov [r9], rbx                 ; store it into 0x14005bd08
```

i.e. the interpreter copied a `0` **out of its own context** into the handler slot.
The null therefore originates *inside the VM's data flow* — an upstream VM-context
value that is `0` in our environment — not a missing native write and not (directly)
the arena-address shape or a `TEB` field. Candidate causes 1 and 2 are not ruled in
by this; the true origin is whatever produced that upstream `0`.

### Consequence

Pinning the origin means following the VM's data flow backwards across many handlers
(each reads/writes `rbp`-relative context slots and advances the `[rbp+0xB2]` cursor)
to the op that should have produced a non-zero value and didn't. That is a
substantial VM-reversal effort and the fix is still unknown — it should be scoped
with the human before building. A promising cheaper cut first: correlate the upstream
VM-context slot (`rbp + *(rbp+0x123)`) with the two values the environment most
plausibly perturbs at this point — the `GetProcAddress` results for
`SetLastError`/`GetLastError` — by watching writes to that slot across the run.
