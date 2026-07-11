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
`kernel32_base + 0x1040`, which was stub slot 4 (`stub_region_rva 0x1000 + 4*16`) =
`LoadLibraryA` in the then-current name-sorted export set. i.e. after obtaining
kernel32's base the loader resolves `LoadLibraryA` and inspects its bytes before use
(a common anti-hook / relocation check). The absolute stub RVA was a property of
that synthetic layout, not the sample: `stub_region_rva` was the export area rounded
up to a page (`0x1000` for that 9-name export set), so the stub region started at
`+0x1000` and slot 4 landed at `+0x1040`.

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
  **`LoadLibraryA`** (stub RVA `0x1040` = slot 4 in the then-current name-sorted
  synthetic export table). So the loader's bootstrap sequence is
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
  `GetProcAddress` from kernel32 (kernel32 stub `rva=0x1030` = slot 3 in the
  then-current name-sorted export table). Identical on all three samples. So the
  loader's bootstrap is the
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
  FetchProt-trapped and dispatched by name). So the NULL transfer is distinct from a
  call to either returned stub: after saving/restoring error state the loader calls or
  jumps through a different pointer that is `0` in our environment. This observation
  alone does not show whether the resolved address values influenced the VM computation
  that produced that pointer.
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
reaches it; it is written (then zeroed) earlier in the run — see the whole-run write
trace section below. The 24 preceding VM ops read valid handlers from the analogous
slot (e.g. `[…] = 0x140053xxx`); only this 25th op reads a null.

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
   and see whether the slot becomes non-zero. **A first in-image implementation did
   not advance the observable `run_loader` frontier, but no comparative VM/source-slot
   trace was captured; see "In-image proc stubs do not advance the observable frontier"
   below. Candidate 1 remains causally unproven.**
2. A prior step gated on an environment detail we don't model (e.g. `SetLastError`/
   `GetLastError` touching `TEB->LastErrorValue` at `TEB+0x68`) never runs, leaving
   the slot 0. Test: implement those APIs' side-effects and/or the missing field.
3. The slot is populated/managed by a pass over `.themida` we hadn't traced. Test:
   trace writes to `0x14005bd08` across the *whole* run. **Done** — see the next
   section: the slot is written by the loader's own VM, which *nulls* it rather than
   populating it, so the origin is an upstream VM value (candidates 1/2 still open).

The fix direction is **ambiguous** and should be chosen with the human before
building: it may be a small API-semantics gap (2) or a larger change to how resolved
addresses are modelled (1), although the first in-image-stub implementation did not
advance the observable frontier. `examples/trap_postmortem.rs` reproduces the wall; the
per-sample capture used a one-shot instruction cap at the final `0x5caf1`.

## Whole-run write trace: the loader's own VM *nulls* the slot (candidate 3 writer found)

Method: a temporary persistent write-watch on the 8-byte slot `0x14005bd08` that
survives the trap's per-API `resume` legs (a `MEM_WRITE` hook filtered to the slot,
recording writer RIP + value). Sample 1.

The slot **is** written during the run — 9 writes (four byte-`mov [rdi],al`, four
byte-`rep movsb`, then one 8-byte store), and the last one wins:

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
or out by this; the true origin is whatever produced that upstream `0`. A subsequent
in-image-stub experiment did not advance the `run_loader` outcome frontier, but did not
trace this upstream slot under both configurations, so candidate 1 remains causally
unproven.

### Consequence

Pinning the origin means following the VM's data flow backwards across many handlers
(each reads/writes `rbp`-relative context slots and advances the `[rbp+0xB2]` cursor)
to the op that should have produced a non-zero value and didn't. That is a
substantial VM-reversal effort and the fix is still unknown — it should be scoped
with the human before building. A promising cheaper cut first: correlate the upstream
VM-context slot (`rbp + *(rbp+0x123)`) with the two values the environment most
plausibly perturbs at this point — the `GetProcAddress` results for
`SetLastError`/`GetLastError` — by watching writes to that slot across the run.

## In-image proc stubs do not advance the observable frontier

Experiment (reproduce by making the change and re-running `run_loader` on all three
samples): temporarily change `resolve_proc`
so a dynamically-resolved export returns a stub **inside the requesting module's image**
(`kernel32_base + rva`, `rva < SizeOfImage`) instead of the out-of-image arena at
`PROC_STUB_BASE = 0x7ffe_0000_0000`, then re-run all three samples. The experimental
implementation also reserved 4096 per-module dynamic-stub slots, enlarging the mapped
stub region and the synthetic module's `SizeOfImage`; it therefore tested that bundled
in-image provider change, not an isolated address-value substitution.

Result: `GetProcAddress(kernel32, "SetLastError"/"GetLastError")` now returns
`0x7fff0000_1090` / `0x7fff0000_10a0` (inside the synthetic kernel32 image) instead of
`0x7ffe0000_0000` / `_0010` — a change of ~4 GiB in the returned value. On all three
samples, `run_loader` prints the same observable summary: the same 8 bootstrap APIs,
then the same `ReachedUntil` (`ret` to 0). This implementation therefore **does not
advance the observable `run_loader` frontier**.

That summary is intentionally not described as a byte-identical run: `run_loader`
reports only handled API names and the final stop, the returned addresses necessarily
differ, and no comparative instruction/memory trace or upstream-source-slot watch was
captured. The observation therefore does **not** prove that the internal VM path was
unchanged or that the proc-address value is causally independent of the upstream `0`.
It rules out this bundled in-image implementation as a direct fix, not candidate 1 as
a cause. The experimental source change was reverted because it did not advance the
observable frontier.

### What this leaves

The next decisive test is either a truly isolated address-only A/B (holding the module
layout and `SizeOfImage` fixed) or an operand/data-dependency trace of **writes to the
upstream source slot** `rbp + *(rbp+0x123)` under the arena and bundled in-image
configurations, including the writer sequence leading to the final handler-slot store.
Reaching the same source slot through the same VM path and storing the same `0` would
strengthen the negative evidence but would not alone prove independence: candidate 1
can be ruled out for this wall only if the trace shows that the returned addresses do
not feed the producer chain (or the isolated substitution preserves the relevant
state). If the configurations diverge internally despite the same final summary, the
trace identifies the missing causal edge. Following that producer chain far enough to
distinguish an unmodelled read (for example `TEB+0x68` or another structure) from a
purely internal VM computation remains a multi-handler VM-reversal; the fix is unknown.

## The upstream zero is a missing ntdll critical-section call

The cheaper upstream correlation identified the exact missing resolution: the
bootstrap export walk selects `RtlInitializeCriticalSection` from ntdll. The
earlier synthetic `ntdll.dll` had an empty export table, so the VM propagated a null
target into the handler slot documented above. This supersedes the earlier
conclusion that fixing the wall necessarily required multi-handler VM reversal.

The production slice now gives `ntdll.dll` exactly the eight names observed during
the initial bootstrap and implements the exercised effect. On x64 the API receives a
writable 40-byte `RTL_CRITICAL_SECTION` in `RCX`; the model clears all 40 bytes, sets
the signed 32-bit `LockCount` at offset `+8` to `-1`, returns `NTSTATUS 0`, and
performs the normal x64 return. Focused tests cover the explicit eight-name export
table, direct memory/register effects, and an end-to-end call through the synthetic
ntdll export stub.

Reproduce the sample-dependent result with:

```
cargo build --release --example run_loader
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
```

The documented sample now handles 15 calls rather than the former 8-call prefix;
call 9 is `RtlInitializeCriticalSection`, and the run stops later at
`ReachedUntil`. The two additional on-disk samples produce the same engineering
result, but their incomplete source/pre-protection provenance in
`samples/SAMPLES.md` means they are not yet formal milestone-acceptance
evidence.

Exact sample-1 output:

```
handled APIs:
  001: GetModuleHandleA
  002: LoadLibraryA
  003: LoadLibraryA
  004: LoadLibraryA
  005: LoadLibraryA
  006: LoadLibraryA
  007: GetProcAddress
  008: GetProcAddress
  009: RtlInitializeCriticalSection
  010: GetModuleHandleA
  011: LoadLibraryA
  012: GetModuleHandleA
  013: LoadLibraryA
  014: GetModuleHandleA
  015: LoadLibraryA
stop: ReachedUntil
```

### New frontier

The critical-section effect fixes this specific null propagation. The next
`ReachedUntil` after the shared 15-call prefix has not yet been diagnosed by a
committed production artifact, so no further API behavior is justified by this
section alone.

## GetUserDefaultUILanguage is the causal call-16 gap

After the merged `RtlInitializeCriticalSection` slice, the baseline handles 15
APIs and then reaches the previously observed ret-to-zero. A sample-1 runtime
trace localized the final null handler slot to `0x14006d3b6`. Its last writer is
`0x1400accf7` (`mov [r9],rbx`), which stores `RBX = 0`; the final dispatcher at
`0x14005caf5` later reads that zero.

An isolated A/B diagnostic changed only `KERNEL32_EXPORTS` by adding
`GetUserDefaultUILanguage`. With that name present, the same writer stores the
synthetic export stub `0x7fff00001040` into the same slot, and the same final
dispatcher reads that address. The export-call trap then reports
`GetUserDefaultUILanguage` as call 16. This directly ties the availability of
that export name to this handler slot and call; it does not justify any other
API. The stub address is a diagnostic observation, not a production constant:
the synthetic export builder sorts names, so RVAs can move when the seed changes.

The production slice seeds only that observed kernel32 name. Its no-argument
dispatch returns deterministic nonzero `LANGID 0x0409` (en-US) as the emulated
environment's default UI-language policy, writes it to `RAX`, and performs the
normal x64 return. Focused tests assert the direct `RAX`/`RIP`/`RSP` effect and
an end-to-end call through the synthetic kernel32 export stub; the trap test
looks the stub up by name rather than fixing its RVA.

Reproduce the sample-dependent result with:

```
cargo build --release --example run_loader
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
```

Each captured run emitted this call/stop summary:

```
handled APIs:
  001: GetModuleHandleA
  002: LoadLibraryA
  003: LoadLibraryA
  004: LoadLibraryA
  005: LoadLibraryA
  006: LoadLibraryA
  007: GetProcAddress
  008: GetProcAddress
  009: RtlInitializeCriticalSection
  010: GetModuleHandleA
  011: LoadLibraryA
  012: GetModuleHandleA
  013: LoadLibraryA
  014: GetModuleHandleA
  015: LoadLibraryA
  016: GetUserDefaultUILanguage
stop: ReachedUntil
```

Returning the environment-policy LANGID advances each sample by approximately
1.1 million instructions beyond the 15-call wall to this later
`ReachedUntil`. Samples 2 and 3 corroborate the engineering result, but their
incomplete source/pre-protection provenance in `samples/SAMPLES.md` means they
are not formal milestone evidence.

### New frontier

A separate broad-name diagnostic observed the next selected and called
kernel32 export as `GetProcessHeap`. This slice does not seed or dispatch
`GetProcessHeap` and claims no semantics for it; it is only the next observed
Win64 frontier.

## GetProcessHeap advances the loader to RtlAllocateHeap

The prior broad-name diagnostic identified `GetProcessHeap` as the export after
call 16. The production slice adds only that observed kernel32 name and models
the no-argument API as returning a deterministic, stable, nonzero opaque handle
owned by `Win64Env`. The handle has no allocator backing in this slice; the code
does not claim heap allocation or `PEB.ProcessHeap` coherence. Direct coverage
calls the API twice in one environment and asserts the stable return plus the
`RAX`/`RIP`/`RSP` effects. An end-to-end test resolves the synthetic export stub
by name and exercises the normal export-call trap.

Reproduce the sample-dependent result with:

```
cargo build --locked --release --example run_loader
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
```

All three captured runs emitted the same call sequence and stop. Exact sample-1
output:

```
handled APIs:
  001: GetModuleHandleA
  002: LoadLibraryA
  003: LoadLibraryA
  004: LoadLibraryA
  005: LoadLibraryA
  006: LoadLibraryA
  007: GetProcAddress
  008: GetProcAddress
  009: RtlInitializeCriticalSection
  010: GetModuleHandleA
  011: LoadLibraryA
  012: GetModuleHandleA
  013: LoadLibraryA
  014: GetModuleHandleA
  015: LoadLibraryA
  016: GetUserDefaultUILanguage
  017: GetProcessHeap
stop: unhandled API RtlAllocateHeap at export-stub or import rva=0x00001020
```

The reported `0x1020` is an address in the current name-sorted synthetic ntdll
layout, not a production constant or sample property. The trap reverse-maps that
stub to `RtlAllocateHeap` by name. Sample 1 is the formal artifact; samples 2 and
3 corroborate the engineering result but retain the provenance limitation in
`samples/SAMPLES.md`.

### New frontier

`RtlAllocateHeap` is now the next observed and called export on all three
samples. It is present in the synthetic ntdll export table but has no dispatch or
allocation semantics yet, so the trap stops before executing it.

## RtlAllocateHeap advances the loader through repeated process-heap requests

Historical capture note: the outputs in this section were recorded at the
merged heap-only baseline `3763982`, before `GetCurrentThreadId` was seeded.
For samples 1 and 2, the same commands at the merged thread-ID baseline
`98969a2` include the additional call documented in the next section; the later
`OpenThread` progression is recorded after that. Sample 3 retains its separate
28-call path at these baselines. The allocation arguments captured here remain
unchanged.

The fault-time capture at the previous wall was identical on all three samples:
`RCX = 0x0000000f30000000` (the stable `GetProcessHeap` result), `RDX = 0x8`
(`HEAP_ZERO_MEMORY`), `R8 = 0x1000`, and `R9 = 0`. The production replay below
then observes the loader call `GetProcessHeap` again and make another allocation
request. That repeated sequence directly justifies a general multi-block
allocator rather than a one-address return value.

The production model accepts the environment's process-heap handle and allocates
distinct RW/NX pages from a bounded 256 MiB bump arena. It tracks requested and
mapped sizes for later ownership checks, guarantees at least 16-byte alignment,
and explicitly zeroes every fresh mapping. The accepted flag subset is
`HEAP_NO_SERIALIZE` and `HEAP_ZERO_MEMORY`: the latter is satisfied for the
observed calls, but absence of the flag is not behaviorally distinguished, and
the former is a no-op in the single-threaded emulator. Unsupported flags,
invalid handles, checked-arithmetic failure, and arena exhaustion return `NULL`
without changing allocator state. Treating a zero-byte request as a fresh
minimum block is an explicit environment policy, not an observed loader
requirement. Free, reallocation, exception-generating allocation failure, and
block reuse are not implemented by this slice.

Focused tests cover the RW/NX mapping primitive, the exact observed call,
alignment and writeability, distinct non-overlapping blocks, metadata, the
low-32-bit `ULONG` flag ABI, failure atomicity, bounded exhaustion, zero-size
uniqueness, and an end-to-end call through the name-resolved synthetic ntdll
stub. The heap-only capture used:

```
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
```

Exact sample-1 output:

```
handled APIs:
  001: GetModuleHandleA
  002: LoadLibraryA
  003: LoadLibraryA
  004: LoadLibraryA
  005: LoadLibraryA
  006: LoadLibraryA
  007: GetProcAddress
  008: GetProcAddress
  009: RtlInitializeCriticalSection
  010: GetModuleHandleA
  011: LoadLibraryA
  012: GetModuleHandleA
  013: LoadLibraryA
  014: GetModuleHandleA
  015: LoadLibraryA
  016: GetUserDefaultUILanguage
  017: GetProcessHeap
  018: RtlAllocateHeap
  019: GetProcessHeap
  020: RtlAllocateHeap
stop: ReachedUntil
```

`trap_postmortem` stopped immediately before call 20 by setting `max_calls = 19`.
On samples 1 and 2 that second allocation again uses the process-heap handle and
flag `0x8`, but requests `0x10` bytes. Sample 3 follows the same first two calls,
then makes four more allocations before its stop; its six requested sizes are
`0x1000`, `0x10`, `0x410`, `0x10`, `0x410`, `0x10`, all with flag `0x8`. Thus the
shared artifact is the same two-allocation prefix, while the longer sample-3
sequence is payload-dependent engineering evidence. Sample 1 is the formal
artifact; samples 2 and 3 retain the provenance limitation recorded in
`samples/SAMPLES.md`.

The bounded argument captures used these exact invocations (setting
`max_calls` one below the target API stops before dispatch and preserves its
argument registers):

```
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 17
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 19
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 17
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 19
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 17
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 19
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 21
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 23
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 25
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 27
```

Clipped sample-1 stdout immediately before call 20:

```
handled: [..., "RtlAllocateHeap", "GetProcessHeap"]
stop:    Other("max_calls reached")
  RCX = 0x0000000f30000000
  RDX = 0x0000000000000008
  R8 = 0x0000000000000010
  R9 = 0x0000000000000000
  RIP = 0x00007fff00301020
```

The shown `0x00007fff00301020` is the name-resolved `RtlAllocateHeap` stub in
this synthetic-module layout, not a stable production constant.

The corresponding flag (`RDX`) and requested-size (`R8`) captures were:

| Sample | Target call | `max_calls` | `RDX` | `R8` |
|---|---:|---:|---:|---:|
| 1 | 18 | 17 | `0x8` | `0x1000` |
| 1 | 20 | 19 | `0x8` | `0x10` |
| 2 | 18 | 17 | `0x8` | `0x1000` |
| 2 | 20 | 19 | `0x8` | `0x10` |
| 3 | 18 | 17 | `0x8` | `0x1000` |
| 3 | 20 | 19 | `0x8` | `0x10` |
| 3 | 22 | 21 | `0x8` | `0x410` |
| 3 | 24 | 23 | `0x8` | `0x10` |
| 3 | 26 | 25 | `0x8` | `0x410` |
| 3 | 28 | 27 | `0x8` | `0x10` |

At the heap-only baseline, the final `ReachedUntil` is again a trampoline `ret`
whose consumed target is zero. On sample 1 it occurs after call 20 with
`RIP = 0`, `RAX = 0`, and `[RSP-8] = 0`; samples 2 and 3 reach the same class of
stop after calls 20 and 28 respectively.

Those final stops were reproduced with `max_calls = 200`:

```
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

Relevant clipped stdout:

| Sample | Stop | `RAX` | `RIP` | `[RSP-8]` |
|---|---|---:|---:|---:|
| 1 | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0` |
| 2 | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0` |
| 3 | `Other("ReachedUntil")` | `0x0000000f40005000` | `0x0` | `0x0` |

### New frontier

At that baseline, the cause of this later null VM-handler value had not yet been
diagnosed. The next section records the isolated trace that identified the
missing export.

## GetCurrentThreadId is the causal post-allocation gap on samples 1 and 2

Historical capture note: the production output in this section was recorded at
exact implementation commit `8041751`; merged commit `98969a2` has the same
tree. Both precede the `OpenThread` slice. The current progression is recorded
in the next section.

A temporary broad-name diagnostic using the 1,664 export names parsed from the
authorized `samples/kernel32.dll` first changed formal sample 1's
post-allocation ret-to-zero into an unhandled `GetCurrentThreadId` call. Sample
2 selected the same name; sample 3 instead selected `GetCurrentDirectoryW`
after its longer, payload-dependent allocation sequence. Because the broad
table changes the synthetic export layout and the loader's export-walk cost, it
was discovery evidence only, not the production justification. The throwaway
broad-name source and raw log were not committed.

The decisive temporary sample-1 A/B added exactly one line to the baseline
kernel32 seed:

```diff
+    "GetCurrentThreadId",
```

The runtime trace localized the baseline null to a new, per-instance handler
slot at `0x1400ad4aa`. Its last writer is the same VM store used at earlier
frontiers, `0x1400accf7` (`mov [r9],rbx`), and the final dispatcher reads it at
`0x14005caf5`. With the baseline seed, that writer copies `0` from the VM
context into the slot. With only `GetCurrentThreadId` added, the writer and
destination are unchanged, but the source and stored value become the
name-resolved stub `0x00007fff00001010`; the final dispatcher reads that exact
value and the export trap reports `GetCurrentThreadId` as call 21. These
addresses are sample-1 and synthetic-layout evidence, not production constants.
The diagnostic tracer and raw log were not committed, so this is a captured
investigation result rather than a command-reproducible repository artifact.
The production code looks the export up and dispatches it by name; the committed
production replay below independently reproduces the resulting call sequence.

`GetCurrentThreadId` takes no arguments and returns a `DWORD`. The modeled
single-thread environment owns deterministic nonzero ID `1`, stable for the
lifetime of a `Win64Env`; dispatch converts the stored `u32` to `u64`, giving a
deterministic zero-extended `RAX`, then performs the normal x64 return. This
policy does not model scheduling, thread creation/termination, or system-wide
uniqueness across separate environments. It also leaves the TEB `ClientId`
region zero: this slice has no observed requirement that justifies introducing
the associated process/thread-ID state. A direct TEB read could therefore
disagree with this API until such a read is observed and modeled.

Focused tests call the API twice with different garbage values in the volatile
argument registers and assert the stable 32-bit result plus exact
`RAX`/`RIP`/`RSP` effects. An end-to-end test resolves the synthetic kernel32
stub by name, calls it through the normal export trap, and asserts the same
result without relying on a fixed RVA. To reproduce the historical
sample-dependent result, check out `98969a2` in a throwaway worktree, make the
local gitignored sample binaries available there, and run:

```
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 20
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 20
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
```

Setting `max_calls = 20` stops before dispatching call 21. The two first samples
both show `RIP = 0x00007fff00001010`, while the consumed trampoline slot at
`[RSP-8]` contains the same value. The address is the `98969a2` name-sorted
synthetic layout's `GetCurrentThreadId` stub, not a stable RVA. The preserved
`RCX = 1`, `RDX = 2`, `R8 = 0x10`, and `R9 = 0` values are incidental guest
state because this API has no parameters.

Exact formal sample-1 production output at `98969a2`:

```
handled APIs:
  001: GetModuleHandleA
  002: LoadLibraryA
  003: LoadLibraryA
  004: LoadLibraryA
  005: LoadLibraryA
  006: LoadLibraryA
  007: GetProcAddress
  008: GetProcAddress
  009: RtlInitializeCriticalSection
  010: GetModuleHandleA
  011: LoadLibraryA
  012: GetModuleHandleA
  013: LoadLibraryA
  014: GetModuleHandleA
  015: LoadLibraryA
  016: GetUserDefaultUILanguage
  017: GetProcessHeap
  018: RtlAllocateHeap
  019: GetProcessHeap
  020: RtlAllocateHeap
  021: GetCurrentThreadId
stop: ReachedUntil
```

At `98969a2`, sample 2 has the same 21-call sequence as engineering
corroboration. Both then reach a zero-target control transfer; full
`trap_postmortem` captures
show `RAX = 1`, `RIP = 0`, and `[RSP-8] = 0`. Sample 3 retains its
six-allocation, 28-call sequence and ret-to-zero, with no
`GetCurrentThreadId` call. Its provenance remains incomplete, and its
separately diagnosed `GetCurrentDirectoryW` selection is a different slice
rather than part of the formal sample-1 mechanism.

### New frontier

At `98969a2`, the cause of the later null handler after
sample-1/sample-2 call 21 had not yet been diagnosed. The next section records
the isolated trace that identifies `OpenThread`. `GetCurrentDirectoryW`
remains a separate sample-3 observation and is not implemented here.

## OpenThread is the causal post-thread-ID gap on samples 1 and 2

The diagnostic started at exact implementation commit `8041751`; merged commit
`98969a2` is tree-identical. A temporary broad-name run using the 1,664 exports
parsed from the authorized `samples/kernel32.dll` changed the later formal
sample-1 null handler into an unhandled `OpenThread` call 22. Sample 2 selected
the same name. Sample 3 instead retained its separate six-allocation path and
selected `GetCurrentDirectoryW` after call 28. The broad table was discovery
evidence only because it changes the synthetic export layout and export-walk
cost; its throwaway source and raw log were not committed.

The decisive sample-1 A/B added only `OpenThread` to the `98969a2` kernel32
seed. The baseline final dispatcher at `0x14005caf5` reads a per-instance handler
slot at `0x1400eb3c6`, reached through context cell `0x14006fa68`. The slot's
last writer remains `0x1400accf7` (`mov [r9],rbx`) in both runs. At baseline the
writer stores zero. With only `OpenThread` added, the writer, destination, and
selectors remain unchanged, while the source and stored value become the
name-resolved stub `0x00007fff00001090`; the dispatcher reads that value and the
export trap reports `OpenThread` as call 22. These addresses are sample-1 and
synthetic-layout evidence, not production constants. The diagnostic tracer and
raw log were temporary and uncommitted; the production replay below
independently reproduces the call and subsequent progress.

The production pre-call capture uses `max_calls = 21`, which stops before
dispatching call 22 and preserves its Win64 arguments:

```text
RCX = 0x00000000001f03ff
RDX = 0x0000000000000000
R8  = 0x0000000000000001
RIP = 0x00007fff00001090
[RSP-8] = 0x00007fff00001090
```

Thus the observed call is `OpenThread(0x001f03ff, FALSE, 1)`. The access value
matches the legacy pre-Vista `THREAD_ALL_ACCESS` mask, including its unnamed
`0x4` bit; that header-era match does not establish the runtime Windows
version. Dispatch consumes only the low 32 bits of the `DWORD`, `BOOL`, and
thread-ID arguments, and treats any nonzero low-32-bit `BOOL` as true.

The bounded environment policy recognizes only the sole modeled current thread
ID `1` and access masks that are subsets of `0x001f03ff`. Every successful open
creates a fresh handle in an unmapped registry namespace starting at
`0x0000000f30001000`, records the target thread, requested access, and
inheritability, and advances the checked cursor. Unknown IDs, unsupported bits,
collisions, arithmetic overflow, and namespace exhaustion return `NULL` without
changing the registry. This is not a Windows security model: ACL and token
checks, privileges, protected processes, last-error values, actual child-process
inheritance, `CloseHandle`, `GetThreadId`, `GetCurrentThread`, waits, and thread
lifecycle are not implemented.

Direct tests dirty the upper halves of all three argument registers, assert the
first policy handle `0x0000000f30001000`, and inspect its exact metadata and
normal `RAX`/`RIP`/`RSP` return effects. Further tests cover coherence with
`GetCurrentThreadId`, fresh handles on repeated opens, nonzero inheritability,
the legacy `0x4` bit, invalid IDs and access bits, the last valid handle,
collision/overflow/exhaustion failure atomicity, unmapped handle values, and a
call through the name-resolved synthetic kernel32 export stub. The handle value
is attributed to those direct and synthetic-trap artifacts: by the next bounded
production stop, guest code has already overwritten `RAX`, so the sample replay
is not claimed as a post-`OpenThread` return-value capture.

Reproduce the committed production path with:

```text
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 21
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 21
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 23
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 25
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 27
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 29
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  021: GetCurrentThreadId
  022: OpenThread
  023: GetProcessHeap
  024: RtlAllocateHeap
  025: GetProcessHeap
  026: RtlAllocateHeap
  027: GetProcessHeap
  028: RtlAllocateHeap
  029: GetProcessHeap
  030: RtlAllocateHeap
stop: ReachedUntil
```

The bounded pre-call captures identify the four additional allocation requests:

| Target call | `max_calls` | `RDX` flags | `R8` size |
|---:|---:|---:|---:|
| 24 | 23 | `0x8` | `0x410` |
| 26 | 25 | `0x8` | `0x10` |
| 28 | 27 | `0x8` | `0x410` |
| 30 | 29 | `0x8` | `0x10` |

Together with the two earlier requests, formal sample 1 now exercises the same
six sizes previously seen only on sample 3: `0x1000`, `0x10`, `0x410`, `0x10`,
`0x410`, `0x10`, all with flag `0x8`. Sample 2 has the same 30-call production
sequence as engineering corroboration. Sample 3 retains its separate 28-call
sequence with the same six allocation sizes and does not call
`GetCurrentThreadId` or `OpenThread`; its incomplete provenance prevents its use
as formal milestone evidence.

Full `trap_postmortem` captures reach a later zero-target control transfer:

| Sample | Calls | Stop | `RAX` | `RIP` | `[RSP-8]` |
|---|---:|---|---:|---:|---:|
| 1 | 30 | `Other("ReachedUntil")` | `0x0000000f40005000` | `0x0` | `0x0` |
| 2 | 30 | `Other("ReachedUntil")` | `0x0000000f40005000` | `0x0` | `0x0` |
| 3 | 28 | `Other("ReachedUntil")` | `0x0000000f40005000` | `0x0` | `0x0` |

### New frontier

The null VM-handler value after formal sample-1 call 30 has not yet been
diagnosed. No next API name is claimed. Sample 3's separately observed
`GetCurrentDirectoryW` selection remains unimplemented and is not evidence for
the formal sample-1 mechanism.

## GetCurrentDirectoryW is the causal post-allocation gap

Historical baseline note: the diagnosis in this section started from exact
merged `OpenThread` commit `f654d7a81afe887fed44c84337545cd88a2299d4`.
That baseline is the 30-call formal sample-1 path recorded in the preceding
section.

A temporary broad-name diagnostic first added the 1,664 export names parsed
from the authorized `samples/kernel32.dll`. The larger export walk required a
`600000000` per-leg instruction cap, but retained formal sample 1's exact first
30 production calls and changed the later null handler into an unhandled
`GetCurrentDirectoryW` call 31. Because the broad table changes both the
synthetic export layout and export-walk cost, it was discovery evidence only.

The decisive sample-1 A/B added only `GetCurrentDirectoryW` to the baseline
kernel32 seed and completed under the normal `60000000` cap. In both legs, the
post-call-30 path has 8,794 instructions and reaches the same final dispatcher
at `0x14005caf5`. The dispatch chain uses `RBP = 0x14006f9e0`, context cell
`0x14006fa68`, and handler slot `0x14005ea32`. The slot's last writer in both
legs is `0x1400accf7` (`mov [r9],rbx`) during the leg after call 6. Its bytecode
cursor is `0x140249ac2`, with words `[0x88, 0, 0x13c]`; destination selector
`0x88` and source selector `0` are unchanged. At baseline the writer's source
and stored value are zero. With only the new name present, both become the
name-resolved stub `0x00007fff00001010`, and the same final dispatcher reads
that address before the export trap reports `GetCurrentDirectoryW` as call 31.
The addresses are sample-1 and synthetic-layout evidence, not production
constants.

The broad-name table, single-name patch, memory-watch extension, trace driver,
and raw logs were temporary and uncommitted. The production code resolves and
dispatches the export by name. The committed tests and production replays below
are the independently reproducible artifacts.

Stopping before formal sample-1 call 31 with `max_calls = 30` preserves these
Win64 arguments:

```text
RCX = 0x0000000000000208
RDX = 0x0000000f40004000
RIP = 0x00007fff00001010
[RSP-8] = 0x00007fff00001010
```

Thus the observed call is
`GetCurrentDirectoryW(0x208, 0x0000000f40004000)`. The capacity is 520
`WCHAR`s, matching the `0x410`-byte fifth heap allocation in the captured
sequence. Sample 2 has the same call 31 as engineering corroboration. Sample 3
selects the same API as call 29 after its separate six-allocation path; its
incomplete provenance prevents that path from serving as formal milestone
evidence.

The documented Windows signature is
`DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer)`. On Win64,
dispatch consumes only the low 32 bits of `RCX` for the capacity and the full
64-bit `RDX` pointer. Capacity counts UTF-16 code units, not bytes. For a path
containing `L` units, a sufficient buffer receives the path plus one UTF-16 NUL
and the return is `L`, excluding the NUL. An insufficient buffer returns
`L + 1`, including space for the NUL; Windows does not specify the resulting
buffer contents. `(0, NULL)` is the documented size query. The Microsoft
contract is recorded at
<https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory>.

The bounded environment policy gives every `Win64Env` the fixed,
host-independent directory `C:\` (`[0x0043, 0x003a, 0x005c]`). Its path length
is three UTF-16 units and its required capacity is four. Capacity at least four
atomically writes `43 00 3a 00 5c 00 00 00`, leaves later bytes untouched, and
returns `3`. Smaller capacities return `4` without reading or writing the
buffer; the no-write choice is Midas policy for Windows' unspecified
undersized-buffer contents. Dispatch writes a deterministic zero-extended
`DWORD` result to `RAX` and performs the normal x64 return. Zero-extension is
environment policy rather than a claim about undefined high return bits on
Windows.

This slice does not consult the host current directory or filesystem. It does
not implement `SetCurrentDirectoryW`, per-drive state, UNC/device/extended
namespaces, long-path policy, normalization, case resolution, symlinks,
`GetCurrentDirectoryA`, concurrency, or last-error state. A sufficient request
with an invalid guest pointer remains an emulator memory error rather than an
invented Windows error mapping.

The six focused test cases cover:

- the documented `(0, NULL)` size query without a buffer access;
- the exact observed `(0x208, 0x0000000f40004000)` call, obtaining the pointer
  as the fifth modeled heap allocation after requests `0x1000`, `0x10`,
  `0x410`, `0x10`, `0x410`, then checking the UTF-16 result and untouched
  suffix;
- dirty upper `RCX` bits with low capacity four and a genuine output pointer
  above `u32::MAX`, proving DWORD-width capacity and full-width pointer use;
- capacities one, two, and three returning four without changing a sentinel
  buffer;
- stable content and return values across repeated calls; and
- a call through the name-resolved synthetic kernel32 export stub without a
  fixed RVA.

All direct calls assert deterministic full `RAX` plus exact `RIP` and `RSP`
return effects. The existing atomic `Emu::write_mem` primitive validates the
entire destination range before writing it.

Reproduce the production path with:

```text
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 30
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 30
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 28
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  021: GetCurrentThreadId
  022: OpenThread
  023: GetProcessHeap
  024: RtlAllocateHeap
  025: GetProcessHeap
  026: RtlAllocateHeap
  027: GetProcessHeap
  028: RtlAllocateHeap
  029: GetProcessHeap
  030: RtlAllocateHeap
  031: GetCurrentDirectoryW
stop: ReachedUntil
```

The full post-mortems show that the API returns `3` and all three paths later
reach another zero-target control transfer:

| Sample | Calls | API position | Stop | `RAX` | `RIP` | `[RSP-8]` |
|---|---:|---:|---|---:|---:|---:|
| 1 | 31 | 31 | `Other("ReachedUntil")` | `0x3` | `0x0` | `0x0` |
| 2 | 31 | 31 | `Other("ReachedUntil")` | `0x3` | `0x0` | `0x0` |
| 3 | 29 | 29 | `Other("ReachedUntil")` | `0x3` | `0x0` | `0x0` |

### New frontier

`GetCurrentDirectoryW` fixes the specific post-allocation null propagation and
advances formal sample 1 through call 31. The cause of the later null handler
has not yet been diagnosed, and no next API name is claimed. Sample 1 remains
the formal artifact; samples 2 and 3 remain engineering corroboration until
their provenance records are completed.

## GetModuleFileNameW is the causal post-current-directory gap

The diagnosis in this section started from exact merged `GetCurrentDirectoryW`
commit `1a4f5ca81f16d029e342c882b1af116fe4303a28`.

A temporary broad-name diagnostic added the 1,664 kernel32 export names parsed
from the authorized `samples/kernel32.dll`. With a `600000000` per-leg
instruction cap it retained formal sample 1's exact first 31 calls and changed
the later null handler into an unhandled `GetModuleFileNameW` call 32. The
broad-table stub RVA `0xf9b0` was a property of that temporary name-sorted
synthetic layout, not a production constant.

The decisive sample-1 A/B added only `GetModuleFileNameW` to the production
kernel32 seed and completed under the normal `60000000` cap. After manually
dispatching call 31, both legs execute 3,880 instructions and reach the same
dispatcher at `0x14005caf5`, with `RBP = 0x14006f9e0`. Context cell
`0x14006fa68` leads to the same handler slot `0x1400f8ee5`. Its last writer in
both legs is `0x1400accf7` (`mov [r9],rbx`) during the leg after call 6, at
bytecode cursor `0x140245e4f` with words `[0x88, 0, 0x13c]`. Destination
selector `0x88`, source selector `0`, and the source address at `RBP` are
unchanged. At baseline the source, `RBX`, and stored value are zero. With only
the new export name present, all three become the name-resolved stub
`0x00007fff00001030` (one-name RVA `0x1030`), and the same dispatcher reads
that address before the trap reports `GetModuleFileNameW` as call 32.

These addresses are sample-1 and synthetic-layout evidence, not production
constants. The broad table, one-name patch, trace instrumentation, and raw logs
were temporary and uncommitted, so the A/B is a captured investigation result
rather than a repository-reproducible artifact. The committed tests and
production replay below independently reproduce the resulting call.

Stopping before formal sample-1 call 32 with `max_calls = 31` preserves:

```text
RCX = 0x0000000000000000
RDX = 0x0000000f40002000
R8  = 0x0000000000000208
R9  = 0x0000000000000000
RIP = 0x00007fff00001030
[RSP-8] = 0x00007fff00001030
```

Thus the observed call is
`GetModuleFileNameW(NULL, 0x0000000f40002000, 0x208)`. The output pointer is
the third modeled heap allocation, requested as `0x410` bytes after earlier
`0x1000`- and `0x10`-byte requests. Its capacity is 520 `WCHAR`s. Sample 2
corroborates the same API as call 32. Sample 3 reaches it as call 30 after its
separate path; neither sample is formal milestone evidence until its provenance
record is completed.

The documented signature is
`DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)`.
On Win64, dispatch consumes the full widths of `RCX` and `RDX` and only the low
32 bits of `R8` for `nSize`. For a filename containing `L` UTF-16 units, a
capacity of at least `L + 1` receives the name plus a NUL and returns `L`.
Current Windows truncates a smaller nonzero buffer to `nSize` total units,
including a final NUL, returns `nSize`, and sets last error to
`ERROR_INSUFFICIENT_BUFFER` (`122`). A zero capacity returns zero and is not a
required-size query. Windows XP's different truncation behavior is not modeled.
The Microsoft contract is recorded at
<https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew>;
error code 122 is recorded at
<https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499->.

The bounded environment policy exposes `C:\guest.exe`, stored as 12 UTF-16
units without a trailing NUL. The required capacity is therefore 13 units, or
26 bytes including the terminator. `hModule == NULL` selects this path.
Capacities at least 13 atomically write the full path and NUL and return `12`;
capacities 1-12 write the first `capacity - 1` units plus a NUL and return the
capacity. Capacity zero returns zero without reading or writing the output
pointer. Nonzero module handles are outside this slice and return zero without
accessing the buffer.

The model does not consult the host executable path or filesystem. It does not
track filenames for arbitrary loaded modules, expose `GetModuleFileNameA`,
translate guest-memory failures into Windows errors, or maintain last-error
state. Modern truncation therefore omits the documented last-error side effect.
A sufficient request with an invalid guest range propagates the emulator memory
error without a partial write. Full `RAX` zero-extension is deterministic Midas
policy rather than a claim about undefined high return bits on Windows.

The seven focused tests cover:

- the exact observed call using the third genuine modeled heap allocation;
- exact-fit capacity 13, full-width pointers, low-32-bit capacity, suffix
  preservation, and repeat stability;
- modern truncation boundaries at capacities 1 and 12, including final NULs;
- capacity zero with both null and unmapped output pointers;
- a high-only nonzero `HMODULE`, proving full-width handle interpretation and
  no buffer write under the bounded unsupported-module policy;
- an invalid sufficient output range, asserting an atomic `WriteUnmapped`
  failure; and
- a call through the name-resolved synthetic kernel32 export stub without a
  fixed RVA.

All successful direct calls assert deterministic full `RAX` plus exact `RIP`
and `RSP` return effects. The shared UTF-16 encoder also replaces the equivalent
`GetCurrentDirectoryW` encoding loop; the full test suite covers that existing
behavior.

Reproduce the production path with:

```text
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 31
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 31
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 29
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  031: GetCurrentDirectoryW
  032: GetModuleFileNameW
stop: ReachedUntil
```

All three paths later reach another zero-target control transfer:

| Sample | Calls | API position | Stop | `RAX` | `RIP` | `[RSP-8]` |
|---|---:|---:|---|---:|---:|---:|
| 1 | 32 | 32 | `Other("ReachedUntil")` | `0x18` | `0x0` | `0x0` |
| 2 | 32 | 32 | `Other("ReachedUntil")` | `0x18` | `0x0` | `0x0` |
| 3 | 30 | 30 | `Other("ReachedUntil")` | `0x18` | `0x0` | `0x0` |

The full post-mortem `RAX = 0x18` is later guest state after it consumes the
filename, not the API return capture. The direct tests establish the modeled
return `12` and exact return-register effects for the observed sufficient
capacity.

### New frontier

`GetModuleFileNameW` fixes the specific post-`GetCurrentDirectoryW` null
propagation and advances formal sample 1 through call 32. The cause of the later
null handler has not yet been diagnosed, and no next API name is claimed.
Sample 1 remains the formal artifact; samples 2 and 3 remain engineering
corroboration until their provenance records are completed.

## SetCurrentDirectoryW is the causal post-module-filename gap

The diagnosis in this section started from exact merged `GetModuleFileNameW`
commit `b30bacbdda974e305be5fb6325df219e0bba6c9b`.

A temporary broad-name diagnostic added the 1,664 kernel32 export names parsed
from the authorized `samples/kernel32.dll`. With a `600000000` per-leg
instruction cap it retained formal sample 1's exact first 32 production calls
and changed the later null handler into an unhandled `SetCurrentDirectoryW`
call 33. The broad-table stub RVA `0x123f0` was a property of that temporary
name-sorted synthetic layout, not a production constant.

The decisive sample-1 A/B added only `SetCurrentDirectoryW` to the production
kernel32 seed and completed under the normal `60000000` cap. After manually
dispatching call 32, both legs execute the same 19,616 instructions, with FNV-64
trace digest `0xed9761b2cc4a09b8`, and reach the same final dispatcher at
`0x14005caf5`. With `RBP = 0x14006f9e0`, context cell `0x14006fa68` leads to the
same handler slot `0x14007c222`. Its last eight-byte writer in both legs is
`0x1400accf7` (`mov [r9],rbx`) during the leg after call 6, at bytecode cursor
`0x14024ba8b` with words `[0x88, 0, 0x13c]`. The destination and source
selectors, destination, and source address remain unchanged. At baseline the
source, `RBX`, and stored value are zero. With only the new name present, they
become the name-resolved stub `0x00007fff000010c0`, which the unchanged final
dispatcher reads before the trap reports `SetCurrentDirectoryW` as call 33.

These addresses are sample-1 and synthetic-layout evidence, not production
constants. The broad table, one-name patch, trace instrumentation, and raw logs
were temporary and uncommitted. The committed tests and production replay below
independently reproduce the resulting call.

Stopping before formal sample-1 call 33 with `max_calls = 32` preserves:

```text
RCX = 0x0000000f40002000
RIP = 0x00007fff000010c0
[RSP-8] = 0x00007fff000010c0
```

The input is the third modeled heap allocation, originally requested as
`0x410` bytes. Its leading UTF-16 units are
`43 00 3a 00 00 00 67 00 75 00 ...`: `L"C:"` followed by the stale
`guest.exe` suffix left by the preceding `GetModuleFileNameW` call. The first
NUL terminates the input, so those later units are not part of the path. Sample
2 corroborates the same API and pointer as call 33. Sample 3 reaches the same
input as call 31 on its separate path; neither sample is formal milestone
evidence until its provenance record is completed.

The documented signature is
`BOOL SetCurrentDirectoryW(LPCWSTR lpPathName)`. Windows accepts a relative or
full path, calculates and stores the resulting full current directory, and
ensures a trailing backslash. A drive designator without a following backslash
is drive-relative: `C:` selects the current directory retained for drive C and
does not intrinsically mean the root. Because the Midas environment has only
one modeled C-drive directory, already `C:\`, the observed `C:` resolves
idempotently to that canonical state. The Microsoft contracts are recorded at
<https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setcurrentdirectory>
and <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file>.

The bounded environment policy reads raw little-endian UTF-16 units through the
full 64-bit `RCX` pointer. It stops at the first NUL and scans at most 260 units,
including any terminator, so stale suffix data is ignored and an unterminated
guest range is bounded. Exact terminated selectors `C:` and `c:` set the
process directory to `C:\`, return zero-extended `BOOL` 1 in `RAX`, and perform
the normal x64 return. Other terminated paths and cap exhaustion return zero
normally without changing directory state. NULL, unmapped, page-crossing, and
overflowing pointers propagate their emulator memory/range errors before
directory, result-register, or control-register mutation.

This policy does not consult the host filesystem. It does not accept general
`C:\` paths, arbitrary relative paths, other drives, per-drive directory
history, UNC/device/extended namespaces, dot components, long-path opt-in, ANSI
conversion, symlink or case resolution beyond the drive letter, concurrency,
or last-error state. Invalid return-stack transactionality follows the existing
dispatcher contract and is outside this slice.

The seven focused tests cover:

- the exact heap-derived `L"C:"` input with the post-NUL `guest.exe` suffix,
  full-width pointer, stable input memory, success result, and coherent
  `GetCurrentDirectoryW` output;
- lowercase `c:` acceptance and canonical uppercase state;
- terminated empty, other-drive, drive-relative-subdirectory, ordinary
  relative, and UNC rejection with normal return and unchanged state/input;
- exactly 260 nonzero units ending at a mapped page boundary, proving cap
  exhaustion does not read the next page;
- NULL, unmapped, and overflowing base-pointer errors before state/result/control
  mutation;
- a page-end `C:` whose required terminator is unmapped, with the same atomicity;
  and
- a call through the name-resolved synthetic kernel32 export stub without a
  fixed RVA, followed by a coherent current-directory read.

Reproduce the production path with:

```text
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 32
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 32
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 30
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  031: GetCurrentDirectoryW
  032: GetModuleFileNameW
  033: SetCurrentDirectoryW
stop: unhandled API RtlAddVectoredExceptionHandler
```

The full replays distinguish the payload-dependent paths:

| Sample | Calls | `SetCurrentDirectoryW` position | Stop | `RAX` | `RIP` |
|---|---:|---:|---|---:|---:|
| 1 | 33 | 33 | unhandled `RtlAddVectoredExceptionHandler` | `0x0` | `0x00007fff00301010` |
| 2 | 33 | 33 | `Other("ReachedUntil")` | `0x0` | `0x0` |
| 3 | 33 | 31 | unhandled `RtlAddVectoredExceptionHandler` after `GetCurrentThreadId`, `OpenThread` | `0x0` | `0x00007fff00301010` |

The full-replay `RAX = 0` values are later guest state, not captures of the
`SetCurrentDirectoryW` return. Direct and name-resolved-trap tests establish the
modeled success return `1` and exact return-register/control effects.

### New frontier

`SetCurrentDirectoryW` fixes the specific post-`GetModuleFileNameW` null
propagation and advances formal sample 1 through call 33. Formal sample 1 then
directly calls the named, currently unhandled ntdll export
`RtlAddVectoredExceptionHandler` with `RCX = 1` and
`RDX = 0x000000014006aa83`; sample 3 corroborates that API with its own handler
address after two additional calls. Sample 2 instead reaches an indirect call
through zero.
`RtlAddVectoredExceptionHandler` is the formal next Win64 frontier and is not yet
implemented.

## RtlAddVectoredExceptionHandler is the direct call-34 frontier

This slice starts from exact merged `SetCurrentDirectoryW` commit
`5893703dedff575ad6fc6913029d5dd4390b322f`. No export-name A/B was needed:
the baseline already stopped at the name-resolved ntdll stub. Stopping formal
sample 1 after its first 33 handled calls preserves the exact pre-call state:

```text
RCX = 0x0000000000000001
RDX = 0x000000014006aa83
R8  = 0x0000000000000208
R9  = 0x0000000000000000
RIP = 0x00007fff00301010
RSP = 0x0000000fffffefc8
[RSP] = 0x0000000140227ab4
```

Thus formal call 34 is
`RtlAddVectoredExceptionHandler(1, 0x000000014006aa83)`. Sample 3 reaches the
same named call as engineering corroboration on its separate path, with
`RCX = 1`, callback `RDX = 0x00000001400e5dbc`, and return address
`0x0000000140210e33`. Its provenance is incomplete, so it is not formal
milestone evidence. Sample 2 does not exercise this export in the captured
path.

Microsoft documents the public
`AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)`
contract: zero appends the handler, nonzero puts it first, success returns an
opaque handle, and failure returns NULL. The handle is later consumed by
`RemoveVectoredExceptionHandler`. The public contracts are recorded at
<https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler>,
<https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredexceptionhandler>,
and
<https://learn.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler>.
The observed export is the lower-level ntdll name, not the documented wrapper.

Clean-room compatibility implementations corroborate that the private
`RtlAddVectoredExceptionHandler` has the same two arguments. ReactOS at
[`c296dcfa`](https://github.com/reactos/reactos/blob/c296dcfa29e7f32b623d8ed3e70604a06472fda2/sdk/lib/rtl/vectoreh.c#L152-L193)
and Wine at
[`f26c699d`](https://gitlab.winehq.org/wine/wine/-/blob/f26c699db5176caee6883210f949110de3af520d/dlls/ntdll/exception.c#L102-117)
both allocate a fresh registration, insert it at the head for any nonzero
`First` and at the tail for zero, and return the registration as the handle.
Neither implementation probes or deduplicates the callback during
registration. Their private node layouts differ, reinforcing that the returned
value must remain opaque. This is compatibility evidence, not an assertion
about native Windows' private layout. In particular, accepting a NULL callback
without probing it is a bounded Midas policy supported by those implementations,
not a Microsoft-documented guarantee for invalid input.

A disposable return-sensitivity experiment checked whether the captured guest
path selected a particular handle identity. Temporary variants returned NULL,
the callback address, or opaque value `0x0000000f30002000`, then performed the
same normal API return. Formal sample 1 executed 5,781 post-return instruction
addresses under every variant with FNV-64 digest `0x3fec30c5cec96161` and the
same later ret-to-zero state. Sample 3 executed 7,552 under every variant with
digest `0x1c13248694b65815` and the same stop. This finite trace shows that the
captured paths ignore the registration return value; it does not justify
returning failure or exposing the callback as the handle. The variants and raw
logs were temporary and uncommitted.

The bounded `Win64Env` policy therefore models registration identity and order
without inventing callback execution:

- dispatch consumes only low `ECX` for the `ULONG First` argument and the full
  `RDX` callback value;
- every success stores the callback exactly, including duplicate, NULL, or
  unmapped values, without a guest-memory read or probe;
- `First == 0` appends, while any nonzero low-32-bit value prepends;
- every call receives a fresh, full-width opaque token. The deterministic token
  namespace begins immediately after the fixed PEB mapping at
  `0x0000000f20001000`, advances by `0x10`, and has the unmapped process-heap
  handle `0x0000000f30000000` as its exclusive upper bound; and
- checked-add, range, alignment, collision, and exhaustion failures return NULL
  without changing the token cursor or ordered registration list. A success
  writes the token to full `RAX` and performs the normal x64 return.

The namespace is intentionally unmapped and disjoint from the fixed guest
mappings and modeled heap backing; the opaque token does not expose either
ReactOS' or Wine's node layout or substitute the callback value. This slice does
not invoke callbacks, remove registrations, dispatch
exceptions, allocate guest-visible nodes, maintain reference counts, model
lifetime or process exit, synchronize concurrent access, or update last-error
state. Registration state changes before the shared `api_return` reads the
guest return stack, so invalid-return-stack transactionality remains outside
this slice's allocator-atomicity claim, consistent with the existing dispatcher
contract.

The six focused tests cover:

- the exact formal sample-1 arguments, a callback deliberately unmapped in the
  synthetic test environment, the first opaque token, its unmapped/full-width
  identity, and exact `RAX`/`RIP`/`RSP` return effects;
- dirty upper `RCX` bits, low-32-bit zero/nonzero interpretation, FIFO tail and
  repeated-head ordering, sequential fresh tokens, and full-width callbacks;
- independent duplicate and NULL callback registrations without callback-memory
  access;
- below-range, misaligned, upper-bound, overflow, collision, last-valid-token,
  and exhausted-cursor cases, with cursor/list preservation on every failure;
- deterministic isolation between two `Win64Env` instances; and
- a call through the name-resolved synthetic ntdll export stub without a fixed
  RVA, preserving the observed arguments and balanced stack.

Reproduce the production path with:

```text
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 33
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 33
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  031: GetCurrentDirectoryW
  032: GetModuleFileNameW
  033: SetCurrentDirectoryW
  034: RtlAddVectoredExceptionHandler
stop: ReachedUntil
```

Release `run_loader` and `trap_postmortem` agree on the handled call counts and
names. The full post-mortems are:

| Sample | Calls | Registration position | Stop | `RAX` | `RIP` | `RSP` |
|---|---:|---:|---|---:|---:|---:|
| 1 | 34 | 34 | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0000000fffffefc8` |
| 2 | 33 | not called | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0000000fffffefc8` |
| 3 | 34 | 34 | `Other("ReachedUntil")` | `0x000000014008f837` | `0x0` | `0x0000000fffffef78` |

The final `RAX` values are later guest state, not registration-return captures.
The direct and name-resolved tests establish the successful first token
`0x0000000f20001000` and its exact return-register effects.

### New frontier

`RtlAddVectoredExceptionHandler` advances formal sample 1 through call 34. It
then executes the finite post-return path and returns through zero without
another named API. Sample 3 corroborates that shape after its separate call 34;
sample 2 reaches its earlier independent indirect call through zero after call
33. The next causal gap has not yet been diagnosed, and no next API name is
claimed. Formal
sample 1 remains the milestone artifact; samples 2 and 3 remain engineering
corroboration until their provenance records are completed.

## GetVersion is the causal call-35 frontier

This diagnosis starts from exact merged `RtlAddVectoredExceptionHandler` commit
`661e8b285aff591bebbed3031dc28cbfc308f76d`. On that baseline, formal sample 1
returns the first registration token `0x0000000f20001000` to
`0x0000000140227ab4`, executes 5,781 more instructions, and reaches `RIP = 0`.
The FNV-1a digest over the little-endian 64-bit instruction addresses in that
suffix is `0x3fec30c5cec96161`.

The terminal zero is carried through the existing VM dispatch chain. On formal
sample 1, `RBP = 0x000000014006f9e0`; bytecode cursor
`0x0000000140211e72` selects context offset `0x88`. The context qword at
`RBP + 0x88` points to handler slot `0x00000001400d42a7`.
`.themida+0x5caf5` reads zero from that slot, `.themida+0x5cb1a` writes the zero
to stack cell `0x0000000fffffefc0`, and `.themida+0x5cb7c: ret 0` consumes it.
The slot's last whole-qword writer is `.themida+0xaccf7: mov [r9],rbx`, observed
735,488 instructions into the leg after handled call 6, with `R9` equal to the
slot and `RBX = 0`. Its bytecode cursor is `0x0000000140242ff6`, beginning with
words `0x0088, 0x0000, 0x013c`; the source selector is zero and reads the
zeroed `RBP + 0` context qword. A disposable late patch replacing only the slot
with the already-mapped registered callback preserved all 5,781 instruction
addresses and the digest but made the final `ret` land at the callback. This
establishes the slot-to-terminal-return edge; it does not identify the missing
name by itself.

The missing name was determined with two export-name A/B experiments. A broad
variant parsed exactly 1,664 export names from the authorized
`samples/kernel32.dll` reference and used the names only; the DLL was never
mapped or executed. It preserved the exact 34-call prefix and then stopped at
an unhandled `GetVersion` export. A narrow variant added only `GetVersion` to
the baseline seed and reproduced the same call at the ordinary 60,000,000
per-leg cap. The broad-layout stub `0x00007fff00010470` and narrow-layout stub
`0x00007fff00001090` are synthetic export-layout results, not sample constants.
Together, the broad discovery and one-name A/B establish `GetVersion` as formal
call 35.

The trace hooks, slot patch, export-name variants, diagnostic sources, and raw
logs used for this diagnosis were temporary and uncommitted; their isolated
worktrees were removed. The committed artifacts are the bounded implementation
and tests plus the production replays recorded below.

Stopping production after 34 handled calls now preserves the exact pre-call
state:

```text
RAX = 0x0000000000000000
RCX = 0x0000000000000001
RDX = 0x000000014006aa83
R8  = 0x0000000000000208
R9  = 0x0000000000000000
RIP = 0x00007fff00001090
RSP = 0x0000000fffffefc8
[RSP] = 0x00000001401ffc3d
```

The documented signature is `DWORD GetVersion(void)`, so the register values
other than `RAX`, `RIP`, and `RSP` are restored incidental state rather than API
arguments. Microsoft documents the result packing and the version-manifest
behavior at
<https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion>.
The formal PE's resource data-directory entry is zero, and no sidecar manifest
is present with the captured sample. Midas therefore uses an explicit,
host-independent unmanifested Windows 8 compatibility policy: major 6, minor 2,
build 9200, and a clear platform bit, packed as `DWORD 0x23f00206`. This is a
fixed emulated-environment policy, not host OS detection or a claim that the
finite sample trace determines Windows version semantics.

A disposable return-sensitivity trace measured the formal post-call path:

| Return | Post-return instructions | FNV-1a RIP digest |
|---|---:|---:|
| `0x00000000` | 21,888 | `0xec2af30cbcaf1b27` |
| `0x23f00206` (6.2.9200) | 22,275 | `0x6b2b7e01ee2164f9` |
| `0x4a65000a` (10.0.19045) | 22,275 | `0x6b2b7e01ee2164f9` |

All three variants handled exactly 35 calls, reached no later named API, and
eventually returned through zero. Additional isolated controls changed the
build, minor, and major fields separately. A major value of 6 alone selected
the 22,275-instruction path; minor 2 alone and build 9200 alone selected the
short path. Majors 6, 7, and 10 shared the long digest, major 4 selected the
short path, and major 5 selected a third 22,472-instruction path with digest
`0xe569a4df55a5bdbd`. This finite experiment establishes that the captured
branch is sensitive to a major-version class. It does not justify the chosen
minor/build values, which remain the explicit compatibility policy above.

The implementation adds the observed name to the synthetic kernel32 seed and
returns `0x23f00206` zero-extended through full `RAX`, followed by the normal
x64 API return. This handler does not read or mutate the incidental argument
registers; their preservation is modeled behavior, not an ABI guarantee. It
does not inspect guest resources or manifests, consult the host OS, apply
compatibility shims, model service-pack or product-type data, implement
`GetVersionEx`/`VerifyVersionInfo`, or update last-error state.

The two focused tests cover:

- two direct calls from dirty result/argument-register states, exact packing of
  major, minor, build, and platform fields, stable full-width return,
  non-mutation of incidental registers, and exact `RIP`/`RSP` effects; and
- a call through the name-resolved synthetic kernel32 export stub without a
  fixed RVA, with the expected trap, result, loop target, and balanced stack.

Reproduce the production path with:

```text
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 34
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  033: SetCurrentDirectoryW
  034: RtlAddVectoredExceptionHandler
  035: GetVersion
stop: ReachedUntil
```

Release `run_loader` and `trap_postmortem` agree on the handled call counts and
names. The full post-mortems are:

| Sample | Calls | `GetVersion` position | Stop | `RAX` | `RIP` | `RSP` |
|---|---:|---:|---|---:|---:|---:|
| 1 | 35 | 35 | `Other("ReachedUntil")` | `0x0000000140058fa0` | `0x0` | `0x0000000fffffef78` |
| 2 | 33 | not called | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0000000fffffefc8` |
| 3 | 34 | not called | `Other("ReachedUntil")` | `0x000000014008f837` | `0x0` | `0x0000000fffffef78` |

The final `RAX` values are later guest state, not `GetVersion` return captures.
The direct and name-resolved tests establish the exact zero-extended
`0x23f00206` return and control effects.

### New frontier

`GetVersion` advances formal sample 1 through call 35 and selects the observed
nonzero-major path. The guest then executes 22,275 post-return instructions and
returns through zero without another named API. The source of that new terminal
zero has not yet been diagnosed. Sample 2 retains its separate indirect
call-through-zero after call 33; sample 3 retains its separate ret-to-zero after
call 34 and does not exercise `GetVersion`. Formal sample 1 remains the
milestone artifact; samples 2 and 3 remain engineering corroboration until
their provenance records are completed.

## CreateThread is the causal call-36 frontier

This diagnosis was captured against exact reviewed `GetVersion` commit
`2f9758394e7a913bbf3620c5f1501589c94b6c3b`. The exact merged base for this
slice is `a1beb21d9352fae2f9de0722bacc14350bb690a1`; both commits have tree
`86f4ff658dd46e11a133b91ac6a857125e7d0c9a`. The diagnostic and merged
starting code are therefore byte-identical. Formal sample 1 is the milestone
artifact throughout this section. Samples 2 and 3 have the incomplete
source/pre-protection provenance recorded in `samples/SAMPLES.md` and are cited
only as engineering corroboration.

On that baseline, `GetVersion` traps at synthetic stub
`0x00007fff00001090` with `RSP = 0x0000000fffffefc8`. Dispatch returns
`0x23f00206` to `0x00000001401ffc3d` and advances `RSP` to
`0x0000000fffffefd0`. The suffix from there contains exactly 22,275 executed
RIPs; its FNV-1a digest over little-endian 64-bit addresses is
`0x6b2b7e01ee2164f9`. Its last instruction is
`0x000000014005cb7c: ret 0`, which consumes zero from
`0x0000000fffffef70` and leaves `RSP = 0x0000000fffffef78`. The last suffix
write to that cell is instruction 22,244 at
`0x000000014005cb1a: mov [rsi],r13`, with `RSI` equal to the cell and
`R13 = 0`.

The final dispatcher state gives the source of that zero. `RBP` is
`0x000000014006f9e0`; the bytecode at `0x0000000140256028` begins
`53 00 c8 0b 00 00`, whose selector `0x53` and displacement `0x0bc8` lead
through handler-table slot `0x000000014007441e`, whose encoded value
`0x00000001400ae431` resolves to handler `0x000000014005caae`. Its payload at
`0x0000000140256bf0` begins
`1e 96 25 00 80 00 88 00`: continuation RVA `0x25961e`, stack offset
`0x80`, and context selector `0x88`. The selected qword is
`[RBP + 0x88] = [0x000000014006fa68] = 0x000000014006f8f0`; that target
contains zero, and no post-`GetVersion` instruction changes it.

The target's earlier whole-qword writer occurs after handled call 6 and before
call 7: watched epoch 7, instruction 1,027,184, at
`0x00000001400accf7: mov [r9],rbx`, with `R9` equal to the target and
`RBX = 0`; its old value was `0x69615bde`. The zero originated in the loader's
manual walk of the synthetic kernel32 `IMAGE_EXPORT_DIRECTORY`. The path
performs a linear ASCII export-name comparison whose sought first byte is
`C`. The baseline candidates at exhaustion are `VirtualAlloc`, `VirtualFree`,
and `VirtualProtect`; the remaining-name count drains to zero and
`0x000000014013e90a: ret 18h` returns zero. At instruction 1,025,557,
`0x00000001400ed1d1: push rax` places that zero on the VM stack, and the
pop-copy sequence beginning at `0x00000001400ed1d8` propagates it. The last
write to the `RBP + 0` context qword is instruction 1,026,934 at
`0x00000001400996fc: mov [rcx],r15`, immediately after
`0x00000001400996fa` pops zero from `0x0000000fffffefe0`. That context result
feeds the later `0x00000001400accf7` store and is eventually selected by the
final return handler.

Two isolated export-name experiments identify the missing name without making
the zero propagation itself a production mechanism:

- A broad variant parsed exactly 1,664 names from the authorized
  `samples/kernel32.dll` reference after checking its recorded hash. It used
  only export names; it did not map or execute the DLL. The variant preserved
  the exact handled calls 1–35, then reached an unhandled `CreateThread` at
  broad-layout synthetic stub `0x00007fff0000e100`.
- A narrow variant added only `CreateThread` to the 17-name baseline seed. At
  the normal 60,000,000-instruction per-leg cap it reproduced call 36 at
  narrow-layout synthetic stub `0x00007fff00001000`, with the same 22,275-RIP
  suffix and digest before the call.

The two stub addresses are consequences of their temporary synthetic export
layouts, not constants from the sample. The preserved broad prefix plus the
one-name A/B establishes `CreateThread` as formal sample-1 call 36.

Stopping the narrow run immediately before dispatch captures this exact callee
state:

```text
RAX       = 0x0000000140058fa0
RCX       = 0x0000000000000000
RDX       = 0x0000000000000000
R8        = 0x0000000140058fa0
R9        = 0x0000000000000000
RSP       = 0x0000000fffffef78
[RSP]     = 0x000000014025961e
[RSP+0x28]= 0x0000000000000000
[RSP+0x30]= 0x0000000000000000
```

Under the Win64 ABI, arguments 1–4 occupy `RCX`, `RDX`, `R8`, and `R9`, stack
argument 5 begins at callee `RSP + 0x28`, and argument 6 begins at
`RSP + 0x30`. Microsoft documents that convention at
<https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170>.
The observed call is therefore:

```text
CreateThread(NULL, 0, 0x0000000140058fa0, NULL, 0, NULL)
```

Microsoft documents the six-argument contract, NULL/default attributes and
stack behavior, creation flags, optional `DWORD` thread-ID output, NULL failure
return, thread handle, and the fact that an invalid start address need not make
creation fail because the execution failure can be deferred until the new
thread runs at
<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread>.
Thread-ID lifetime and handle/ID distinction are documented at
<https://learn.microsoft.com/en-us/windows/win32/procthread/thread-handles-and-identifiers>.

The observed start address `0x0000000140058fa0` is readable in the mapped
image and begins `jmp 0x00000001402864f8`. Both addresses lie in the RWX
`.themida` section, whose characteristics are `0xe0000060`. The target begins
with `pushf`, `sub rsp, 8`, an `r14` save, and opaque arithmetic. This evidence
makes it a downstream thread-entry candidate only. The implementation neither
schedules nor executes it, and this section does not classify it as the OEP.

A disposable return-sensitivity handler compared three injected return values
while leaving the formal call arguments unchanged:

| Return | Post-return instructions | FNV-1a RIP digest | Later named calls | Stop |
|---:|---:|---:|---|---|
| `0x0000000000000000` | 19,572 | `0x203e6e80809eb565` | 37 `GetProcessHeap`; 38 `RtlAllocateHeap` | `RIP = 0` |
| `0x0000000f30001010` | 19,572 | `0x203e6e80809eb565` | 37 `GetProcessHeap`; 38 `RtlAllocateHeap` | `RIP = 0` |
| `0x0000000f30001020` | 19,572 | `0x203e6e80809eb565` | 37 `GetProcessHeap`; 38 `RtlAllocateHeap` | `RIP = 0` |

The finite captured path is insensitive to NULL versus these two non-NULL
handle identities. This does not imply that general guest code can ignore the
documented success/failure distinction.

### Bounded CreateThread policy

The implementation adds `CreateThread` to the synthetic kernel32 seed and
reads the six arguments at their ABI widths: full-width pointers and `SIZE_T`,
exactly four bytes for `DWORD dwCreationFlags` at callee `RSP + 0x28`, and a
full-width optional output pointer at `RSP + 0x30`. All arguments are read
before state mutation.

The accepted policy is deliberately limited to NULL thread attributes, zero
requested stack size, and zero creation flags. It records the full start and
parameter values without probing either address, allocates a fresh nonzero
`DWORD` thread ID beginning at 2, and returns a fresh opaque handle from the
existing bounded kernel-handle namespace. The record's state is runnable but
unscheduled. If the optional output pointer is non-NULL, the handler validates
and writes exactly four bytes before committing ID, thread, handle, or cursor
state. The handle is noninheritable because the accepted attributes pointer is
NULL and carries `0x001f03ff`, the complete legacy rights universe already
modeled by Midas rather than a claim about every version-dependent Windows
`THREAD_ALL_ACCESS` value.

Created IDs are accepted by the existing `OpenThread` policy. ID 1 remains the
current executing thread because no created record is scheduled. The ID cursor
can issue every value through `u32::MAX` once and then enters an explicit
exhausted state; the handle cursor retains its existing bounded unmapped range
and stride. Unsupported attributes, stack size, or flags return NULL before
probing an output pointer. ID/handle range, alignment, collision, and exhaustion
failures also return NULL without changing output or allocator state. A valid
request with an unmapped, read-only, page-crossing, or overflowing output range
returns an emulator error before any thread state is committed.

This slice does not allocate a guest stack, TEB, or TLS data; schedule or run a
start routine; send DLL thread notifications; model suspended creation,
resume/suspend, termination, waits, signaling, handle close/reuse, or process
exit; implement ACL/token checks or detailed descriptor/inheritance behavior;
or update last-error state. As with the other dispatch handlers, state committed
before the shared return-stack read is not claimed transactional for a malformed
API return frame.

The nine focused tests cover:

- the exact formal call after the earlier `OpenThread`, including the next
  handle identity, ID 2, stored runnable-unscheduled record, and exact
  `RAX`/`RIP`/`RSP` effects;
- full-width start, parameter, and output pointers; acceptance of NULL and
  deliberately unmapped starts without probing; fresh IDs; an exact four-byte
  output write with adjacent-byte preservation; and `OpenThread` coherence for
  a created ID;
- every unsupported-policy case without output access, including dirty upper
  bytes in the eight-byte stack slot proving that only the low four-byte flags
  object is consumed;
- last-valid ID and handle allocation, explicit exhaustion, malformed cursor,
  alignment, and occupied-candidate cases with unchanged allocator/output
  state on rejection;
- deterministic isolation between two `Win64Env` instances;
- unmapped and overflowing stack arguments before result, control, or thread
  mutation;
- unmapped, read-only, page-crossing, and overflowing optional output ranges
  with output and state preservation; and
- a call through the name-resolved synthetic kernel32 export stub, using a
  real 0x30-byte caller reservation for the shadow area and two stack arguments,
  with balanced caller `RSP` and no fixed stub RVA.

Reproduce the tests and production paths with:

```text
cargo test --all-targets
cargo build --locked --release --example run_loader --example trap_postmortem
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 35
target/release/examples/run_loader samples/test_target_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target2_protected.exe 60000000 200
target/release/examples/run_loader samples/test_target3_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target2_protected.exe 60000000 200
target/release/examples/trap_postmortem samples/test_target3_protected.exe 60000000 200
```

The exact formal sample-1 production suffix is:

```text
  034: RtlAddVectoredExceptionHandler
  035: GetVersion
  036: CreateThread
  037: GetProcessHeap
  038: RtlAllocateHeap
stop: ReachedUntil
```

Release `run_loader` and `trap_postmortem` agree on these handled-call counts
and names:

| Sample | Evidence role | Calls | `CreateThread` position | Start address | Stop | `RAX` | `RIP` | `RSP` |
|---|---|---:|---:|---:|---|---:|---:|---:|
| 1 | formal | 38 | 36 | `0x0000000140058fa0` | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0000000fffffefc8` |
| 2 | engineering corroboration | 33 | not called | — | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0000000fffffefc8` |
| 3 | engineering corroboration | 37 | 35 | `0x000000014008f837` | `Other("ReachedUntil")` | `0x0` | `0x0` | `0x0000000fffffefc8` |

The final `RAX` values are later guest state, not `CreateThread` return
captures. The direct and name-resolved tests establish the successful bounded
handle and exact return-control effects.

### New frontier

At the CreateThread-only checkpoint, formal sample 1 advances through call 36.
That production tree then uses the existing `GetProcessHeap` and
`RtlAllocateHeap` handlers as calls 37 and 38 before returning through zero. A
disposable broad export-name control on formal sample 1, corroborated by a
narrow `CreateThread`-plus-`Sleep` seed, continues to `Sleep` as call 39 with
`RCX = 1`; both the disposable NULL and non-NULL `CreateThread` return variants
reach the same call. The checkpoint export seed did not contain `Sleep`, so
that slice captured a stop after call 38 at the ret-to-zero. The subsequent
Sleep slice below changes that frontier. Sample 2 does not call `CreateThread`;
sample 3 corroborates it at its separate call 35 and reaches 37 calls before
ret-to-zero, subject to its provenance limitation. Scheduling the recorded
thread-entry candidate also remains outside the CreateThread slice.

## Sleep exposes a stable polling loop after call 39

The isolated diagnosis for this slice began from exact merged `CreateThread`
commit `ca0daf054ec8bacd2f8d246387ed708d60b3d374`. Formal sample 1 is the
milestone artifact. Samples 2 and 3 retain the incomplete
source/pre-protection provenance recorded in `samples/SAMPLES.md` and are cited
only as engineering corroboration.

A disposable narrow export seed added only `Sleep` to the reviewed baseline.
The formal 38-call prefix remained behaviorally stable, then the loader reached
`Sleep` as call 39 at seed-layout stub `0x00007fff000010f0`. That address is
derived from the temporary sorted export layout and is not a sample or
production constant. Immediately before dispatch:

```text
RAX    = 0x0000000000000000
RBX    = 0x0000000140060000
RCX    = 0x0000000000000001
RDX    = 0x0000000000000008
RSI    = 0x0000000f40002004
RDI    = 0x0000000140111133
RBP    = 0x000000014004f000
RSP    = 0x0000000fffffefc8
R8     = 0x0000000000000010
R9-R15 = 0x0000000000000000
RIP    = 0x00007fff000010f0
[RSP]  = 0x00000001401867d6
```

This establishes the observed argument as `Sleep(1)`. Microsoft documents
`Sleep(DWORD dwMilliseconds)` as a `VOID` function that suspends the current
thread until the interval elapses; zero yields its remaining time slice and
`INFINITE` does not time out. The elapsed interval makes the thread ready, not
necessarily running immediately, and timing depends on system clock resolution:
<https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep>.

Returning immediately from call 39 reaches the same `Sleep(1)` stub again as
call 40. The steady leg contains exactly 3,527 executed RIPs, beginning at the
on-stack return address `0x00000001401867d6` and ending at
`0x000000014005cb7c`; its FNV-1a digest over little-endian 64-bit addresses is
`0x7fce9fdb31fbfd70`. Repeating to a 10,000-call bound handles 9,962 `Sleep`
calls after the original 38-call prefix and stops only at `max_calls`; it does
not reach another named export. Because `run_with_import_trap` applies its
instruction cap separately to each resume leg, this 3,527-instruction loop also
shows that `max_calls` is currently the effective whole-run bound for this path.

An isolated return-sensitivity experiment preserved all other state and tried
the incoming formal zero, a forced zero, and marker
`0x0000000f30001aa0` in `RAX`. Every variant produced the identical 3,527-RIP
leg and digest; the marker remained present at call 40. This proves that the
captured leg does not consume `RAX`. It does not turn `RAX` into a return value:
the Windows function is `VOID`, and preserving it is an explicit deterministic
Midas policy rather than an ABI guarantee.

### Bounded Sleep policy

Production adds only `Sleep` to the synthetic kernel32 seed and consumes the
low 32 bits of `RCX` as the `DWORD` interval. Every finite positive interval
from `1` through `0xfffffffe` uses deterministic immediate wait elision and the
scalar-free `ApiOutcome::HandledVoid` path. The shared API return consumes the
on-stack return address and advances `RSP` by eight. `RAX`, all incidental
general registers, and flags remain unchanged by policy. There is no host
sleep, elapsed or virtual time, timer-resolution model, scheduler, yield,
interleaving, or execution of a recorded created thread.

Intervals zero and `0xffffffff` (`INFINITE`) are unsupported because their
yield/nontermination semantics cannot be represented by immediate completion.
They return `Unhandled` before the dispatcher reads the return stack or mutates
machine or environment state. A finite-positive call with an invalid return
frame retains the shared dispatcher error ordering and is failure-atomic for
the state modeled by this handler.

The five focused tests cover the observed interval one with dirty upper `RCX`
bits; representative and finite-boundary generalization cases; zero and
`INFINITE` rejection without stack access; invalid return-frame pointers with
the 18-register observation snapshot and unchanged `Win64Env` state; and
name-resolved export dispatch with genuine Win64 shadow space, balanced caller
`RSP`, and no fixed stub RVA. The verification matrix is:

```text
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 115 passed
cargo clippy --all-targets -- -D warnings
git diff --check
cargo build --locked --release --example run_loader --example trap_postmortem
```

Release `run_loader` and `trap_postmortem` agree on the production paths:

| Sample | Evidence role | Preserved prefix | First `Sleep` | Result at `max_calls = 200` |
|---|---|---:|---:|---|
| 1 | formal | 38 calls | 39 | 162 `Sleep(1)` calls; stops at `max_calls` |
| 2 | engineering corroboration | 33 calls | not reached | unchanged `ReachedUntil` |
| 3 | engineering corroboration | 37 calls | 38 | 163 `Sleep(1)` calls; stops at `max_calls` |

At both the 40- and 200-call bounds, formal sample 1 is poised at the same
derived Sleep stub with `RCX = 1`, `RSP = 0x0000000fffffefc8`, and the same
`[RSP] = 0x00000001401867d6`. Sample 3 has the analogous stable loop with
return address `0x0000000140255091`. The final `RAX = 0` in these captures is
guest state and must not be read as a `Sleep` return value.

### New frontier

The production artifact exposes a stable main-thread polling loop rather than
another missing export. A separate disposable trace on the exact baseline
identified its semantic condition. At `0x000000014005ffeb`, the guest executes
`cmp byte [r12],dil` with `R12 = 0x000000014005aae0`, `DIL = 0`, and the byte
equal to zero. The resulting `ZF = 1` flows through VM selector `0x9b` at cursor
`0x000000014029563f`, decoded as JNE; because the comparison is equal, the
branch is not taken and the path reaches another `Sleep(1)`.

The cell is rawless RWX `.themida` RVA `0x5aae0` and begins as mapped zero. A
whole-prefix overlap-aware watch found exactly one guest write before the first
Sleep: initial-run instruction 425,458 at `0x000000014030b1c5` executes
`rep movsb`, copying zero from `0x000000014005aad8` into the cell. No later
main-thread writer was observed. Changing only the cell from zero to one
immediately before the compare clears `ZF`, avoids the next Sleep, and reaches
`RIP = 0` after 66,588 executed instructions from the prior Sleep return; that
intervened suffix has FNV-1a RIP digest `0x7ce3875e603e7b59`. This establishes
the byte comparison as causal for repetition of the captured loop. It does not
identify the Windows event or loader state the byte represents.

### Isolated execution of the recorded child does not release the poll

A second disposable control ran formal sample 1's created ID 2 directly from
recorded start `0x0000000140058fa0`, parameter zero, in the already transformed
shared guest image. The control used a disjoint 1 MiB RW/NX stack, an aligned
Win64 entry frame with 32-byte shadow space and an unmapped return sentinel, a
separate minimal TEB selected through `GS_BASE`, deterministic register state,
and exact save/restore of the tracked 20-register main-thread set. These are
diagnostic conditions, not a production scheduler or a claim of
Windows-faithful thread startup.

The child handles `LoadLibraryA` and `GetProcAddress`, then reaches unhandled
`timeGetTime` after 14,086 guest instructions at dynamic proc stub
`0x00007ffe00000020`; its on-stack return address is
`0x000000014021a15d`. It reads the separate TEB Self qword three times at
`0x00000001400ef7b5`, confirming that per-thread `GS`/TEB identity is consumed
on this path. Diagnostic-only `timeGetTime` returns of zero, one, and
`0x89abcdef` all produce the same 18,188-instruction terminal path at
`RIP = 0`. The supplied low `DWORD` is stored at `0x000000014009af1d`, but the
tail consumes an internal zero instead of reaching the installed return
sentinel. The capture therefore does not establish a clean start-routine
return; missing thread-start/VM context and an intentional zero terminal edge
remain unresolved alternatives.

An overlap-aware watch recorded no child read or write of poll cell
`0x000000014005aae0`, which remained zero. The original main stack and main TEB
were byte-identical before and after the child control. Restoring 20 main CPU
registers, including flags and `FS_BASE`/`GS_BASE`, then applying the bounded
immediate Sleep return reproduces the next Sleep in exactly 3,527 RIPs with
baseline digest `0x7fce9fdb31fbfd70` for all three diagnostic clock results.

This falsifies the narrow hypothesis that scheduling the recorded child once,
under the tested direct-entry conditions, releases this particular Sleep loop.
It does not falsify all scheduling models: a Windows startup thunk, fuller
per-thread/TLS initialization, callbacks, interleaving, or time evolution were
not modeled. The child supplies observation-driven evidence for a future
bounded `timeGetTime` policy and for context/stack/TEB isolation, while its zero
edge requires diagnosis before a scheduler can claim faithful thread lifecycle.
No result in this section identifies an OEP.

## Owner-checked CPU contexts provide the restore primitive

The next bounded groundwork slice began from exact merged Sleep commit
`707936e6bd797aca1a17ce469b04fe8e1a93f869`. It changes only the emulator
layer. No sample replay is part of this slice because no production runner or
Win64 dispatch path consumes the new primitive.

`Emu::new` now selects Unicorn `ContextMode::CPU`. The public opaque
`CpuContext` supports three operations: capture the current CPU state into a
new native allocation, overwrite that allocation with a later state, and
restore it repeatedly. Every `Emu` and its contexts share a private `Rc<()>`
identity token. Save and restore compare those tokens before entering Unicorn,
so a context from another emulator is rejected without touching either native
engine. The wrapper is movable but deliberately does not implement `Clone`.

The tested CPU-state contract covers the 15 non-stack-pointer x64 general
registers, `RIP`, `RSP`, `EFLAGS`, `FS_BASE`, `GS_BASE`, and a complete 16-byte
XMM register. The public contract intentionally says CPU execution state rather
than promising version-specific Unicorn internals. Guest memory contents and
mappings, hooks, the `EmuData` observation buffers and counters, `Win64Env`,
scheduling state, and time state are outside the context. A restore therefore
switches CPU state while retaining shared guest memory and global observation
history.

Three synthetic tests establish the boundary:

- capture/restore and reusable overwrite recover distinct seeded register sets;
- memory changed after capture, executed-address history, recent RIPs,
  instruction count, and an installed trace hook remain live after restore; and
- foreign save and restore return `ForeignCpuContext` without changing the
  destination CPU state or corrupting the context still owned by its source.

The verification matrix is:

```text
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 118 passed
cargo clippy --all-targets -- -D warnings
git diff --check
```

## Dynamic Winmm `timeGetTime` keeps the child zero edge unresolved

This bounded Win64 slice began from exact merged CPU-context commit
`77e17cd20c0fc008b6ee0a760058f0966866cf31`. Formal sample 1 is the sole
milestone artifact for this replay; its SHA-256 was rechecked as
`8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf`,
matching `samples/SAMPLES.md`. Samples 2 and 3 retain incomplete provenance and
were not used as formal evidence for this slice.

Before implementation, an isolated pairing probe was repeated twice after the
preserved 38-call main prefix. Both runs observed the recorded child at
`0x0000000140058fa0` call `LoadLibraryA("winmm.dll")`, receive module handle
`0x00007fff00900000`, and pass that exact handle plus the name `timeGetTime` to
`GetProcAddress`. The existing dynamic procedure arena returned
`0x00007ffe00000020`, where dispatch stopped as unhandled. This closes the DLL
provenance gap that the earlier child finding left open.

### Bounded policy

Production deliberately leaves Winmm's synthetic export table empty and does
not seed `timeGetTime` into kernel32, ntdll, or Winmm. The observed name is
resolved through the existing dynamic `GetProcAddress` arena. The handler takes
no arguments and returns the fixed host-independent `DWORD` value zero,
explicitly zero-extended into `RAX`. It consumes a valid return frame before
changing `RAX`, so an invalid frame leaves all tested CPU and environment state
unchanged.

Zero is a deterministic uptime snapshot, not an advancing clock. The handler
does not consult host time, add mutable time state, advance on `Sleep`, schedule
or yield threads, or attach lifecycle meaning to the child's terminal edge.
Earlier diagnostic values zero, one, and `0x89abcdef` already produced the same
child path, so the fixed result is sufficient for the observed call but is not
a general timing model. The dynamic arena remains keyed only by function name;
the exact Winmm handle pairing is verified here, but general DLL export
membership is not claimed.

Three focused tests cover repeated calls in one environment and a fresh
environment with dirty register state; invalid return stacks with complete
tracked-state preservation; and the actual `LoadLibraryA("winmm.dll")` then
`GetProcAddress(handle, "timeGetTime")` route. The integration case proves the
Winmm export table remains empty, the result reverse-maps through the dynamic
arena rather than a seeded export, and a machine-code call with real Win64
shadow space returns zero with a balanced stack.

The verification matrix is:

```text
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 121 passed
cargo clippy --all-targets -- -D warnings
git diff --check
cargo build --locked --release --example run_loader --example trap_postmortem
```

### Formal production replay

Release `run_loader` and `trap_postmortem` preserve formal sample 1's calls
1–38, then handle `Sleep(1)` from call 39 through the 200-call bound. The result
is unchanged from the Sleep slice: 162 Sleep calls after the prefix, poised at
the same derived Sleep stub with the same registers and stack frame. Adding the
child-only time API therefore does not change the normal unscheduled main path.

A disposable production diagnostic then captured the main CPU context at that
frontier and ran the recorded child directly with the previously documented
disjoint stack and minimal TEB conditions. It produced:

```text
main_prefix=38
LoadLibraryA("winmm.dll") -> 0x00007fff00900000
GetProcAddress(0x00007fff00900000, "timeGetTime") -> 0x00007ffe00000020
[timeGetTime RSP] -> 0x000000014021a15d
stored DWORD at 0x000000014009af1d = 0
post-time suffix = 4,102 RIPs, FNV-1a 0xf71d13ef9b4673bc
stop = RIP 0
```

The 4,102-RIP suffix follows the previously measured 14,086-instruction
entry-to-API prefix, preserving the 18,188-instruction total child run. The
unmapped return sentinel was still not reached. The original main stack and TEB
were byte-identical after the child. Restoring the new owner-checked CPU context
and handling one `Sleep(1)` reproduced exactly 3,527 RIPs with digest
`0x7fce9fdb31fbfd70` before the next Sleep stub.

This establishes that the production time handler matches the observed dynamic
Winmm call and that fixed zero does not resolve the captured child edge or main
poll. It does not establish a Windows startup thunk, TLS initialization,
scheduling, clean thread return, termination, or an OEP. The terminal zero
remains diagnostic state whose source must be traced before scheduler lifecycle
work can classify it.

## Persistent cross-resume watching reproduces the poll-cell accesses

The persistent watch diagnostic was independently reproduced against the formal
sample artifact with SHA-256
`8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf`:

```text
cargo run --locked --release --example trace_slot -- samples/test_target_protected.exe 14005aae0 14005aae1 64 60000000 39
```

The relevant captured accesses were:

| Access | Global instruction | RIP | Instruction |
|---|---:|---:|---|
| write | 425458 | `0x000000014030b1c5` | `rep movsb` |
| read | 35096805 | `0x000000014005ffeb` | `cmp byte [r12],dil` |
| read | 35100332 | `0x000000014005ffeb` | `cmp byte [r12],dil` |

The final watched byte was `00`. The run handled call 39 as `Sleep`, then
stopped at the next API boundary because `max_calls` was reached. The watched interval
`[0x000000014005aae0, 0x000000014005aae1)` is one byte. Memory accesses are
matched by true half-open overlap, so an access is not required to begin inside
the watched interval. The persistent watch and its global instruction counter
remain live across resume legs; the instruction numbers above therefore share
one timeline rather than restarting after each trapped API call. This reproduces
the previously documented poll-cell observation: the same cell is written by
the `rep movsb` path, later read by the `cmp byte [r12],dil` poll, and remains
zero at the bounded stop.

The production APIs use one overlap helper for both the existing `run_watching`
path and persistent watching. Synthetic coverage records an 8-byte access when
only an interior byte is watched; adjacent, empty, and reversed ranges do not
match, while overflow edges retain nonwrapping overlap behavior. Persistent-hit
read and write value capture preserves the recorded value for access sizes
`0..=8`, including zero, and returns `None` for wider accesses rather than
exposing partial or raw data. The legacy `run_traced` value behavior is unchanged.

`trace_slot` bounds both watch-derived outputs it can retain or dump. Its hit cap
defaults to 4,096 and values above 16,384 are rejected because every retained hit owns an
18-register snapshot. The requested watched span still uses checked arithmetic;
the final dump reads and formats at most its first 4,096 bytes and emits an
explicit truncation message when more bytes were requested. Each printed hit
includes all 18 captured registers, including `RCX`, `RSI`, `RDI`, and `R12`, so
the operands of the two observed instructions are present in the diagnostic.

The focused synthetic tests are
`persistent_watch_survives_resume_legs_and_records_values`,
`persistent_watch_hit_cap_is_honored_across_resume_legs`,
`persistent_watch_value_helpers_preserve_zero_through_eight_and_reject_wider`,
`run_watching_records_access_overlapping_an_interior_watched_byte`,
`access_overlap_covers_interior_adjacent_empty_reversed_and_overflow_ranges`,
`hit_cap_validation_preserves_default_and_enforces_maximum`,
`final_dump_plan_is_checked_bounded_and_explicit`,
`register_format_covers_the_complete_snapshot`, and
`trap_reports_null_control_transfer_for_ret_to_zero`.

`TrapStop::NullControlTransfer` now classifies `StopReason::ReachedUntil` when
the final RIP is zero. It is an unexpected diagnostic state only: it is not normal thread
exit, lifecycle completion, OEP, or a fix for terminal-zero provenance.
Historical `ReachedUntil` and `Other("ReachedUntil")` captures remain accurate
labels for their older checkpoints before this classifier; they are not
retroactively reinterpreted.

The verification matrix is:

```text
cargo fmt
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 129 passed (126 library, 3 trace_slot)
cargo clippy --all-targets -- -D warnings
git diff --check
```

## Bounded child post-mortem traces the internal zero through its handler slot

This diagnostic slice starts from exact merged baseline
`ce16825921d5bcce7a2881121093446d3ef751de`, whose production capabilities
include persistent watching from `0130636b204f18c4ec1306ae7a6eadeb51690167`.
Formal sample 1 remains the sole
milestone artifact. Its SHA-256 was rechecked as
`8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf`,
matching `samples/SAMPLES.md`. Samples 2 and 3 retain incomplete provenance and
were not used for this result.

The committed reproducer is:

```text
cargo run --locked --release --example trace_child_postmortem -- \
  samples/test_target_protected.exe 60000000 100000 4096
```


`trace_child_postmortem` does not hardcode the formal call position, thread ID,
start address, parameter, `timeGetTime` stub, return address, VM handler slot,
or terminal stack cell. It advances one trapped API at a time until the
read-only stub-name projection identifies pending `Sleep`; obtains the sole
runnable-unscheduled record from `Win64Env`; and then advances the recorded
start until the same projection identifies pending `timeGetTime`.

The direct-entry conditions remain deliberately diagnostic rather than a
Windows startup model. Each pass uses a disjoint 1 MiB zeroed RW/NX stack, a
separate minimal TEB containing `StackBase`, `StackLimit`, `Self`, and the shared
PEB pointer, deterministic GPR/flags state, the recorded parameter in `RCX`,
and a nonzero unmapped return sentinel. No scheduler selects this context; no
TLS storage, startup thunk, DLL notification, or lifecycle state is created.

### Four replay passes and bounds

The example requires four fresh `Emu`/`Win64Env` replays to have identical
main API lists, created-thread records, child instruction-address vectors,
terminal result, and restored-main Sleep leg:

1. A discovery pass derives the terminal cell from the final `ret` and final
   `RSP`.
2. A terminal-cell pass arms its eight-byte watch only at the pending
   `timeGetTime` boundary, avoiding the 35-million-instruction main prefix.
3. A handler-slot pass derives the double-dereference target from the terminal
   VM bytecode and watches that exact slot from before the main PE entry.
4. A source-edge pass watches the dynamically derived selector field, source
   context qword, and handler slot. It rearms before each trapped main API leg
   and immediately freezes and formats the first leg containing the exact
   address, RIP, value, and global instruction index derived for the slot's last
   writer by pass 3. No API name or call ordinal selects that leg.

The CLI rejects a watch cap of zero or more than 16,384. The default and formal
cap is 4,096. The source-edge pass also rejects any individual rearmed
leg that reaches that cap; the frozen writer leg retains 801 hits. Any trace
divergence, terminal instruction other than a qword near `ret` with zero extra
stack adjustment and no operand-size override, unrecognized stop,
mapping/register restore failure, missing handler-slot read, or incomplete
source edge aborts the diagnostic without a provenance claim. The child per-leg
cap is required to be nonzero and no larger than 250,000 because child and
restored-Sleep RIPs are retained; fixed API-leg bounds keep that retention
finite.

All four passes reproduce:

```text
main prefix                 = 38 handled calls, pending Sleep
created thread              = ID 2, start 0x0000000140058fa0, parameter 0
child APIs                  = LoadLibraryA, GetProcAddress, timeGetTime
timeGetTime return address  = 0x000000014021a15d
child trace                 = 18,188 RIPs, digest 0xce52695f00082b00
post-time suffix            = 4,102 RIPs, digest 0xf71d13ef9b4673bc
terminal                    = NullControlTransfer; sentinel not reached
restored main Sleep leg     = 3,527 RIPs, digest 0x7fce9fdb31fbfd70
```

The main stack and main TEB are byte-identical before and after the child in
each replay. Restoring the owner-checked CPU context recovers all 20 tracked
registers (`RIP`, `RSP`, flags, and FS/GS bases included) before reproducing
the main Sleep leg. Guest memory, loaded Winmm state, hooks, and observation
history remain live, consistent with the documented CPU-only context boundary.

### Terminal stack cell and dispatcher source

The last executed instruction is
`0x000000014005cb7c: ret 0`. Final `RSP - 8` identifies consumed child-stack
qword `0x0000000f500feed0`; its value is zero, not the installed sentinel
`0x0000000edead0000`. This Unicorn build did not emit a `MEM_READ` hook for the
`ret` stack access, so the consumed-cell evidence is the terminal instruction,
the post-`ret` stack pointer, and the qword value rather than a claimed watch
read.

The terminal-cell watch records four writes during the 4,102-RIP suffix. The
last is:

```text
global instruction 35,116,502
0x000000014005cb1a: mov [rsi],r13
RSI = 0x0000000f500feed0
R13 = 0
```

The preceding runtime disassembly makes `R13`'s source explicit:

```text
mov rcx,[rbp+0xb2]
add rcx,6
mov r13w,[rcx]
add r13,rbp
mov r13,[r13]
mov r13,[r13]
...
mov [rsi],r13
```

At this edge the bytecode cursor is `0x0000000140295f08`; selector word
`[cursor+6]` is `0x88`. It selects context qword
`[0x000000014006fa68] = 0x0000000140066c04`, and the second dereference reads
zero from handler slot `0x0000000140066c04`.

The whole-run slot watch captures its history without a sample constant in the
diagnostic: the address is derived by the terminal-cell replay. Initial
decompression writes the nonzero low bytes `a0 58 18 38` followed by four zero
bytes. The last whole-qword writer occurs much later:

```text
global instruction 29,778,112
0x00000001400accf7: mov [r9],rbx
R9  = 0x0000000140066c04
RBX = 0
RBP = 0x000000014006f9e0
R12 = 0
```

The fourth replay derives selector field `0x000000014006fb03` and source context
qword `0x000000014006f9e0` from that writer snapshot, watches both together with
the slot, and captures the selected edge in one rearmed API leg:

```text
29,778,101  W  0x00000001400acccb: mov [rsi],r12w
                [0x000000014006fb03] <- selector 0
29,778,109  R  0x00000001400acced: movzx rbx,word [rbx]
                selector 0 <- [0x000000014006fb03]
29,778,111  R  0x00000001400accf4: mov rbx,[rbx]
                0 <- [0x000000014006f9e0]
29,778,112  W  0x00000001400accf7: mov [r9],rbx
                [0x0000000140066c04] <- 0
```

The validator anchors on the pass-3 writer identity, searches backward for the
nearest matching source and selector events, requires strict order, and rejects
conflicting writes to the selected field, source qword, or slot between their
respective edges. It freezes and decodes the four-instruction
`movzx`/`add rbx,rbp`/load/store fallthrough, then derives the required dynamic
instruction-index spacing from that path. It does not depend on an exact
handler byte signature or fixed per-sample instruction counts. The whole-run
replay proves no later write touches the slot. At global instruction 35,116,494,
`0x000000014005caf5: mov r13,[r13]` reads that same exact qword. The retained
terminal tail and watched chronology agree on the eight-instruction distance to
the terminal-cell writer, and decoded register access proves that none of the
seven intervening instructions writes `R13`.

This closes the immediate provenance chain for the tested direct entry:

```text
VM context selector 0 value 0
  -> VM store zeros handler slot 0x0000000140066c04
  -> terminal dispatcher loads R13 = 0 through selector 0x88
  -> trampoline writes 0 to the return cell
  -> ret transfers to RIP 0 instead of the diagnostic sentinel
```

It does not establish why context selector zero held zero at the earlier VM
store. It also does not establish a clean thread-routine return, a Windows
startup/TLS requirement, exception-handler execution, scheduling, thread
termination, or an OEP. The direct-entry child's failure to access the main
poll byte remains unchanged. The next causal question is the producer of the
source context zero, not the already-traced terminal stack or handler-slot
edges.

The verification matrix for the committed slice is:

```text
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 136 passed (127 library, 6 child diagnostic, 3 trace_slot)
cargo clippy --all-targets -- -D warnings
git diff --check
cargo build --locked --release --example trace_child_postmortem
```

This is a scheduler prerequisite, not a scheduler. In particular, restoring a
CPU context does not select `Win64Env.current_thread_id`, create stacks or TEBs,
initialize TLS, model a clock, or classify thread termination. Because
`Emu::resume` takes an explicit start address, a future context switch also has
to read the restored `RIP` and pass it to resume. Context switches are intended
at stopped or trapped boundaries, not from inside a running Unicorn hook. The
child's unresolved zero-target edge still cannot be labeled a normal thread
exit, and no result in this slice identifies an OEP.

## Six-pass reconstruction identifies the prior RET-zero producer path

The preceding four-pass checkpoint stopped at a specific question: what wrote
zero to source context qword `0x000000014006f9e0` before selector zero copied it
through historical RET handler slot `0x0000000140066c04`. Before changing the
USER32 export seed, the bounded diagnostic added two more fresh production
replays and answered that question to the live `RAX` value that entered the
VM's stack choreography.

The fifth pass derives the source context's last writer rather than fixing its
address or instruction index. On the formal checkpoint trace, the selected
source-context read occurs at global instruction 29,778,111. The last write to
that qword before the read is:

```text
global instruction 29,777,862
0x00000001400996fc: mov [rcx],r15
RCX = 0x000000014006f9e0
R15 = 0
```

The immediately preceding global instruction 29,777,861 is `pop r15`. Runtime
stack state derives its source as `0x0000000fffffefe0`; it is not selected by a
fixed sample stack address. Watching that cell and the context qword together
shows that the last writer to the cell before the pop is not the much earlier
stack traffic that a first broad search suggested. The exact writer is:

```text
global instruction 29,776,566
0x00000001400d5438: pop qword [rsp+80h]
destination = 0x0000000fffffefe0
source      = 0x0000000fffffef58
value       = 0
```

Global instruction 29,776,565 immediately before it is `mov [rsp],r8`, with
`RAX = R8 = 0`. The sixth pass watches the runtime-derived upstream cell only
inside a checked global-instruction interval around that producer. The frozen
fallthrough validates this exact six-instruction data path:

```text
push r8
pop qword [rsp]
mov r8,rax
push imm
mov [rsp],r8
pop qword [rsp+80h]
```

After hook-time instruction freezing was added to persistent watch hits, a
disposable empty-USER32 control reran all six passes. It reproduced the same
addresses, global instruction numbers, 158 retained upstream hits, and all
three trace digests while decoding the relevant windows from bytes frozen at
each watch hit rather than from later writable guest memory.

The validator checks the paired stack read/write, equal snapshots, the
runtime-decoded `rsp+80h` displacement, the derived destination/source
relationship, preservation of the value through `R8`, the relative global
instruction numbers, and absence of conflicting writes in the selected
interval. Its synthetic mutation test requires rejection for a wrong `RAX`
value, a global-index gap, divergent read/write snapshots, and a conflicting
write, while accepting a changed irrelevant immediate. The corresponding
emulator test proves that a persistent watch's
half-open global-instruction filter survives resume legs, rejects invalid
ranges atomically, and is cleared by ordinary unfiltered reconfiguration. The
formal sixth pass retains 158 watched hits under the 4,096-hit bound.

The checkpoint chain is therefore:

```text
RAX = 0
  -> R8
  -> temporary stack cell 0x0000000fffffef58
  -> future R15 cell 0x0000000fffffefe0
  -> R15
  -> source context qword 0x000000014006f9e0
  -> selector-zero VM store
  -> historical RET handler slot 0x0000000140066c04
  -> terminal stack cell
  -> ret to RIP 0
```

All six fresh replays preserve the checkpoint's 18,188 child RIPs and digest
`0xce52695f00082b00`, 4,102 post-`timeGetTime` RIPs and digest
`0xf71d13ef9b4673bc`, and restored-main 3,527-RIP Sleep leg and digest
`0x7fce9fdb31fbfd70`. This reconstruction identifies the native register and
stack path that produced the source-context zero. It does not establish why
`RAX` was zero at the beginning of the frozen sequence, nor does it give that
value Windows lifecycle meaning.
## Names-only USER32 controls identify two bounded child APIs

The prior source chain ends in the empty synthetic export-name table of
`user32.dll`, loaded at `0x00007fff00100000` in the captured environment. A
disposable broad control supplied USER32 export names from Wine's
`dlls/user32/user32.spec` at pinned wine-mirror commit
[`6eb2e4c32cc9e271856146df11ed3a5c2cf29234`](https://github.com/wine-mirror/wine/blob/6eb2e4c32cc9e271856146df11ed3a5c2cf29234/dlls/user32/user32.spec).
The downloaded spec SHA-256 was
`5f401185f736d82efb3ce1eb0bd36f2758a2c1bf92fd6573456213c93b1637af`.
Parsing only named entries and excluding `-noname` declarations produced 841
names; the newline-delimited list SHA-256 was
`e9cc0d85cd14bb9c1b13df74a55ad13f46dad09536f941338a2fa8880efc4116`.
The control used those names only. No Wine DLL or implementation code was
mapped, linked, or executed, and the disposable absolute include was removed
after diagnosis.

The broad control preserves the formal 38-call main prefix, the checkpoint
18,188 child RIPs, both checkpoint child digests, and the restored-main Sleep
digest. It changes the selector-zero source, historical handler-slot value,
and terminal target from zero to a synthetic USER32 stub whose trap resolves by
name as `LoadCursorA`. The loader's fourth resolver block carried observed
discriminator `0x8ea61819`; that number is not a decoded export-name hash and
is not equated with `LoadCursorA`. A narrow control adding only `LoadCursorA`
reproduces the named terminal under the ordinary 60,000,000-instruction leg
cap, with exact arguments:

```text
LoadCursorA(NULL, MAKEINTRESOURCEA(32649))
RCX = 0
RDX = 0x0000000000007f89   # IDC_HAND
```

Microsoft documents `LoadCursorA` and the predefined cursor identifiers at
<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadcursora>
and <https://learn.microsoft.com/en-us/windows/win32/menurc/about-cursors>.
Production seeds the observed name into USER32 and accepts only the full-width
`(NULL, 32649)` shape. It returns stable opaque unmapped handle
`0x0000000f30000010`, after validating and consuming the return frame. Module
resources, string-name pointers, and every other predefined identifier can be
valid Windows requests but remain unmodeled; they return `Unhandled` before
pointer or return-stack access. Direct tests cover repeat/fresh identity,
unsupported-input no-access behavior, invalid-return failure atomicity, and a
name-resolved call through the synthetic USER32 module.

With that handler active, the child executes 6,805 additional instructions and
reaches a second zero terminal after 24,993 total child RIPs. A broad 841-name
control changes this second terminal to a synthetic USER32 stub named
`RegisterClassExA`; a narrow two-name seed (`LoadCursorA`,
`RegisterClassExA`) reproduces the call at the ordinary leg cap. The exact
callee state is:

```text
RCX = 0x0000000f500fef40
RSP = 0x0000000f500feed8
[RSP] = 0x0000000140203928
```

The 80-byte x64 `WNDCLASSEXA` at `RCX` decodes as:

| Field | Observed value |
|---|---:|
| `cbSize` | `80` |
| `style` | `3` |
| `lpfnWndProc` | `0x000000014005c309` |
| `cbClsExtra`, `cbWndExtra` | `0`, `0` |
| `hInstance` | `0x0000000140000000` |
| `hIcon` | `0` |
| `hCursor` | `0x0000000f30000010` |
| `hbrBackground` | `6` |
| `lpszMenuName` | `0` |
| `lpszClassName` | `0x00000001400e04b6` → `"SplashClassName"` |
| `hIconSm` | `0` |

Its exact raw bytes are:

```text
500000000300000009c305400100000000000000000000000000004001000000
0000000000000000100000300f00000006000000000000000000000000000000
b6040e40010000000000000000000000
```

Microsoft documents the registration contract and structure at
<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassexa>
and <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexa>.
The bounded handler parses exactly 80 bytes and supports only the observed
scalar shape with a non-atom, printable 7-bit ASCII name supplied to the A API
and terminated within a 256-byte scan. It owns the resulting record rather than
retaining guest pointers. Local class atoms are allocated deterministically from
`0xc000..=0xffff`; the lookup key is `(hInstance, ASCII-lowercase class name)`.
A duplicate name, known-invalid required field, empty/unterminated name,
collision, or exhaustion returns zero without committing a record. Plausibly
valid but unmodeled scalar shapes, atom-name input, and non-printable names
return `Unhandled` before unrelated memory or return-stack access. Reads and
the return transition are preflighted before environment mutation. Focused
tests exercise the observed scalar shape with neutral class-name and
window-procedure fixtures, owned-record behavior, two ordinary distinct atoms,
fresh environments, case-insensitive duplicates, the strict name and atom
bounds, known-invalid and unmodeled cases, memory/return atomicity, and a
name-resolved synthetic-USER32 trap. The production replay supplies the actual
`SplashClassName` values shown above.

This is registration state only. `CreateWindowExA`, callback invocation,
window lifetime, message queues/dispatch, global versus local atom tables,
unregistration, icons, menus, brushes, and general class semantics remain
unmodeled.

## Production reaches a distinct post-class indirect-zero frontier

Reproduce the current formal diagnostic with the same bounded command:

```text
cargo run --locked --release --example trace_child_postmortem -- \
  samples/test_target_protected.exe 60000000 100000 4096
```

The formal sample SHA-256 remains
`8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf`.
The current production replay preserves the main 38-call prefix and pending
`Sleep`, derives the same ID 2/start/parameter, and reports:

```text
child prefix APIs          = [LoadLibraryA, GetProcAddress]
handled child tail         = [timeGetTime, LoadCursorA, RegisterClassExA]
terminal transfer          = indirect qword call
terminal instruction       = 0x000000014019b098
terminal pointer cell      = 0x000000014006f108
terminal pointer value     = 0
pushed return address      = 0x000000014019b09e
child trace                = 28,135 RIPs, digest 0x6b27c3a47b61a00d
post-time suffix           = 14,049 RIPs, digest 0x9aecc2c386795f99
restored main Sleep leg    = 3,527 RIPs, digest 0x7fce9fdb31fbfd70
```

This terminal is not the prior trampoline `ret` and its pointer cell is not the
prior VM handler slot. In particular, historical RET handler slot
`0x0000000140066c04` belongs to the 18,188-RIP checkpoint chain above. Current
cell `0x000000014006f108` is the runtime-derived memory operand of
`0x000000014019b098: call qword [rdi+20108h]`; the diagnostic calls it an indirect
pointer cell and does not assign a handler-table role without evidence.

A fresh whole-run watch on the runtime-derived current cell retains ten hits;
its instruction windows and the terminal instruction tail are decoded only
from hook-time snapshots, not from later writable guest memory.
Initial unpacking writes its low four bytes separately at globals
1,118,716/727/735/743 and its high four bytes with `rep movsb` at globals
1,118,818 through 1,118,821. Those earlier byte initialization writes remain
part of the chronology. The last observed guest write before the terminal read
is instead the exact qword store:

```text
global instruction 28,615,712
0x00000001400accf7: mov [r9],rbx
R9  = 0x000000014006f108
RBX = 0
```

No later watched write intervenes before the exact qword read at global
35,149,409 by `0x000000014019b098`. A second production replay reproduces the
same terminal and trace digests. Running the pinned 841-name USER32 control
after handling `RegisterClassExA` does not change this null indirect call. The
current stop is therefore not classified as another USER32 export gap. That
negative control does not identify the pointer's semantic role or explain why
the VM store selected zero.

Incomplete-provenance sample 3 independently corroborates the bounded USER32
behavior on a distinct binary. Its release diagnostic handles the same child
tail `[timeGetTime, LoadCursorA, RegisterClassExA]`, then reaches an indirect
zero call at `0x000000014010c05d` through pointer
`0x00000001400a36c5`. It records 27,654 child RIPs with digest
`0x25e21a892db20b71`, 13,799 post-time RIPs with digest
`0x61641e351dfafbf0`, and a restored 3,523-RIP main Sleep leg with digest
`0xe6f2315efb90611e`. The last watched guest writer is global 30,447,604 at
`0x000000014008db11: mov [r12],r11`, storing zero. This is engineering
corroboration only until the sample's provenance is complete. Sample 2 does not
reach pending `Sleep` on its established separate path, so no child replay is
claimed for it.

The direct-entry constraints and scheduler limits remain unchanged. The
expanded child does not release the formal main poll condition; main stack and
TEB remain unchanged, and restoring the CPU context reproduces the next Sleep leg.
The current indirect call is neither a clean thread return nor evidence of a
Windows startup thunk, TLS initialization, exception dispatch, thread
termination, or an OEP. The next bounded question is the semantic provenance
of current indirect pointer cell `0x000000014006f108` and the zero selected by
its last qword writer, without assuming that it is an export slot.

The current verification commands are:

```text
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 152 passed (139 library, 10 child diagnostic, 3 trace_slot)
cargo clippy --all-targets -- -D warnings
git diff --check
cargo run --locked --release --example trace_child_postmortem -- \
  samples/test_target_protected.exe 60000000 100000 4096
```

## `WideCharToMultiByte` is the causal post-class null

The post-class cell is no longer semantically unresolved. A corrected
names-only kernel32 control identifies it as `WideCharToMultiByte`, and a
bounded implementation advances the child through both observed conversion
calls. This result comes from address and control provenance at the loader
writer; no further zero-value VM/stack chain was followed.

### One-name A/B identifies the cell

The retained export-name control now records whether it was actually applied
and rejects a run if the configured module bypassed it. This check exposed and
fixed a diagnostic bug: the dedicated `GetModuleHandleA("kernel32.dll")` path
had mapped the ordinary kernel32 seed directly, so the earlier reported broad
kernel32 control was a no-op. No conclusion from that no-op is retained.

The two committed control files are strictly sorted and differ by exactly one
line:

```text
docs/controls/kernel32-without-widechar.txt  # 19 production names
docs/controls/kernel32-with-widechar.txt     # same names + WideCharToMultiByte
```

Their SHA-256 values are, respectively,
`ead2f345b2eebfeedfabbd1551e1029fd721678d0d068321b598948ade757234`
and
`dfd7ed5f8d57f01047b511334aa6e45c42362964b7b0baba56c74561bc2490db`.
Reproduce the current-tree A/B with:

```text
cargo build --locked --release --example trace_child_postmortem

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  kernel32.dll docs/controls/kernel32-without-widechar.txt \
  > /tmp/midas-widechar-without-artifact.txt

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  kernel32.dll docs/controls/kernel32-with-widechar.txt \
  --frontier-only \
  > /tmp/midas-widechar-with-artifact.txt

sha256sum /tmp/midas-widechar-{without,with}-artifact.txt
```

The output SHA-256 values are
`331931055f374b1728f7c47b2abf05b3add5c201cc0ca9a459a5f522c26b87d0`
and
`44e1a79e5bd4c4af74182b168e2011e11c56a9a8760120a6e121eb76116ca280`.
The treatment changes the observable frontier:

| Observation | 19-name control | Same control plus `WideCharToMultiByte` |
|---|---|---|
| Cell writer | global 28,615,712, `0x00000001400accf7: mov [r9],rbx`, `RBX=0` | same writer instruction stores the runtime synthetic kernel32 stub; the extra sorted name shifts it to global 28,635,463 |
| First post-class transfer | `0x000000014019b098 -> [0x000000014006f108] = 0` | same instruction/cell reads nonzero stub `0x00007fff00001130` |
| Old-frontier boundary | null indirect terminal | same call dispatches to name-resolved `WideCharToMultiByte` |
| Trace to that call | 28,135 child RIPs, digest `0x6b27c3a47b61a00d`; 14,049 post-time RIPs, `0x9aecc2c386795f99` | exact same counts and digests before dispatch |
| First reported terminal | old indirect null | after two conversions plus `GetProcessHeap` and `RtlAllocateHeap`, a distinct near-return null |
| Restored main | 3,527 RIPs, digest `0x7fce9fdb31fbfd70`, next `Sleep(1)` | exact same loop and digest |

Before the handler was added, the 20-name treatment stopped as
`UnhandledApi { name: "WideCharToMultiByte" }` with pointer value
`0x00007fff00001130`; that captured report has SHA-256
`8e715c1016a9e982a6533c56aa8b00b8fffd46f2ffb1a8ab02005bc9ddbd7985`.
A genuine 1,416-name treatment from Wine's
[pinned kernel32 spec](https://github.com/wine-mirror/wine/blob/6eb2e4c32cc9e271856146df11ed3a5c2cf29234/dlls/kernel32/kernel32.spec)
independently selected the same name, but exceeded the ordinary
60,000,000-instruction leg cap. The one-name treatment above completes at the
formal bound and is the causal artifact.

### The terminal arguments are an exact conversion-size query

The terminal instruction bytes remain `ff 97 08 01 02 00`, or
`call qword [rdi+0x20108]`. Interpreting the four registers and four stack
arguments under the eight-argument kernel32 signature gives:

```text
WideCharToMultiByte(
    CodePage          = 0,                       # CP_ACP
    dwFlags           = 0,
    lpWideCharStr     = 0x0000000140111121,      # L"guest.exe"
    cchWideChar       = -1,
    lpMultiByteStr    = NULL,
    cbMultiByte       = 0,
    lpDefaultChar     = NULL,
    lpUsedDefaultChar = NULL)
```

This exact match supersedes the earlier window-construction-shaped inference.
Microsoft documents that `cchWideChar=-1` processes the terminating null and
that `cbMultiByte=0` returns the required byte count without using an output
buffer:
<https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte>.
For printable ASCII `guest.exe` plus its terminator, the supported result is
10.

A query-only production checkpoint returned 10, then exposed
`GetProcessHeap`, `RtlAllocateHeap`, and a second call through the same cell.
Its report SHA-256 is
`7872e94a586b9cdbbd6e80ff653e9fe217492ffa189dd282b5ea20e0e846cac4`.
The second observed shape is:

```text
WideCharToMultiByte(
    0, 0, L"guest.exe", -1,
    0x0000000f40007000, 10, NULL, NULL)
```

The implementation is deliberately narrower than general Windows NLS:

- kernel32 exposes the one observed name;
- `UINT`, `DWORD`, and `int` inputs consume their low 32 bits, while pointers
  remain full-width;
- only `CP_ACP`, flags zero, `cchWideChar=-1`, null default-character pointers,
  and a null-terminated printable 7-bit ASCII input within 260 UTF-16 units are
  supported;
- the size-query form returns the derived byte count including null;
- the output form requires a non-null buffer with the derived size, writes the
  derived ASCII bytes and terminator without touching its suffix, and returns
  the same count;
- other code pages, flags, explicit input lengths, non-ASCII text, and
  cap-exhausted strings remain `Unhandled`; host locale and code-page state are
  not consulted.

Focused tests cover repeated and fresh size queries, dirty upper halves,
conversion output and suffix preservation, non-ASCII and cap rejection,
unmodeled-shape no-input/no-return access, input/return/output failure
atomicity, and dispatch through the name-resolved kernel32 stub.

### Production advances to a distinct bounded frontier

The current formal command deliberately stops after the first new terminal so
the diagnostic does not enter another long provenance chain:

```text
target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  --frontier-only \
  > /tmp/midas-widechar-production-artifact.txt
sha256sum samples/test_target_protected.exe \
  /tmp/midas-widechar-production-artifact.txt
```

The formal sample SHA-256 remains
`8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf`;
the report SHA-256 is
`221b073964e9899c3e0969ba3af516397c4098a0c7a06b74cbd2445821ea02b8`.
It reports:

```text
child tail APIs = [timeGetTime, LoadCursorA, RegisterClassExA,
                   WideCharToMultiByte, GetProcessHeap, RtlAllocateHeap,
                   WideCharToMultiByte]
child terminal  = NullControlTransfer
terminal        = near `ret 0` at 0x000000014005cb7c
terminal cell   = 0x0000000f500fee90, value 0
child trace     = 44,386 RIPs, digest 0xed010b86a52a2ab2
post-time       = 30,300 RIPs, digest 0x3d2b90b3678f0d4e
restored main   = 3,527 RIPs, digest 0x7fce9fdb31fbfd70,
                  next API Sleep(1)
provenance      = skipped by --frontier-only
```

The new terminal is not followed backward here. It is not classified as a
clean Windows thread return, startup-thunk return, callback, or OEP.

Incomplete-provenance sample 3 independently exercises both bounded
`WideCharToMultiByte` forms and the same seven-API tail, then reaches its own
near-return null. Its report has 43,724 child RIPs (digest
`0x55db266985c561e3`), 29,869 post-time RIPs
(`0x892e272b7fedd906`), and the unchanged 3,523-RIP restored-main digest
`0xe6f2315efb90611e`; `/tmp/midas-widechar-sample3.txt` has SHA-256
`c2270cc7c8488f49c7d3cbc4ca53374a2b92bb42e7346cafe58f0726e4e7a5b1`.
This is engineering corroboration only; the formal sample remains the
milestone artifact.

### Lifecycle hypothesis matrix

| Hypothesis | Bounded observation or treatment | Result |
|---|---|---|
| Missing kernel32 `WideCharToMultiByte` name/semantics causes the post-class null | Current-tree 19-name versus 20-name controls; then query-only and output-form handlers | Supported causally. One added name changes the same loader writer/cell from zero to the named stub; the two documented shapes return/write 10 and advance 16,251 child instructions beyond the old terminal |
| One extra serial main leg before direct child entry is sufficient | Complete one more 3,527-instruction `Sleep(1)` leg, then enter the child directly | Child and restored-main results remain unchanged. This tests only that ordering, not a scheduler yield or real interleaving |
| Current-thread ID, `TEB.ClientId`, or per-thread TLS supplies the missing value | Main TEB prefix through `+0x70`; complete child TEB watch; formal image TLS-cell watches | Main has 1,545 reads at `TEB+0x30`; the advanced child has four, all at `TEB+0x30`. Neither path reads `ClientId`, the TEB TLS pointer, or the formal image TLS cells |
| The fixed zero `timeGetTime` value is the immediate blocker | Return fixed 1 and 1,000 in separate recorded controls | Neither changes the old terminal or loop. A coherently advancing clock, `Sleep` coupling, and time-driven scheduling remain untested |
| A mapped-image TLS/DLL thread callback initializes the cell | Decode the formal TLS directory and mapped synthetic module headers | Formal callback array starts with NULL; synthetic modules have zero entry point and no TLS callback directory. There is no runtime-derived guest notification target to invoke |
| `RegisterClassExA` callback/window lifecycle causes the current call | Record the registered WndProc and classify all eight terminal arguments | The registered WndProc is not executed before the call, and the arguments exactly identify `WideCharToMultiByte`, not `CreateWindowExA/W` or a WndProc |
| A scheduler alone releases the main poll | Directly run the recorded child before and after the conversion fix, restore main CPU state, and execute the next leg | Not supported. Midas still lacks a scheduler, but even the advanced direct child leaves the next main leg exact and reaches a distinct child null |

The main TEB and TLS controls remain reproducible with:

```text
target/release/examples/trace_slot samples/test_target_protected.exe \
  f10000000 f10000070 4096 60000000 39 \
  > /tmp/midas-main-teb-watch.txt
target/release/examples/trace_slot samples/test_target_protected.exe \
  14004e000 14004e018 256 60000000 39 \
  > /tmp/midas-tls-watch.txt
```

Their SHA-256 values are
`155f237c7cb131c4ae2cfe16cbbe15d89145ea1017aaafa12bf346196fd1204b`
and
`15f4d8bb3eab8605470320d306cfc44e437be3b331dfb007b5f1fa289d8bcb62`.
A disposable advanced-child watch of the same three image TLS cells retained
no hit; its full report SHA-256 is
`e8130b78fec17442f080eb252aa8cbfeec30ada456f5750bbd17c59b06445364`.

### Supported causal explanation and next question

The missing/inaccurate semantic that causes the diagnostic child's current
post-`RegisterClassExA` null is the absence of kernel32
`WideCharToMultiByte`, specifically its CP_ACP printable-ASCII size query and
matching output conversion. It is not thread identity, fixed uptime value,
mapped-image DLL notification, or USER32 class/callback lifecycle.

That semantic is not, by itself, the explanation for the main loop. Normal
Midas execution never starts the recorded child because there is no scheduler;
after direct diagnostic execution with both conversions implemented, the poll
and restored Sleep leg still do not change, and the child reaches a distinct
near-return null. The evidence therefore supports two separate blockers rather
than one Windows semantic that explains both observations.

No additional speculative API or return policy is added. The next bounded
question is the control provenance of the distinct `ret 0`: is it intended to
reach the diagnostic return sentinel/thread-start wrapper, or is one more
runtime-selected dependency missing? That question should be tested at the
new terminal with a bounded return/startup treatment and poll comparison, not
by extending another zero-value VM/stack trace.

Current verification is:

```text
cargo fmt --check
cargo build --all-targets
cargo test --all-targets              # 160 passed (146 library, 11 child diagnostic, 3 trace_slot)
cargo clippy --all-targets -- -D warnings
git diff --check
target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  --frontier-only
```

## Poll release producer is a post-`CreateWindowExA` child store

The poll producer was identified without adding another Win64 API handler.
`trace_child_postmortem --poll-window` first derives the poll comparison from
one bounded Sleep-to-Sleep replay, then starts a fresh emulator with a one-byte
persistent watch armed before guest entry. Discovery selects the unique
executed base-register-only `cmp r/m8,r8` whose byte equals the compared
register at the repeated Sleep boundary. It does not assume an address,
instruction index, or register allocation. This matters across the two
observed variants: formal sample 1 uses `cmp [r12],dil`, while sample 3 uses
`cmp [rsi],al`.

The discovery hook is installed with an empty range before the first guest
translation block executes, then reconfigured for the one-leg image-memory
capture. The final one-byte watch remains armed across the main prefix, child
execution, CPU-context restoration, and the resumed main leg. All retained
accesses use hook-time instruction bytes and the persistent global instruction
index. Retained restored-main instruction history has an independent
1,000,000-instruction diagnostic cap; both reported runs stop naturally below
72,000 instructions.

### The advanced null is `CreateWindowExA`

The prior advanced child terminal carries the complete x64 argument frame for
`CreateWindowExA`: extended style `8`, class name `"SplashClassName"`, NULL
window name, style `0x90000000`, default x/y `0x8000`, dimensions
`0x237` by `0x12b`, NULL parent/menu, process image instance, and NULL
parameter. Two names-only USER32 controls distinguish the A and W exports:

| Control | Input SHA-256 | Formal output SHA-256 | Result |
|---|---|---|---|
| `user32-with-createwindowa.txt` | `91d4ca9bffea7a669bcf508f155d5a2f62604678a203700ee0fe479a2419d2b2` | `4101946e1dae39e2231a9da3d7a94c0fd3e1b2d17038b3010ac9565e8f13ae31` | The same 44,386-RIP child reaches `UnhandledApi { name: "CreateWindowExA" }` at the selected USER32 stub |
| `user32-with-createwindoww.txt` | `f4a63033e35bbd557c81ab56dd6f619b7c2c3955b20581209399d42f67c153d5` | `e81e62774c5539ddd19365e8f20925c7c072d25127968e802e7c87b89784a040` | The target remains zero with the exact baseline child digest |

This identifies the resolver-selected name and ABI shape. It does not
implement `CreateWindowExA` or claim a complete USER32 window lifecycle.

### Writer and main-loop release

The bounded treatment returns a diagnostic nonzero opaque HWND at the derived
`CreateWindowExA` boundary, without registering window state or invoking a
WndProc. The existing child then executes until the next named frontier. The
poll watch records a child store of byte one, after which restoring the saved
main CPU context makes the next comparison read one and leave the Sleep loop.

| Observation | Formal sample 1 | Incomplete-provenance sample 3 |
|---|---|---|
| Runtime-derived poll cell / compare | `0x000000014005aae0`; `0x000000014005ffeb: cmp [r12],dil` | `0x0000000140072f20`; `0x000000014006da94: cmp [rsi],al` |
| False initializer | global 425,458, `0x000000014030b1c5: rep movsb`, stores `0` | global 1,335,237, `0x000000014033d1c5: rep movsb`, stores `0` |
| Release writer | global 35,212,364, `0x00000001400a3fe8: mov [r9],r8b`, with `R9 = poll`, `R8B = 1` | global 36,966,978, `0x00000001400a62ea: mov [r15],r12b`, with `R15 = poll`, `R12B = 1` |
| Post-create child frontier | handles `GetProcessHeap`, then stops at unhandled `RtlFreeHeap` after 10,567 RIPs (`0xf2cb668d6f40311a`) | same named frontier after 10,466 RIPs (`0x1cd09314fee386f6`) |
| Restored main | reads `1`; 66,682 RIPs (`0xca21a387d6e00ed4`), including 64,695 instructions past the poll, then null control transfer | reads `1`; 71,516 RIPs (`0x8fe001a0013d9c96`), including 69,544 instructions past the poll, then null control transfer |

Formal output `/tmp/midas-poll-window-final.txt` has SHA-256
`1d7ff8ea9214236887f7f9eebc4277389ec44dc461f8528b2f3de4fcf0c79177`.
The sample-3 engineering corroboration has SHA-256
`f3eff209b697464accfc38a00673d45ccc26d1b09a8c6724472036b060d4cb56`;
its provenance remains incomplete, so it is not formal milestone evidence.

The producer is therefore classified as a **child-thread store after the
window-creation return**, not the timer/APC/VEH/loader initializer alternatives
for this observed release path. The previous scheduler-only negative control
remains compatible with this result: its child stopped before receiving a
valid `CreateWindowExA` return and therefore never reached the writer. This
treatment runs the child through the store before restoring main, so it does
not establish that fine-grained interleaving is required. A scheduler remains
necessary to execute the created thread in production, but scheduler behavior
alone is not sufficient; the observed window-creation boundary must also be
handled. No production scheduler, window API, WndProc dispatch, or
`RtlFreeHeap` handler is added in this slice.

The main now has a positive north-star measurement under the bounded
treatment, but the later null is not classified as OEP. OEP detection can
shorten later execution once a natural transfer reaches an original-code
candidate; it cannot replace the release prerequisite demonstrated here.

Reproduce the controls and poll treatment locally with the formal sample:

```text
cargo build --locked --release --example trace_child_postmortem

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  user32.dll docs/controls/user32-with-createwindowa.txt \
  --frontier-only > /tmp/midas-createwindowa-final.txt

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  user32.dll docs/controls/user32-with-createwindoww.txt \
  --frontier-only > /tmp/midas-createwindoww-final.txt

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  --poll-window > /tmp/midas-poll-window-final.txt
```

## Post-release null is missing `GetCommandLineA` resolution

Slice A classifies the restored-main null as option **(b), another missing API
or return boundary**. It is the result of the kernel32 export walk failing to
find `GetCommandLineA`, not a second child-dependent wait and not an observed
transfer into original code. This slice changes only the diagnostic example
and names-only control data; it adds no production API handler, scheduler, or
window behavior.

### Baseline terminal and zero provenance

`--poll-window` now retains a bounded main-stack watch only for the restored
post-poll leg. From that watch and the hook-time instruction tail it derives the
terminal register call, its pushed fallthrough, the stack cell supplying zero,
and the last read/modify/write that changes that cell from nonzero to zero. The
derivation assumes no address, instruction index, displacement, or register
allocation. It selects a unique full-qword `push [base+disp]` read in the frozen
tail, recomputes its effective address from the hook register snapshot, and
requires the final zero writer to have a paired nonzero read at the same global
instruction and RIP with no later overlapping write.

| Observation | Formal sample 1 | Incomplete-provenance sample 3 |
|---|---|---|
| Instructions past the runtime-derived poll | 64,695 | 69,544 |
| Restored-main trace | 66,682 RIPs, `0xca21a387d6e00ed4` | 71,516 RIPs, `0x8fe001a0013d9c96` |
| Terminal | global 35,287,539, `0x000000014023c6d0: call rax`, target zero, fallthrough `0x000000014023c6d2` | global 37,046,898, `0x000000014017c609: call rax`, target zero, fallthrough `0x000000014017c60b` |
| Frozen 64-RIP terminal-tail digest | `0xe54044308547f9f2` | `0x391bf765217440e5` |
| Last target-cell transition | global 35,287,451, `add qword [rbp-2Ch],0FFFFFFFFA0462BF8h`, `0x5fb9d408 -> 0` | global 37,046,807, `add qword [rbp-2Ch],0FFFFFFFFC05024B9h`, `0x3fafdb47 -> 0` |
| Derived zero consumer | global 35,287,499, cell `0x0000000fffffefac` | global 37,046,854, cell `0x0000000fffffefac` |

The equal cell address is an emergent consequence of the common diagnostic
main stack, not a classifier constant. The distinct instructions, globals, and
protected code addresses show that the mechanism is not selecting a stored
sample address. Both variants execute the pending `Sleep` return that begins
the restored leg, read the already-released poll byte once, and reach the
register call without another observed named wait or another poll comparison.

The compact zero-chain validator does not symbolically execute every protected
instruction between the derived stack read and `RAX`. That chain is supporting
provenance. The causal classification instead comes from the applied broad and
one-name export controls below, which preserve the exact 64-RIP terminal
address sequence and call site while changing its target from zero to a
reverse-mapped named stub.

### Broad discovery and one-name causal control

A local 1,416-name kernel32 control from the same pinned Wine kernel32 spec used
for the earlier `WideCharToMultiByte` diagnosis was applied as export names
only. Its SHA-256 is
`2a05619eb0a3a41b0f400200d56a29dcdd3300afbe4dbb238e79f2572760a0be`.
The large table exceeds the ordinary 60,000,000-instruction resolver leg, so the
bounded discovery used a 200,000,000 main-leg cap. It advances 185,148
instructions past the poll and stops at
`UnhandledApi { name: "GetCommandLineA" }`. The terminal remains
`0x000000014023c6d0: call rax`, its 64-RIP tail digest remains
`0xe54044308547f9f2`, and `RAX` is the runtime synthetic stub
`0x00007fff0000c7a0`. The output artifact SHA-256 is
`b2495d093d4bd407e621751b8e8248ed744ea364c219bfe7a0aa3571bebd0f50`.

At the Slice A checkpoint, the committed narrow control
`docs/controls/kernel32-with-getcommandlinea.txt` was the 20-name production
kernel32 seed plus exactly one sorted name. Slice B retains that 20/21-name pair
as a frozen diagnostic control after `GetCommandLineA` joins production. The
two controls have SHA-256 values
`dfd7ed5f8d57f01047b511334aa6e45c42362964b7b0baba56c74561bc2490db`
and
`244487c6d6d693668111a3d5d13f19cf881eec9fef86fe7b8d919312fda45832`.

| Observation | Formal sample 1 | Incomplete-provenance sample 3 |
|---|---|---|
| Baseline | zero-target register call at +64,695 | zero-target register call at +69,544 |
| One-name treatment | `UnhandledApi { name: "GetCommandLineA" }` at +8,242; target stub `0x00007fff00001020` | same named boundary at +11,335; target stub `0x00007fff00001020` |
| Treated restored-main trace | 10,229 RIPs, `0xbc793a51cd19c6c6` | 13,307 RIPs, `0x625ebc69fba1ecb5` |
| Call site / fallthrough | unchanged `0x000000014023c6d0` / `0x000000014023c6d2` | unchanged `0x000000014017c609` / `0x000000014017c60b` |
| Frozen terminal-tail digest | unchanged `0xe54044308547f9f2` | unchanged `0x391bf765217440e5` |
| Baseline output SHA-256 | `cca7376149fafd7cde99b5c79949b4ad94e9abd1b919e3cd2287eddfdb35077` | `f2c982d07134fc22cb137637a4e55b0958de58bf734351fa735f4974e221bccd` |
| Treated output SHA-256 | `dc5646046802539a776c387f354daab0daefe258eedf53e2b897b0cecb8b2715` | `ff9619bb9349feb9c84beb4f5c85a97ec7661eb7a3fddc4fa80211dbbb399d0b` |

The treatment changes the synthetic export layout, so its shorter
instructions-past-poll count and whole-trace digest are not expected to equal
the baseline. The invariant is the 64-RIP protected tail address sequence,
register-call site, and pushed fallthrough; only the runtime export-walk result
changes from zero to the named synthetic stub.

The rows above are the original separate Slice A artifacts. Slice B replaces
manual comparison with a paired assertion in one invocation:

```text
cargo build --locked --release --example trace_child_postmortem

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 60000000 100000 4096 \
  --poll-window > /tmp/midas-slice-b-poll-ab-s1.txt

target/release/examples/trace_child_postmortem \
  samples/test_target3_protected.exe 60000000 100000 4096 \
  --poll-window > /tmp/midas-slice-b-poll-ab-s3.txt

sha256sum /tmp/midas-slice-b-poll-ab-s{1,3}.txt
```

The paired output SHA-256 values are
`81e933a4a286bc2e3fc427374fa8f7c781bbfcb24d5f61e8872c54758f381a72`
and `f160fea080e8e8871ee819e637af88dd2a3da0088a00d4929fe33534cc6300c6`.

The formal sample SHA-256 remains
`8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf`.
Sample 3 remains engineering corroboration because its source provenance is
incomplete; its observed SHA-256 is
`6c70e14c40fde8661b0b0121161deb1afd9edffd682f1f30f2b5916895f79585`.

### Classification and Slice B consequence

The post-release null is therefore **(b), missing `GetCommandLineA`
resolution/semantics**. No second child-written condition is observed after the
released poll, so Slice A provides no reason to require fine-grained main/child
ping-pong. Slice B can use the planned coarse cooperative yield to run the
child through the release store, while batching the observed `RtlFreeHeap` and
`GetCommandLineA` frontiers with the window-creation boundary. This is an
architecture result, not an implementation of those APIs.

The controlled path still stops inside protected code at an unhandled named
stub. It does not reach or prove original code or OEP, and no OEP criterion is
claimed. Verification for this diagnostic slice is `cargo test --locked
--all-targets` with 164 tests (146 library, 15 child diagnostic, and 3
`trace_slot`), plus the full build and `clippy -D warnings`.

## Production cooperative `Sleep` yield releases the poll

Slice B moves the established release mechanism into the normal `run_loader`
path. The production assumption is deliberately narrow: a supported finite
main-thread `Sleep` is a cooperative yield when an unclaimed created thread
exists. The runner completes that `Sleep`, captures the returned main CPU
context, claims the lowest thread ID once, and starts it with its recorded
parameter in `RCX` on a fresh zeroed 1 MiB stack plus a minimal TEB selected by
`GS`. The child has a 100,000-instruction and 32-API bound. It runs until its
per-runtime NX return guard, child `Sleep`, API/fault wall, or cap; main CPU
state is then restored while guest memory, mappings, hooks, and `Win64Env`
remain live.

No poll address, instruction address, register allocation, or sample index is
used by the scheduler. `Sleep` is the only yield trigger. The mechanism is not
a thread-lifecycle model and does not retain the stopped child CPU state.

Three observation-driven API treatments are included:

- `CreateWindowExA` consumes the complete ABI frame and supports the observed
  top-level/null-title subset only for an already registered ANSI class and
  instance. It returns the stable opaque unmapped HWND
  `0x0000000f30000020`, creates no window state, and does not invoke a WndProc or
  message loop.
- `RtlFreeHeap` accepts the modeled process heap, the supported low-`ULONG`
  flags, and an exact live allocation base. Success removes allocation metadata
  but does not unmap or reuse the page backing.
- `GetCommandLineA` returns stable read-only guest storage containing the
  host-independent process command line `C:\guest.exe`.

### Normal production replay

The ordinary release `run_loader` example, with no diagnostic control or
manual child setup, leaves the repeated `Sleep` loop on all three deposited
variants:

| Observation | Formal sample 1 | Incomplete-provenance sample 2 | Incomplete-provenance sample 3 |
|---|---:|---:|---:|
| Main API at yield | call 39, `Sleep` | call 38, `Sleep` | call 38, `Sleep` |
| Child instructions / stop | 65,203 / `NullControlTransfer` | 65,677 / `NullControlTransfer` | 64,324 / `NullControlTransfer` |
| Child handled suffix | `... CreateWindowExA, GetProcessHeap, RtlFreeHeap` | same | same |
| `GetCommandLineA` position | first restored-main API | pre-yield call 34 | first restored-main API |
| Main instructions after yield | 77,870 | 84,748 | 147,854 |
| Production output SHA-256 | `54ce9475a7ee8eab66d9024362edc2b7ddd7606637c18f598ec566d97a39074d` | `593e5846c96e9637b52749529287e6fa2eb194ae08407a675613a44eb2b71540` | `73b781dd781cc52bc59cd26aab3039988fe51a849682ef7bf9936a1ef9ba3be1` |

Each output is byte-identical across two fresh invocations. Sample 1 then
handles two `SetCurrentDirectoryW` calls and reaches a later null control
transfer. Sample 2 has already handled `GetCommandLineA` before `CreateThread`;
after the yield it handles `RtlAddVectoredExceptionHandler`, `GetVersion`, and
two `SetCurrentDirectoryW` calls before its later null. Sample 3 handles
`GetVersion`, the same two directory calls, and its own later null. The child
null is the first newly observed post-`RtlFreeHeap` child wall on all three.
For samples 1 and 3 it occurs after the release store because restored main
reaches `GetCommandLineA` without another child turn. Sample 2 independently
validates the coarse one-turn release but has a different main ordering, with
`GetCommandLineA` before the yield. The coarse-yield assumption remains scoped
to these observed boundaries only; it is not established for future child
execution.

Reproduce locally:

```text
cargo build --locked --release --example run_loader

target/release/examples/run_loader \
  samples/test_target_protected.exe 60000000 200 \
  > /tmp/midas-slice-b-production-s1.txt
target/release/examples/run_loader \
  samples/test_target2_protected.exe 60000000 200 \
  > /tmp/midas-slice-b-production-s2.txt
target/release/examples/run_loader \
  samples/test_target3_protected.exe 60000000 200 \
  > /tmp/midas-slice-b-production-s3.txt

sha256sum /tmp/midas-slice-b-production-s{1,2,3}.txt
```

### Durable post-release A/B check

`trace_child_postmortem --poll-window` now owns a paired control: one invocation
runs fresh 20-name target-absent and 21-name `GetCommandLineA`-present kernel32
environments. It programmatically requires an exact 64-RIP tail match, the same
register-call site, target register, pushed return cell, and fallthrough, and
the sole terminal change from target zero to the reverse-mapped named stub. The
zero consumer must also match an exact `(global instruction index, RIP)` in the
frozen tail. The formal sample retains 64,695 instructions past its
runtime-derived poll; sample 3 retains 69,544. This replaces manual hash
comparison as the option-(b) invariant. Sample 2 resolves `GetCommandLineA`
before creating and yielding to its child, so it does not have this
post-release missing-name boundary; its independent production replay above is
the applicable scheduler artifact.

The production runs do not classify any newly observed null as original code or
OEP.
OEP detection, a general scheduler, an advancing clock, WndProc/message-loop
dispatch, and full thread or heap lifecycle remain outside this slice. Formal
two-sample acceptance also remains open: `samples/SAMPLES.md` records complete
provenance only for sample 1. The author has supplied matching Themida
version/configuration for samples 2 and 3, but their source and pre-protection
binary hashes remain temporarily unavailable on the author's work notebook.

Final-tree verification is green for `cargo fmt --all -- --check`,
`cargo build --locked --all-targets`, `cargo test --locked --all-targets` (164
library, 17 child-diagnostic, and 3 `trace_slot` tests),
`cargo clippy --locked --all-targets -- -D warnings`, `git diff --check`, and
the repository no-hype gate. Two fresh production invocations for each of the
three observed variants are byte-identical at the SHA-256 values in the replay
table. Fresh paired A/B artifacts retain SHA-256
`81e933a4a286bc2e3fc427374fa8f7c781bbfcb24d5f61e8872c54758f381a72`
for formal sample 1 and
`f160fea080e8e8871ee819e637af88dd2a3da0088a00d4929fe33534cc6300c6`
for incomplete-provenance sample 3.

## Slice C: the post-directory null is a missing-name return; the OEP criterion is armed

Slice C starts from the normal cooperative production path above and separates
two questions that must not be conflated:

1. what produces the zero control target after the two
   `SetCurrentDirectoryW` calls; and
2. what runtime event would qualify as an OEP candidate if execution later
   reaches original executable code.

The first question is now classified as option **(b), another missing
API/return**. The second has a falsifiable implementation and a production
watch, but the criterion did not fire in this slice. No OEP address or
original-code claim follows from the null classification.

### Additive production-terminal diagnostic

`trace_child_postmortem --production-terminal` runs the same cooperative
scheduler as `run_loader`. A discovery pass establishes the production result;
a fresh replay stops immediately before the last handled API and enables
hook-time byte retention only for a bounded suffix of at most 1,000,000
instructions and the final 64 instructions. For a consumed return qword, a
third exact production replay watches only the runtime-derived cell and only
over the global instruction indices represented by that frozen tail. The
diagnostic rejects replay divergence, a saturated watch, a missing exact
qword writer/reader pair, or a source-register value that disagrees with the
watched write.

The initial post-directory observations are distinct sample addresses but the
same runtime-derived shape:

| Observation | Formal sample 1 | Incomplete-provenance sample 3 |
|---|---:|---:|
| Protected return | `0x000000014005cb7c: ret 0` | `0x000000014009a5ae: ret 0` |
| Consumed qword | `0x0000000fffffef90` = zero | `0x0000000fffffefc0` = zero |
| Last exact writer | `0x000000014005cb1a: mov [rsi],r13`, `R13=0` | `0x000000014009a54d: mov [rax],r15`, `R15=0` |
| Writer-to-reader distance | 31 instructions | 31 instructions |
| Frozen 64-RIP tail digest | `0x96d53dcd14507048` | `0x7daf35286d74de1a` |

Both source instructions are in an image executable section reported as
`.themida`; zero is outside the image and every synthetic module. Section names
are printed as evidence only and do not participate in classification.

### Narrow correct/wrong export controls

Two 22-name controls are committed. Each is the frozen 21-name kernel32 list
from the prior slice plus exactly one sorted candidate:

| Control | Added name | SHA-256 |
|---|---|---|
| `docs/controls/kernel32-with-getcurrentprocess.txt` | `GetCurrentProcess` | `5159afeab422902ffaa4979d4e5cfb81ba7eed95793d05c5d9db449f445869df` |
| `docs/controls/kernel32-with-getcurrentthread.txt` | `GetCurrentThread` | `e0a1d6b8e6f64961e313cf4891d82f80abf4a0c505ac4b05fe6616f005ba0b34` |

The correct control is `GetCurrentProcess` for sample 1 and
`GetCurrentThread` for sample 3; the other file is the crossed wrong-name
control. On the final tree, the correct control advances through the named
call while the crossed control does not. Because each deliberately restricted
module omits the following required name, both paths eventually return through
the same protected tail with another zero value:

| Observation | Formal sample 1 | Incomplete-provenance sample 3 |
|---|---:|---:|
| Correct control advance | handles call 43 `GetCurrentProcess` | handles call 43 `GetCurrentThread`, then call 44 `OpenThreadToken` |
| Wrong crossed control | 42 handled APIs, no candidate call | 42 handled APIs, no candidate call |
| Correct / wrong tail | same `0x96d53dcd14507048` | same `0x7daf35286d74de1a` |
| Correct / wrong total instructions | 35,743,849 / 35,701,441 | 37,594,734 / 37,585,713 |
| Correct / wrong main after yield | 81,646 / 77,964 | 203,264 / 155,619 |
| Correct output SHA-256 | `7069b800b7cf4370c44a21764b97c932aebc77c054b703f8c793f5138a9f8d40` | `5b69a86708ca30d6fd9212dfc667d108f9c07338015a567d73c1a4e189be665c` |
| Wrong output SHA-256 | `a063380c9e3639e1ac1ecf0ef606971eb2470c2dc6ce27da46c17cad9c3d472d` | `fcc1367d08306ac6e8066e987463316b9c860e7aaed7f50b1880a9a14de60ba8` |

Thus export-name availability changes whether the protected resolver returns a
callable API and advances, while the return site, consumed-cell mechanism, and
frozen protected tail remain fixed within each sample. The post-directory null
is not a transfer into an original executable section and is classified as
option (b), not an OEP candidate. No sample address, section name, or sample
index enters production behavior.

Reproduce the final-tree controlled checks locally:

```text
cargo build --locked --release --example trace_child_postmortem

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 250000000 100000 4096 \
  kernel32.dll docs/controls/kernel32-with-getcurrentprocess.txt \
  --production-terminal > /tmp/midas-slice-c-final-ab-s1-correct.txt
target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 250000000 100000 4096 \
  kernel32.dll docs/controls/kernel32-with-getcurrentthread.txt \
  --production-terminal > /tmp/midas-slice-c-final-ab-s1-wrong.txt

target/release/examples/trace_child_postmortem \
  samples/test_target3_protected.exe 250000000 100000 4096 \
  kernel32.dll docs/controls/kernel32-with-getcurrentthread.txt \
  --production-terminal > /tmp/midas-slice-c-final-ab-s3-correct.txt
target/release/examples/trace_child_postmortem \
  samples/test_target3_protected.exe 250000000 100000 4096 \
  kernel32.dll docs/controls/kernel32-with-getcurrentprocess.txt \
  --production-terminal > /tmp/midas-slice-c-final-ab-s3-wrong.txt

sha256sum /tmp/midas-slice-c-final-ab-s{1,3}-{correct,wrong}.txt
```

### Falsifiable OEP-candidate criterion

`src/oep.rs` derives a supported image partition from PE metadata at runtime
and fails closed when the relationships are absent or ambiguous. It does not
consult section names or preferred/sample addresses. The supported layout
requires:

- an executable, raw-backed entry-point code section;
- its mapped-adjacent immediate predecessor to be rawless, writable,
  executable code sharing the entry section's earlier raw-data frontier; and
- pre-boundary executable code to have raw backing and agree exactly with
  `BaseOfCode` and `SizeOfCode` accounting.

Declared section virtual sizes, rather than alignment padding, define accepted
targets. The actual mapped base is explicit. For both observed samples the
derived production layout reports protector boundary RVA `0x0004f000`, loader
section indices `[20, 21]`, and original executable section index `[0]`; these
values are output evidence, not constants in the criterion.

The runtime rule is:

> Accept the first indirect branch or return from a derived loader executable
> region to an exact, previously unexecuted RIP inside a derived original
> executable section.

Indirect calls are excluded because a loader callback/helper is ambiguous;
direct transfers, repeated target RIPs, image padding, data sections,
synthetic modules, and out-of-image targets do not satisfy the rule.

`Emu` tracks target-RIP coverage from the first guest instruction across resume
legs and CPU-context restores. Predecessor continuity resets at host-driven
resume boundaries, preventing a resume directly at a target from being
misreported as a transfer. When a matching source-to-target edge is observed,
the emulator decodes the exact source instruction bytes, freezes a bounded
runtime byte window at the target before it executes, captures the general
register/RIP/flags snapshot, latches the first observation, and stops. The
production runner then re-evaluates that observation with `OepCriterion` and,
if accepted, emits the candidate RIP, source and target section indices,
transfer kind, source bytes, target bytes with bounded disassembly, global
instruction index, and captured registers.

The proof payload also fails closed: the exact target instruction must be
readable and decodable and all 18 registers must be captured before the watch
can latch a candidate. An incomplete payload is retained as an explicit
capture failure and `run_loader` emits no OEP candidate.

This is criterion readiness, not M4 acceptance. Neither raised-cap production
run below produced a qualifying observation, so both print `OEP criterion: did
not fire`. There is no reproducible candidate RIP and therefore no candidate
disassembly artifact to corroborate in this slice.

### Observation-driven API batch after the classified null

The narrow controls exposed different first names on the two variants, and
subsequent bounded runs exposed a short security/token suffix. The final Win64
batch models only the observed shapes:

| API | Supported bounded effect |
|---|---|
| `GetCurrentProcess` | returns the full-width pseudo-handle `-1` |
| `GetCurrentThread` | returns the full-width pseudo-handle `-2` |
| `CheckRemoteDebuggerPresent` | for the current-process pseudo-handle, writes a four-byte false result and returns true |
| `OpenThreadToken` | for current-thread, `TOKEN_QUERY`, `OpenAsSelf=true`, reports no impersonation token, leaves the output untouched, and returns false |
| `OpenProcessToken` | for current-process plus exact `TOKEN_QUERY`, allocates a tracked non-inheritable process-token handle, writes it, and returns true |
| `GetTokenInformation` | for that tracked query handle, `TokenGroups`, `NULL`, length zero: writes required size 4 for an empty `TOKEN_GROUPS` and returns false |

Other process/thread pseudo-handles, access masks, token information classes,
non-query buffers, impersonation state, token groups, security policy, and
last-error behavior remain unmodeled. Unsupported shapes stop as unhandled;
memory/return-frame failures preserve the bounded state established by the
tests.

The resulting observed main suffix is:

- sample 1: `GetCurrentProcess`, `CheckRemoteDebuggerPresent`,
  `GetCurrentThread`, `OpenThreadToken`, `GetCurrentProcess`,
  `OpenProcessToken`, `GetTokenInformation`;
- sample 3: `GetCurrentThread`, `OpenThreadToken`, `GetCurrentProcess`,
  `OpenProcessToken`, `GetTokenInformation`.

### Raised-cap production frontier: `VirtualAlloc`

Normal release production runs with a 250,000,000 per-leg cap and 512-call
bound now reach the same named frontier on both variants:

| Observation | Formal sample 1 | Incomplete-provenance sample 3 |
|---|---:|---:|
| Handled main APIs before stop | 49 | 47 |
| Main instructions after first yield | 224,235 | 190,472 |
| Total guest instructions in terminal diagnostic | 36,156,143 | 37,899,761 |
| `VirtualAlloc` arguments | `RCX=0`, `RDX=4`, `R8=0x1000`, `R9=4` | same |
| OEP criterion | did not fire | did not fire |
| Production output SHA-256 | `7327e7879fdb0580b256d3253eb2c44db0342ccf2f22c8ee03a3d1ba06533967` | `1e5212114f353c0b644ff05c88fe0382cebd79e77025b567e53209d3d7096582` |
| Terminal diagnostic SHA-256 | `c0ed8c01d28ad6acafb32f5bfc45a2e05be435ec7ef7383b657453206e78215a` | `e9114c79a610a37afb679a2ee5af7fe38e1fb736eeb68a36c181ae247feaa683` |

Each production output is byte-identical across two fresh invocations. The
diagnostic reverse-maps target `0x00007fff00001140` to the synthetic
`VirtualAlloc` stub and freezes the full register state above; the address is
runtime evidence and is not production behavior. `VirtualAlloc` semantics are
not added in this slice.

Reproduce the raised-cap frontier locally:

```text
cargo build --locked --release --example run_loader \
  --example trace_child_postmortem

target/release/examples/run_loader \
  samples/test_target_protected.exe 250000000 512 \
  > /tmp/midas-slice-c-final-production-s1-run1.txt
target/release/examples/run_loader \
  samples/test_target_protected.exe 250000000 512 \
  > /tmp/midas-slice-c-final-production-s1-run2.txt
target/release/examples/run_loader \
  samples/test_target3_protected.exe 250000000 512 \
  > /tmp/midas-slice-c-final-production-s3-run1.txt
target/release/examples/run_loader \
  samples/test_target3_protected.exe 250000000 512 \
  > /tmp/midas-slice-c-final-production-s3-run2.txt

cmp /tmp/midas-slice-c-final-production-s1-run1.txt \
  /tmp/midas-slice-c-final-production-s1-run2.txt
cmp /tmp/midas-slice-c-final-production-s3-run1.txt \
  /tmp/midas-slice-c-final-production-s3-run2.txt
sha256sum /tmp/midas-slice-c-final-production-s{1,3}-run2.txt

target/release/examples/trace_child_postmortem \
  samples/test_target_protected.exe 250000000 100000 4096 \
  --production-terminal > /tmp/midas-slice-c-final-frontier-s1.txt
target/release/examples/trace_child_postmortem \
  samples/test_target3_protected.exe 250000000 100000 4096 \
  --production-terminal > /tmp/midas-slice-c-final-frontier-s3.txt
sha256sum /tmp/midas-slice-c-final-frontier-s{1,3}.txt
```

This is an honest Slice C frontier, not OEP proof. Trace recording, VM
detection, IR lifting, a general scheduler, and full token/thread/process memory
semantics remain outside this slice. Formal two-sample acceptance also remains
open: sample 1 has complete provenance, while sample 3 has author-supplied
matching Themida version/configuration but still lacks source and
pre-protection hashes. Sample 3 therefore remains engineering corroboration.
