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
result, but their missing version/config/provenance fields in `samples/SAMPLES.md`
mean they are not yet formal milestone-acceptance evidence.

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
incomplete version/config/source provenance in `samples/SAMPLES.md` means they
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
corroboration. Both then return through zero; full `trap_postmortem` captures
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

Full `trap_postmortem` captures reach a later trampoline return through zero:

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
