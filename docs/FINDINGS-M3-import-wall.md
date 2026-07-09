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
a **callable stub address** for the requested `(module, name)` — i.e. resolve the name
against the given module's synthetic export table and, because the loaded DLLs currently
have empty tables, dynamically add a stub for the requested name to that module on
demand so the returned address later faults and dispatches by name. `lpProcName` (in
`RDX`) may be a name pointer or an ordinal (low bits, high bits zero); handle both.
Implementing this both unblocks the loader and reveals — via the requested names — which
functions it resolves from user32/advapi32/ntdll/shell32/shlwapi, each then observed and
handled one at a time, re-validated on all samples.
