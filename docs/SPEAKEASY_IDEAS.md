# Ideas to Borrow from Speakeasy

Speakeasy (Mandiant's Python Windows malware emulator) and Midas (our Rust
Themida unpacker) both sit on top of Unicorn and both fake a Windows runtime.
Speakeasy is a mature generalist; Midas is a focused unpacker. A lot of the
generalist scaffolding translates directly into things that will make Midas
more reliable on real Themida 3.x samples.

Repos referenced:

- Midas: https://github.com/notsido/midas
- Speakeasy: https://github.com/notsido/speakeasy

Source references use `repo:path:line` where helpful.

---

## Snapshot of what each side looks like today

| Area                   | Midas                                                          | Speakeasy                                                                         |
| ---------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Language               | Rust                                                           | Python                                                                            |
| Emulator               | Unicorn (direct)                                               | Unicorn behind `EmuEngine` wrapper (`speakeasy/engines/unicorn_eng.py`)           |
| API table              | Manual string map in `ApiRegistry::register_*` (~35 funcs)     | Auto-loaded decorator registry across `speakeasy/winenv/api/usermode/*.py` (40+ modules) |
| API args               | Hand-rolled `reg_read(RCX/RDX/R8/R9)` + manual RSP math        | `@apihook(name, argc=N, conv=...)` with centralized arg extraction                |
| PEB/TEB                | Minimal C struct copy (`src/win64/peb.rs`)                     | Full PEB + LDR with decoy modules (`speakeasy/windows/objman.py`, `winenv/decoys`) |
| Memory manager         | `workspace += size` bump allocator (`src/unpacker.rs:14`)      | Tagged page-block allocator with reserve/commit/free (`speakeasy/memmgr.py`)      |
| Hooks                  | Inline closures in `Unpacker::run_emulation`                   | `Hook` / `ApiHook` / `DynCodeHook` / `MapMemHook` class hierarchy (`common.py`)    |
| Reporting              | Flat `UnpackResult` struct (`src/result.rs`)                   | Versioned event log with tick/tid/pid positions + artifact store (`profiler.py`) |
| Structs                | `#[repr(C)] struct Peb { ... }` only                           | `EmuStruct` mini-ORM + NT defs (`struct.py`, `winenv/defs/nt/*`)                   |
| Isolation              | In-process                                                     | Multiprocess + timeout + exit_event (`cli.py`)                                    |
| Config                 | CLI flags only                                                 | JSON config with volumes, OS version, user, locale (`config.py`, `volumes.py`)    |
| Strings                | Byte-by-byte loops inlined into each API handler               | `read_ansi_string` / `read_unicode_string` / `do_str_format` helpers              |

---

## Priority 1 — high impact, bounded effort

### 1. Attribute-driven API handler registry

**What speakeasy does.** Handlers are methods on a class, annotated with a
decorator that records the export name, arg count, and calling convention:

```python
# speakeasy/winenv/api/usermode/ntdll.py
class Ntdll(api.ApiHandler):
    name = "ntdll"
    apihook = api.ApiHandler.apihook

    @apihook("LdrLoadDll", argc=4)
    def LdrLoadDll(self, emu, argv, ctx=None):
        SearchPath, LoadFlags, Name, BaseAddress = argv
        ...
```

The base class walks `dir(self)` looking for `__apihook__` attributes and
auto-populates `self.funcs` (`speakeasy/winenv/api/api.py:57-78`). A separate
`autoload_api_handlers()` in `winenv/api/winapi.py` discovers every subclass
via `inspect.getmembers` so adding a new DLL = dropping a new file.

**What Midas does today.** `ApiRegistry::register_kernel32_apis` and
`register_ntdll_apis` in `src/win64/api/registry.rs` hand-list every export
and each handler pops `RCX/RDX/R8/R9` itself. Stack arg handling is manually
reimplemented inside each handler (see `nt_protect_virtual_memory` in
`src/win64/api/ntdll.rs` which computes `rsp + 0x28`).

**Action for Midas.**
1. Introduce an `ApiHandler` trait + `#[api(name = "LdrLoadDll", argc = 4)]`
   proc-macro (or a `linkme`/`inventory`-backed submit macro — both work on
   stable Rust). Each handler receives a pre-extracted `&[u64]` argv and a
   `&mut EmuContext` instead of a raw `&mut Unicorn<()>`.
2. Move the `reg_read(RCX)`/`mem_read(rsp + 0x28)` logic into a single
   `extract_args(emu, argc, conv)` helper modeled on speakeasy's call-conv
   dispatch. x64 → RCX, RDX, R8, R9 then `[rsp+0x28 + 8*i]`; x86 stdcall/cdecl
   → walk the stack. Future-proofs Midas for x86 Themida without a rewrite.
3. Drop the manual `register_*` functions. Registration happens at build time
   via the macro.

**Why it matters.** The single largest contributor to "an API broke; now
emulation stopped" bugs is arg-extraction drift. Centralizing it also makes
every handler shorter — the `nt_protect_virtual_memory` body shrinks by ~20
lines.

---

### 2. Tagged page-block memory manager

**What speakeasy does.** `MemoryManager.mem_map` (`speakeasy/memmgr.py:85-127`)
sub-allocates out of page blocks for small requests, pads to 0x10, tracks a
`tag` per allocation, supports `reserve` + later `mem_map_reserve` (MEM_RESERVE
→ MEM_COMMIT), and implements `get_valid_ranges` to find an unused range by
scanning `emu_eng.mem_regions()`. `mem_free` only unmaps when every tagged
block in the page is free.

**What Midas does today.** A single `WORKSPACE_BASE = 0x20000000` and each
`VirtualAlloc` / `NtAllocateVirtualMemory` does:

```rust
let aligned_size = (size + 0xFFF) & !0xFFF;
let address = *workspace;
emu.mem_map(address, aligned_size, Prot::ALL)?;
*workspace += aligned_size;
```

Consequences already visible:

- `VirtualFree` is a no-op (`src/win64/api/kernel32.rs:virtual_free`). Space is
  never reclaimed.
- Every small allocation (e.g. Themida's dozens of 8-byte scratch allocs)
  consumes a full 0x1000 page.
- `VirtualQuery` can't answer (`src/win64/api/kernel32.rs:virtual_query`
  returns 0) because there's no metadata store.
- We can't honor `flProtect`; everything is mapped `Prot::ALL`. Packers that
  probe `PAGE_NOACCESS` guard pages to detect emulation will flag us.

**Action for Midas.**
1. Add `src/emu/memmgr.rs` with `MemMap { base, size, tag, prot, free, block_base }`
   and a `MemoryManager` that owns the Unicorn engine handle, mirroring the
   speakeasy API (`mem_map`, `mem_reserve`, `mem_commit`, `mem_free`,
   `mem_protect`, `get_address_tag`, `get_valid_ranges`).
2. Replace the `workspace: &mut u64` arg threading through every API handler
   with `&mut MemoryManager`. Allocations become `mm.mem_map(size, tag =
   "api.VirtualAlloc")`.
3. `VirtualQuery` then returns a populated `MEMORY_BASIC_INFORMATION` from
   the metadata; anti-emulation checks pass.

**Why it matters.** Themida aggressively uses `VirtualAlloc`,
`VirtualProtect`, and `VirtualQuery` to map trampolines and probe the
environment. Our current bump allocator is the most likely reason a
non-trivial sample will stop emulating before OEP.

---

### 3. Decoy DLLs for realistic `GetProcAddress` / `LoadLibrary`

**What speakeasy does.** Ships prebuilt PE stubs under
`speakeasy/winenv/decoys/{amd64,x86}/` for kernel32.dll, ntdll.dll, user32.dll,
etc. When malware calls `LoadLibraryA("kernel32.dll")`, speakeasy maps the
decoy, wires it into the PEB `InLoadOrderModuleList`, and `GetProcAddress`
returns an address inside that real-looking PE. Export walking from JITed
shellcode (a Themida favorite) then Just Works.

**What Midas does today.** `get_proc_address` hashes `module+name` and
returns a synthetic address in `0xFEEE_0000..0xFEFF_FFFF`
(`src/win64/api/kernel32.rs:55-88`). `LoadLibraryA` hashes the name into
`0x7000_0000..0x7FFF_0000`. There is no LDR entry for the loaded module, and
Themida's routine "walk the PEB LDR to find ntdll!LdrLoadDll manually" path
will fail.

**Action for Midas.**
1. Ship `resources/decoys/amd64/{kernel32,ntdll,user32}.dll`. Can be minimal —
   just needs a valid export table with names pointing at small RET stubs.
2. On first `LoadLibrary*` or `GetModuleHandle*`, map the decoy from
   `resources/`, register it in a Rust `ModuleManager`, and append to the
   LDR lists in `src/win64/ldr.rs`.
3. `GetProcAddress` walks the decoy's export table to return real addresses.
   Our existing `ApiRegistry` hooks already fire on execution of those
   addresses because code hooks are `0..u64::MAX`.
4. Delete the FNV-1a synthetic address scheme.

**Why it matters.** Themida's import resolver does manual PEB/LDR walks and
manually parses export directories. Without decoys we have no way to resolve
those without also hooking the manual walker.

---

## Priority 2 — bigger scope, bigger payoff

### 4. Real profiler + artifact store instead of `UnpackResult`

**What speakeasy does.** `profiler.py` captures a stream of typed events
(`ApiEvent`, `FileReadEvent`, `MemWriteEvent`, `NetHttpEvent`,
`ExceptionEvent`, etc., defined in `profiler_events.py`), each carrying a
`TracePosition { tick, tid, pid, pc }`. Duplicate/adjacent events are merged
(e.g. `MemWriteEvent` at `base+size` extends the previous event). Binary
payloads go through `ArtifactStore` — zlib-compressed, base64-encoded,
deduped by sha256 (`speakeasy/artifacts.py`). Report is versioned
(`__report_version__ = "3.0.0"`) and serialized through a pydantic `Report`
model.

**What Midas does today.** `UnpackResult` (`src/result.rs`) is a flat struct:
success bool, OEP address, version, instruction count, optional list of API
names. `apis_called`, `warnings`, and `code_sections_modified` are never
actually populated — the fields exist but nothing sets them. The tracer
(`src/tracer.rs`) accumulates stats but they don't end up in JSON output.

**Action for Midas.**
1. Create `src/report/events.rs` with `ApiCall`, `MemoryWrite`, `SectionDump`,
   `OepTransition`, `BreakoutDetected`, `UnmappedAccess`. Each event has
   `{ tick, rip, module, ... }`.
2. Replace `UnpackResult` with `Report { version: "1.0.0", events, dumps,
   artifacts, ... }`. Events are the append-only log produced during
   emulation.
3. Add an `ArtifactStore` wrapping zlib + sha256. Memory dumps, the final PE,
   and any dropped data live there, referenced by hash from events. Gives us
   a compact JSON report even for 10 MB dumps.
4. `OepDetector::on_execute` pushes an `OepTransition` event instead of just
   mutating `self.oep`. The tracer's "breakout detected" log line becomes a
   `BreakoutDetected` event.

**Why it matters.** The Midas README lists features ("JSON output mode for
automation") that aren't yet useful because the JSON barely describes what
happened. A proper event log turns Midas into something a triage pipeline
can consume without parsing our logs.

---

### 5. Engine abstraction behind a trait

**What speakeasy does.** `EmuEngine` in `speakeasy/engines/unicorn_eng.py`
hides Unicorn's constants behind speakeasy-native ones (`HOOK_CODE`,
`PERM_MEM_RWX`, etc. from `common.py`). Callers never import `unicorn`
directly — if Mandiant wanted to swap in Bochs or QEMU, it would be a
drop-in.

**What Midas does today.** Every file has `use unicorn_engine::...`.
`src/unpacker.rs` directly configures code hooks and memory hooks, and each
API handler takes `&mut Unicorn<()>`.

**Action for Midas.**
1. Define `trait EmuEngine { fn mem_map; fn mem_read; fn reg_read; fn
   hook_code; fn start; ... }` in `src/emu/engine.rs`.
2. Implement `UnicornEngine: EmuEngine`. API handlers become generic over
   `E: EmuEngine`.
3. Nice side effect: unit-testing handlers becomes trivial — drop in a
   `MockEngine` that records `(reg_write, RAX, value)` calls.

**Why it matters.** Also gives us a seam to experiment with `mwemu` (already
called out in the README's "Inspiration" section) without ripping up every
handler.

---

### 6. `DynCodeHook` for OEP detection

**What speakeasy does.** `DynCodeHook` in `common.py` fires the first time
execution enters a dynamically-mapped region. Combined with `record_dyn_code_event`
in the profiler, it's a clean signal for "packer just jumped into its
unpacked code."

**What Midas does today.** `ExecutionTracer::detect_breakout` is heuristic —
it watches for a spike in unique addresses per million instructions. Good
signal, but false positives are possible, and it doesn't catch the case where
the unpacked region is tiny.

**Action for Midas.**
1. Track every `VirtualAlloc` / `NtAllocateVirtualMemory` /
   `NtProtectVirtualMemory(...PAGE_EXECUTE...)` in the memory manager with
   a `dyn_code: true` flag.
2. On the code hook, when `addr` first lands in a region tagged `dyn_code`,
   emit an `OepTransition` event with high confidence and stop.
3. Keep the unique-address spike as a secondary signal (for packers that
   unpack in place).

**Why it matters.** A deterministic OEP signal. Right now
`Unpacker::run_emulation` has a convoluted flow where "breakout detected"
only sets a flag, and the actual OEP is whatever `RIP` happened to hold
when the flag was noticed.

---

## Priority 3 — nice-to-haves once the above is in

### 7. String and struct helpers

Speakeasy handlers use `read_ansi_string(addr)`, `read_unicode_string(addr)`
(UNICODE_STRING descriptor, not just a wide buffer), and `do_str_format`
(printf parser) — see `speakeasy/winenv/api/api.py:149-220`. Midas handlers
like `load_library_a` inline a 256-byte byte-by-byte loop, and
`load_library_w` does the same for UTF-16 (see lines 95-110 and 152-170 of
`src/win64/api/kernel32.rs`).

Action: add `src/utils/strings.rs` with `read_cstr`, `read_wstr`,
`read_unicode_string_descriptor`, `read_ansi_string_descriptor`. Cuts each
string-taking handler in half.

### 8. Configurable environment

`speakeasy/config.py` exposes OS version, computer name, user name,
locale, drive layout, and mounted volumes. Themida probes `RtlGetVersion`,
`GetComputerNameA`, `GetUserNameA`, `GetVolumeInformationA`. Midas hardcodes
`10.0.19041.0` in `rtl_get_version` and a fixed sample path in
`get_module_filename_a`. A `src/emu/env.rs` Config (loadable from a JSON
file, overridable from CLI) lets us spoof a different environment per run —
useful for unpacking samples that only run on a specific locale.

### 9. Handle-based object manager

`speakeasy/windows/objman.py` allocates monotonic handles and maps them to
real objects (files, keys, threads, processes). Midas returns `-1`, `0xFFFFFFFF...FFFE`,
etc. from `GetCurrentProcess` / `GetCurrentThread` and `close_handle` is a
no-op. A minimal `HandleTable { next: u64, map: HashMap<u64, HandleKind> }`
lets us round-trip handles through `CreateFile`/`ReadFile`/`CloseHandle` for
free.

### 10. Multiprocess + real timeout enforcement

`speakeasy/cli.py` runs the emulation in a `multiprocessing.Process` with a
`mp.Event` exit flag, enforcing `--timeout` hard. Midas accepts `--timeout`
but the implementation is a TODO — emulation runs inline and we rely on
`max_instructions`. Rust equivalent: spawn a thread, call `emu_stop()` from
a watchdog when the timeout elapses. Important for CI loops (the existing
`analyze-loop.sh`) so a pathological sample doesn't wedge the runner.

---

## Non-goals

These speakeasy features are intentionally out of scope for Midas:

- **Kernel-mode driver emulation** (`windows/kernel.py`, `kernel_mods/`).
  Themida 3.x is user-mode.
- **Network / HTTP emulation** (`windows/netman.py`). Themida phones home
  rarely, and when it does, an unreachable network is correct behavior.
- **File system emulation** (`windows/fileman.py`). We don't need dropped
  files; we need the unpacked PE dump. Keep it simple.
- **COM support** (`windows/com.py`). Not on the Themida 3.x hot path.

The design lessons from those modules (event emission, object manager,
tagged allocations) are still worth stealing; the modules themselves are
not.

---

## Suggested order of work

1. #1 attribute-driven API registry — unblocks everything else because new
   handlers become cheap to add.
2. #2 memory manager — highest direct impact on real-sample success rate.
3. #3 decoy DLLs — retires the biggest remaining class of failure (manual
   PEB walks).
4. #4 profiler + artifact store — once we have real event sources from 1-3,
   the report becomes worth producing.
5. #5, #6 engine trait + DynCodeHook — enables cleaner testing and a
   deterministic OEP signal.
6. #7-#10 polish.

Each step is independently shippable and each builds on the previous without
forcing a rewrite.
