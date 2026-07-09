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
- **Populating the TEB self-pointer does not move the wall.** After writing
  `NtTib.Self = TEB_BASE`, `StackBase/StackLimit`, and `TEB.ProcessEnvironmentBlock
  = PEB_BASE`, the sample still faults at `0x4d00d` at the identical instruction
  count. So the `gs:[0x30]` reads tolerate their value (consistent with an
  anti-debug / pointer-encode use), and the wall is specifically the unresolved
  API bootstrap — not a missing TEB field. The TEB population is retained as
  correct environment modeling (both samples read `gs:[0x30]`), not as a fix for
  the wall.

### Consequence for the design (still partly open)

Because resolution is not `PEB->Ldr`-based, a byte-accurate fake kernel32 export
directory is *not* the lever. The lever is the **placeholder call itself**: the
loader transfers control to an unresolved placeholder address with the DLL name
in `RCX`. A candidate design is to treat a control-transfer to an unmapped
placeholder as an **API-call trap** — identify the intended API, emulate its
effect, set `RAX`, and resume at the on-stack return address. The **open
sub-question** is how to identify *which* API each placeholder denotes (the DLL
is in `RCX`, but the function selector — name string, ordinal, or hash, and where
it lives relative to the call site/table) is **not yet determined** and must be
traced before the trap handler is designed. This is the next investigation.
