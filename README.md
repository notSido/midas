# Midas

A Themida 3.x unpacker + static devirtualizer for Linux, written in
pure Rust. Runs Windows PE binaries through Unicorn CPU emulation,
reaches the original entry point, and produces a readable pseudo-C
reconstruction of the VM-protected code — all from a single positional
argument.

```sh
midas protected.exe
```

Two artifacts, one command. Nothing else to pass.

## What it does, end-to-end

Running `midas <path>` produces:

- `<stem>_unpacked.exe` — a PE dump of the post-OEP memory image.
- `<stem>_unpacked.trace.jsonl` — a trace of every instruction executed
  post-OEP, plus register/memory snapshots at every VM dispatcher
  fetch and exit.

Running `analyze-trace --input <trace> --detect-vm` then reconstructs
the observed VM program:

```
== VM detector ==
unique VM contexts: 3

--- descriptor #1 ---
  dispatch_rip:         0x1410488b9
  vm_pc_addr:           0x14109a7f8  *(u64*) = 0x141378560
  handler_table_addr:   0x14109a784  *(u64*) = 0x1412b2db6
  dispatch evaluation:  OK — R10 = 0x141235c89  (matches captured)

  observed VM program: 3 dispatches, 1 unique handlers

  handler_0x141235c89() {
      *(u32*)(rbp + 0x1d2) = *(u32*)(rbp + 0x1d2) ^ decrypt_expr;
      *(u32*)(rbp + 0xda) = *(u32*)(rbp + 0xda) - 0x729adfce;
      *(u8*)(rbp + 0x88) = *(u8*)(rbp + 0x88) - decrypted_byte;
      if (((*(u32*)(rbp + 0xda) & 1) == 0) == 1) goto 0x14123603b;
      *(u32*)(rbp + 0xda) = *(u32*)(rbp + 0xda) - 0x1a94db9d;
  }

  // VM program trace (tick → handler)
  //   tick    1109775  handler_0x141235c89()
  //   tick    1569072  handler_0x141235c89()
  //   tick    2155372  handler_0x141235c89()
```

Every statement above comes from the native Themida handler body
through: trace capture → IR lift → forward substitution →
algebraic simplification → pseudo-C emit. 128 native instructions
per handler collapse to 5-10 semantic statements.

## Pipeline

```
  midas <sample>
    |
    v
  +------------------+
  | Unicorn emulator |
  | + WinAPI stubs   |
  | + OEP detector   |
  +------------------+
    |
    +--> <sample>_unpacked.exe      (OEP memory dump as PE)
    +--> <sample>_unpacked.trace.jsonl
           |
           | per-instruction post-OEP stream +
           | auto-captured regs/mem at every
           | indirect jmp r<reg> and movzx word ptr
           v
  +-------------------------------+
  | analyze-trace --detect-vm     |
  |                               |
  |  1. VM-pattern detector       |   finds Themida dispatchers
  |  2. Context dedup             |   collapses inlined sites
  |  3. Dispatcher evaluator      |   validates against captures
  |  4. Bytecode replay walker    |   emits all observed opcodes
  |  5. IR lift + simplify + emit |   produces pseudo-C handlers
  +-------------------------------+
    |
    v
  pseudo-C VM program (stdout)
```

## Status

**Working end-to-end** on both reference samples in `samples/`:

| Stage                                | Sample 1    | Sample 2    |
|--------------------------------------|-------------|-------------|
| Unpack → OEP                         | OK (197M insns) | OK (97M insns)  |
| Devirt trace                         | 298+ captures   | 298+ captures   |
| VM detector (unique contexts)        | 3 detected      | 3 detected      |
| Dispatcher evaluator vs ground truth | 27/27 match     | 3/3 match       |
| Pseudo-C handler emit                | 8 unique / 27 firings | 1 unique / 3 firings |

Zero per-sample constants in code. Every sample-specific parameter
(VM_PC offset, handler-table offset, decryption formula,
dispatcher entry / exit RIPs) is auto-detected at runtime from
invariant patterns.

## Design axioms

These constraints are load-bearing and shouldn't be relaxed
without explicit renegotiation:

1. **Sample-agnostic.** No hardcoded per-sample offsets, constants,
   or RIPs in code. Detection is pattern-based; parameters come
   from runtime auto-detection.

2. **Zero-config CLI.** The binary takes exactly one positional
   argument — the path to the protected PE. Every other flag is a
   debugging back-door (many are hidden from `--help`).

3. **Pure Rust, in-tree.** No Triton, miasm, z3 / boolector bindings.
   If a SAT solver becomes necessary, `varisat` (pure-Rust SAT) is
   the approved path — defer until algebraic simplification proves
   insufficient.

## Building

Must be built on Linux; Unicorn's build system depends on Linux
tooling. The usual setup is a Docker container.

```sh
docker run --rm -v "$(pwd):/midas" -w /midas rust:bookworm bash -c '
  apt-get update && apt-get install -y libclang-dev clang cmake p7zip-full
  cargo build --release
'
# Binary: target/release/midas
# Helper: target/release/analyze-trace
```

macOS developers: run the build inside a persistent Docker container.

## Usage

```sh
# Unpack + trace in one shot:
midas samples/protected.exe

# Analyze the resulting trace:
analyze-trace --input samples/protected_unpacked.trace.jsonl --detect-vm
```

Optional debug flags (hidden from `--help` as they're not for the
happy path):

- `--no-devirt-trace` — opt out of the trace recording (pure-unpack
  mode, small perf win).
- `--devirt-trace <path>` — override the default trace path.
- `--devirt-trace-limit <N>` — cap post-OEP events recorded
  (default 10M).
- `--devirt-capture-regs-at 0xRIP` — manual one-shot reg capture at a
  specific RIP (the automatic path captures every indirect `jmp
  r<reg>` and `movzx r, word ptr [...]` already).

## Limitations

Be honest about what doesn't work yet:

- **Observed-execution only.** The pseudo-C emit is driven by what
  the VM actually executed during recording. Statically enumerating
  *every possible* VM opcode the sample could execute requires
  forward-simulating handler effects, which the current simplifier
  only partially supports. The handler bodies themselves aren't
  walked for their own branches.
- **Non-runnable PE dumps.** The OEP dump is analysis-grade, not
  executable. IAT reconstruction is partial; the dumped PE crashes
  on first call through an unresolved import. Static analysis is
  unaffected.
- **64-bit only.** PE32+ (x86-64). No 32-bit PE support.
- **Themida 3.x focus.** Tested on Themida 3.x samples; other
  versions or packers aren't supported.

## Architecture

Three-tier crate layout:

- `src/unpacker.rs` — main emulation driver. Loads the PE into
  Unicorn, runs until the OEP breakout heuristic fires, dumps memory,
  records the devirt trace.
- `src/devirt/` — offline analysis.
  - `trace`, `trace_events` — JSONL recorder.
  - `vm/detector.rs` — canonical VM-pattern detector.
  - `vm/eval.rs` — concrete evaluator + replay walker.
  - `ir/{expr, lifter, simplify, emit}.rs` — IR, iced-x86 lifter,
    simplifier, pseudo-C emitter.
  - `oep_dump.rs` — VA-based reader for the unpacker's PE dump.
- `src/bin/analyze-trace.rs` — research CLI over the trace and dump.

## Dependencies

- `unicorn-engine` — CPU emulation.
- `iced-x86` — x86 decoder + encoder.
- `goblin` — PE header parsing.
- `serde`, `serde_json` — trace event serialization.
- `clap` — CLI parsing.

All Rust, no C++ bindings beyond Unicorn's internal C.

## Further reading

- `docs/DEVIRT.md` — devirt milestone plan, findings, architecture
  notes. The authoritative source for what's been tried, what works,
  and what's next in the devirt pipeline.

## License

GPL-3.0 — see `LICENSE`.
