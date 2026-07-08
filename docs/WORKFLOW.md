# Dev Workflow

How to build, run, and iterate on midas. Read this first if you're
starting a session.

## Environment

- **Windows side** (`C:\Users\MikhailSidorenko\Documents\midas\`) —
  the canonical repo. Edit code here. Git operations here.
- **WSL2 Ubuntu-22.04** — build environment. Rust toolchain at
  `~/.cargo/bin`, gcc at `/usr/bin/gcc`. Clone lives at `~/midas`.
  Start it: `wsl -d Ubuntu-22.04`.

Midas cannot be built on Windows — Unicorn's build system needs
Linux tooling.

## Setup (one-time)

```sh
# Inside WSL2:
git clone /mnt/c/Users/MikhailSidorenko/Documents/midas ~/midas
cd ~/midas
sudo apt update && sudo apt install -y build-essential cmake libclang-dev clang p7zip-full
cargo build --release
```

## Dev cycle

```
edit (Windows) → git commit → pull in WSL → cargo build → run → read output → repeat
```

One-liner to sync + build:

```sh
cd /mnt/c/Users/MikhailSidorenko/Documents/midas && \
git add -p && git commit -m "..." && \
wsl -d Ubuntu-22.04 -- bash -lc 'cd ~/midas && git pull /mnt/c/Users/MikhailSidorenko/Documents/midas dev && cargo build --release'
```

## Building

```sh
# WSL2:
cd ~/midas
cargo build --release
# Binaries: ~/midas/target/release/{midas,analyze-trace,disasm-loop}
```

## Running

```sh
# Unpack + trace:
./target/release/midas samples/protected.exe
# Produces:
#   samples/protected_unpacked.exe          (OEP memory dump)
#   samples/protected_unpacked.trace.jsonl (per-instruction post-OEP trace)

# Analyze offline (no Unicorn needed, runs in seconds):
./target/release/analyze-trace \
  --input samples/protected_unpacked.trace.jsonl \
  --detect-vm
```

## Why clone to ~/midas and not build on /mnt/c

Cargo's thousands of small file writes against the 9P filesystem
are 5–10× slower than native ext4. Always build in `~/midas`.

## Debug flags (hidden from --help)

| Flag | What it does |
|---|---|
| `--no-devirt-trace` | Skip trace recording, pure-unpack mode |
| `--devirt-trace <path>` | Override trace output path |
| `--devirt-trace-limit <N>` | Cap post-OEP events (default 10M) |
| `--devirt-capture-regs-at 0xRIP` | Manual reg snapshot at a specific RIP |
| `--max-instructions <N>` | Lower from 500M default for faster fail |
| `--verbose` / `--quiet` | Log level control |

## What you're usually doing

The unpacker (`src/unpacker.rs`) is relatively stable. Active work
is in `src/devirt/` — VM detection + IR lifting + simplification.

| Task | Edit | Rebuild → run |
|---|---|---|
| VM detection | `src/devirt/vm/detector.rs` | `analyze-trace --detect-vm` → check descriptors |
| IR lifter | `src/devirt/ir/lifter.rs` | `analyze-trace --lift-handler N` → check coverage |
| Simplifier | `src/devirt/ir/simplify.rs` | `analyze-trace --detect-vm` → check pseudo-C |

The trace JSONL is ground truth. Once you have a trace, iterate on
analysis without re-running Unicorn (sample 1 takes ~195M insns
to reach OEP).

## Commit discipline

- **Branch `dev`** for all active work. `main` stays at the
  "unpacker reaches OEP" checkpoint.
- **Commit at every milestone slice.** Each commit compiles,
  passes its own tests, describes *why* not just *what*.
- **Both samples must keep passing.** "Works on sample X" is not
  progress — the sample-agnostic axiom is load-bearing.
- Never `git add .` — stage specific files.

## Samples

`samples/` is gitignored. Test PEs land there on the WSL side.
The test target (a trivial C program packed with Themida) is the
first sample controlled end-to-end.

## Architecture context

- `src/unpacker.rs` — Unicorn emulation driver. Loads PE, stubs
  WinAPI (PEB/TEB/LDR, kernel32/ntdll), runs to OEP, dumps memory,
  records devirt trace.
- `src/devirt/` — offline analysis pipeline:
  - `trace.rs` / `trace_events.rs` — JSONL recorder
  - `vm/detector.rs` — VM-pattern detector → `VmDescriptor`
  - `vm/eval.rs` — concrete evaluator + replay walker
  - `ir/{expr,lifter,simplify,emit}.rs` — IR + iced-x86 lifter
  - `oep_dump.rs` — VA-based reader for the PE dump
- `src/bin/analyze-trace.rs` — research CLI over the trace

## Design axioms (load-bearing, don't relax)

1. **Sample-agnostic.** No hardcoded per-sample offsets, constants,
   or RIPs. Detection is pattern-based; parameters come from
   runtime auto-detection.
2. **Zero-config CLI.** One positional arg — the PE path. Every
   other flag is a debug back-door.
3. **Pure Rust, in-tree.** No Triton, miasm, z3. If a SAT solver
   becomes necessary, `varisat` is the approved path.
