# Samples

Real Themida-protected PE64 binaries used for the sample-dependent milestones
(M3–M7). The binaries themselves are **gitignored and never committed** — only
this metadata file is tracked.

Any Themida internals reported below (VM architecture, wrap counts, etc.) come
from the tool's own protection log and are recorded as **provenance**, not as
verified analysis findings. Per `docs/CHARTER.md`, all such values are
hypotheses to re-confirm against disassembly before midas relies on them.

## Sample inventory

Two distinct samples are required to satisfy the "sample-agnostic, zero
hardcoded per-sample constants" acceptance criterion. **Only one is present so
far**; a second must be provided before that criterion can be met.

### 1. `test_target_protected.exe`

| Field | Value |
|---|---|
| Filename | `samples/test_target_protected.exe` |
| SHA-256 | `8e3796d03ddcdc8d66444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf` |
| Size | 1,651,622 bytes |
| Format | PE32+ (PE64) console executable, x86-64, 23 sections |
| Protector | Themida demo (free evaluation build), `Themida64.exe` |
| Themida version | 3.2.4.34 (x64) |
| Config | Demo defaults: Anti-debug ON; Compress & Encrypt (Application, Resources, SecureEngine) ON; Detect file/registry monitors ON; Allow execution under VMware/Virtual PC ON. Entry Point Virtualization, Anti-File-Patching, Anti-Sandbox, String Encryption all OFF. |
| VM (per protection log) | Machine #1 FALCON64 (Tiny), Machine #2 Internal (Falcon demo); ~166 KB each. |
| API wrapping (per protection log) | 94 imported-API references wrapped. |
| Provenance | Built from `test_target.c` — a single-translation-unit, kernel32-only C program (no CRT I/O, integer-only). Pre-protection binary SHA-256 `2e1f5a921bae7483d21221adaf770fa7e71ea6fe700cd73e1eda6976dfe84f29`, 298,390 bytes. Verified to run standalone on Windows (demo splash then identical program output). |

### 2. (second sample — not yet provided)

Required before the "two distinct samples" generality criterion in
`docs/CHARTER.md` can be satisfied. STOP and request it at the M3→M4 boundary if
still absent.
