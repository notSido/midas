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
hardcoded per-sample constants" acceptance criterion. **Two samples are now
present on disk** (both gitignored).

## Support assets

### `kernel32.dll` (export-name source for the synthetic win64 module)

| Field | Value |
|---|---|
| Filename | `samples/kernel32.dll` (gitignored) |
| SHA-256 | `8fce3e55da4919423661e89d53434797b0c2f6b488a4ae0317285b57633326b0` |
| Size | 683,288 bytes |
| Format | **PE32 (32-bit, i386)** DLL — note the bitness |
| Version | 10.0.26100.7920 (Windows 11 24H2), FileVersion/ProductVersion from the resource |
| Provenance | Copied from a 64-bit Windows 11 notebook's `C:\Windows\System32\kernel32.dll`; the file is 32-bit because a 32-bit tool triggered **WOW64 file-system redirection** (System32 → SysWOW64). |
| Use in midas | **Export *name* list only** (1664 names; bitness-independent). midas never maps or executes this binary. The names seed the synthetic PE32+ kernel32 export table so the loader's manual export walk resolves any function it looks up. A 64-bit copy is not required for this purpose. |

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

### 2. `test_target2_protected.exe`

| Field | Value |
|---|---|
| Filename | `samples/test_target2_protected.exe` |
| SHA-256 | `1f583d70d7bd0655cd873415dd818adeee8215769d73754065719d133f45f3ee` |
| Size | 1,903,014 bytes |
| Format | PE32+ (PE64) console executable, x86-64, 23 sections (per `objdump`: ImageBase `0x140000000`, AddressOfEntryPoint `0x33d058`, Subsystem 3 Windows CUI) |
| Protector | Themida (provenance to be supplied by the sample author) |
| Themida version | *to be supplied by author* |
| Config | *to be supplied by author* |
| Provenance | Second distinct sample, deposited on disk 2026-07-09. Themida version/config, source program, and pre-protection hash are **not yet recorded** — the fields above marked "to be supplied" must be filled in by the author before this sample is relied on for a milestone artifact. The SHA-256, size, and format fields were computed directly from the on-disk binary. |

> The verified facts (hash, size, format, and the `objdump`-read header values)
> are direct observations of the deposited file. The Themida version/config and
> source provenance are placeholders until the author records them; do not treat
> them as known.
