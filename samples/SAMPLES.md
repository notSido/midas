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
hardcoded per-sample constants" acceptance criterion. **Three samples are now
present on disk** (all gitignored).

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
| Protector | Themida demo (free evaluation build), `Themida64.exe` |
| Themida version | 3.2.4.34 (x64), supplied by the sample author |
| Config | Same demo-default configuration as sample 1, supplied by the sample author: Anti-debug ON; Compress & Encrypt (Application, Resources, SecureEngine) ON; Detect file/registry monitors ON; Allow execution under VMware/Virtual PC ON. Entry Point Virtualization, Anti-File-Patching, Anti-Sandbox, String Encryption all OFF. |
| Provenance | Second distinct sample, deposited on disk 2026-07-09. The author confirmed the version/configuration on 2026-07-11. The source program and pre-protection hash are **not yet recorded** because the original is temporarily unavailable on the author's work notebook. The SHA-256, size, and format fields were computed directly from the on-disk binary. |

> The hash, size, format, and `objdump`-read header values are direct
> observations of the deposited file. Version/configuration are author-supplied
> provenance. Source and pre-protection-binary provenance remain pending.

### 3. `test_target3_protected.exe`

| Field | Value |
|---|---|
| Filename | `samples/test_target3_protected.exe` |
| SHA-256 | `6c70e14c40fde8661b0b0121161deb1afd9edffd682f1f30f2b5916895f79585` |
| Size | 1,911,748 bytes |
| Format | PE32+ (PE64) console executable, x86-64, 23 sections; entry RVA `0x33d058` (from midas / probe) |
| Protector | Themida demo (free evaluation build), `Themida64.exe` |
| Themida version | 3.2.4.34 (x64), supplied by the sample author |
| Config | Same demo-default configuration as samples 1 and 2, supplied by the sample author: Anti-debug ON; Compress & Encrypt (Application, Resources, SecureEngine) ON; Detect file/registry monitors ON; Allow execution under VMware/Virtual PC ON. Entry Point Virtualization, Anti-File-Patching, Anti-Sandbox, String Encryption all OFF. |
| Provenance | Third distinct sample, deposited on disk 2026-07-09. The author confirmed the version/configuration on 2026-07-11. The source program and pre-protection hash are **not yet recorded** because the original is temporarily unavailable on the author's work notebook. SHA-256, size, and format were computed directly from the on-disk binary. |

> Same caveat as sample 2: hash/size/format and midas-observed header values are
> direct observations; version/configuration are author-supplied provenance;
> source and pre-protection-binary provenance remain pending.

## Cross-sample generality (observed)

The M3 finding chain reproduces **identically on all three samples** with no code
changes: each self-decrypts (~26–29M instructions), hits the same unbound-IAT
wall (`GetModuleHandleA` at import RVA `0x4d00d`, `RCX` → `"kernel32.dll"`), and
after the import-call trap + synthetic kernel32 proceeds through the export walk
to resolve `LoadLibraryA` and read its bytes. This is the sample-agnostic
behaviour the charter requires; per-instance values (entry RVA, instruction
counts, string pointers) differ, the mechanism does not.
`docs/FINDINGS-M3-import-wall.md` documents the mechanism in detail on the first
two samples; the third's reproduction is confirmed here (instruction count to the
wall: sample 1 ≈ 26.5M, sample 2 ≈ 28.2M, sample 3 ≈ 28.3M).
