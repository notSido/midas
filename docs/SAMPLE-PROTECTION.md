# Sample Protection Log — Themida Demo

Provenance record for the test PE that will live in `samples/`.
This file documents **exactly** how the sample was protected with
the Themida demo so we can separate "what the unpacker must undo"
from "what the original source looked like."

The midas test target is a trivial C program. We protect it with
the **Themida demo** (free evaluation build) so the result is a
known, single-packer-layer PE suitable for OEP / devirt work.

---

## 0. Source-of-truth sample

| Field | Value |
|---|---|
| Original source | `test_target.c` — single-TU C, kernel32-only, no CRT I/O, integer-only. Functions: `decode_string` (XOR), `fnv1a_64` (rolling hash), `decide` (3-way branch), `run_state_machine` (4-state FSM). See `themida-sample/README.md`. |
| Pre-protection hash | `2e1f5a921bae7483d21221adaf770fa7e71ea6fe700cd73e1eda6976dfe84f29` (SHA-256, 298,390 bytes) |
| Post-protection hash | `8e3796d03ddcdc8d664444e9a3f3bc1dfef419ded5418b6cc3a03cca3c91d5eaf` (SHA-256, 1,651,622 bytes / 1,612.91 KB). MD5: `ab233038e853d01827c01c5274d2f8b3` (Themida-reported) |
| Deposited path | `samples/test_target_protected.exe` (gitignored; lives only on disk) |
| Tool | Themida demo (free evaluation build), `Themida64.exe` from `ThemidaDemo32_64.zip` |

> Fill the two hash fields once you've produced the files. The
> pre-protection hash is the only way to confirm the unpacker
> recovered the original byte image — keep it.

---

## 1. Demo-version constraints (confirmed at protect-time)

When **Protect** was clicked, Themida displayed a warning dialog
listing the exact demo restrictions applied to this build. These
are **authoritative** — they come from the tool itself, not from
Oreans docs or third-party claims:

> This application will be protected with some DEMO restrictions:
>
> - Virtualization Macros convert to Falcon Tiny VM
> - String Encryption not available
> - DEMO splash screen inserted in protected file
> - Some internal protections are disabled

### What each restriction means for this sample

| Restriction | Effect on our sample | midas impact |
|---|---|---|
| **VM macros → Falcon Tiny VM** | Any inline SecureEngine VM macros are downgraded to the Falcon Tiny VM architecture. **Our source has 0 macros**, so this only affects the boot-loader VM — Themida's own internal VM code will use Falcon Tiny. | The devirt pipeline will see the **Falcon** VM architecture. `vm/detector.rs` must recognize Falcon's dispatch pattern. Falcon is a real VM, not a stub — it still needs full devirt. |
| **String Encryption not available** | The STR_ENCRYPT macro and the "Encrypt ASCII/Unicode on VM macros" toggles are non-functional in demo. | No string-encryption layer to reverse. Our source had no macros anyway, so no change. |
| **DEMO splash screen inserted** | A splash image runs before the protected app takes control. | midas trace will include splash execution in the pre-OEP region. OEP is **after** splash + boot loader. Don't misread splash code as boot-loader VM. |
| **Some internal protections disabled** | Unspecified subset of internal (non-UI) protections are off. Oreans does not document which. | We cannot know what's missing. Treat the sample as having **at least** the UI-selected protections, and **possibly fewer** internal ones. Do not assert the sample has a specific internal protection unless confirmed in trace. |

### Prior Oreans-docs notes (context only)

The Oreans help docs mention additional demo constraints that are
consistent with the above:
- No registration/unlock path — splash stays regardless.
- Windows services fail because splash can't display (our target
  is not a service — no impact).
- License tiers: Developer 249 EUR, Company 499 EUR.

### Critical correction vs. earlier assumptions

The Oreans *documentation* says "all protection options are
enabled by default." **This is not true for the demo build.**
The demo ships with a lighter default set:
- Encrypt Strings: all OFF
- Entry Point Virtualization: OFF
- Anti-Sandbox: OFF
- Anti-File Patching: OFF (we confirmed this in the UI)

The demo *does* enable: Anti-debug, Compress & Encrypt (all 3),
Detect file/registry monitors, Allow execution under VM/VPC.

**Any future statement about "Themida defaults" must specify
whether it refers to the paid build or the demo.** This doc now
does.

---

## 2. Pre-flight — record the unprotected sample

Before opening Themida:

1. Place the unprotected EXE somewhere outside `samples/` (e.g. a
   scratch dir). We will deposit only the *protected* output in
   `samples/`.
2. Compute and record its SHA-256:
   ```powershell
   Get-FileHash <path>\hello.exe -Algorithm SHA256
   ```
   Paste the value into section 0 ("pre-protection hash").
3. Note the file size — Themida will inflate it; the delta is the
   protection code + VM.

---

## 3. Launch Themida and load the file

1. Open the Themida demo GUI.
2. **Application Information** panel:
   - **Input Filename:** the unprotected EXE from step 2.
   - **Output Filename:** `<scratch>\hello_themida.exe` (not in
     `samples/` yet — we verify before depositing).
   - Leave **Application** blank; it is project bookkeeping only.
3. After loading, the **File Size** and **File Information**
   windows show: file size, file type, detected compiler, and the
   number of SecureEngine® macros detected (should be **0** — our
   test target has no inline macros).

Path variables are supported (`%THEMIDA_FOLDER%`,
`%CURRENT_FOLDER%`, `%<env>%`) but not needed for a local run.

---

## 4. Protection Options — actual demo UI state (confirmed)

The **Protection Options** panel in the demo does **not** ship
with "all options enabled by default" (the Oreans docs describe
the paid build). The actual demo defaults we observed:

| Option | State | Decision |
|---|---|---|
| Anti-debug | **ON** | ✅ keep — exercises anti-debug path in unpacker |
| Compress & Encrypt: Application | **ON** | ✅ keep |
| Compress & Encrypt: Resources | **ON** | ✅ keep |
| Compress & Encrypt: SecureEngine | **ON** | ✅ keep |
| Encrypt Strings: ASCII on VM macros | OFF | ✅ leave — no VM macros in target, no effect; also demo disables STR_ENCRYPT entirely |
| Encrypt Strings: Unicode on VM macros | OFF | ✅ leave — same |
| Encrypt Strings: Re-encrypt after decryption | OFF | ✅ leave — same |
| Detect file/registry monitors | **ON** | ✅ keep |
| Allow execution under VMware/Virtual PC | **ON** | ✅ keep — midas uses Unicorn emulation; this prevents VM-detection refusals |
| Entry Point Virtualization | OFF | ✅ leave — baseline. (This is the option the Oreans docs call "Entry Point Obfuscation"; first thing to enable in a harder re-protect variant if baseline succeeds.) |
| Anti-File Patching | OFF | ✅ keep — avoids `MSG_ID_FILE_CORRUPTED` trips on post-protection modification |
| Anti-Sandbox | OFF | ✅ leave — baseline; demo defaults it off |

> **No changes were made from the demo defaults.** The panel was
> left exactly as Themida presented it. This is the baseline build.

---

## 5. Protection Macros panel

Our test target has **no inline SecureEngine macros** and we are
not importing a MAP file. Confirm the macro count is 0 and move
on. (If a MAP file were present, this is where we'd assign per-
function VM architectures; not applicable here.)

---

## 6. Virtual Machine panel — Falcon Tiny (demo-enforced)

The boot loader is virtualized by Themida's internal VM. In the
**paid** build, you can select among multiple architectures
(TIGER, LION, FISH, EAGLE, DOLPHIN, etc.) and set instances.

In the **demo**, the protect-time warning confirmed:
> **Virtualization Macros convert to Falcon Tiny VM**

This means the boot-loader VM in our sample uses the **Falcon
Tiny** architecture (`falcon64_tiny.vm` in `custom_vms/public/`).
"Tiny" variants are smaller/faster but still real VMs with their
own opcode tables, handlers, and register layouts.

Notes for analysis:
- The devirt pipeline must be **sample-agnostic** (axiom 1 in
  `docs/WORKFLOW.md`): per-instance constants are not portable.
- Falcon Tiny's dispatch pattern must be recognized by
  `src/devirt/vm/detector.rs` — do not hardcode Falcon-specific
  offsets; detect the pattern.
- If we later protect a variant with the paid build, the VM
  architecture may differ (e.g. TIGER), and the detector must
  still work without code changes.

We do not add custom VM macros to the target. The boot-loader VM
is the only VM region the demo will inject.

---

## 7. Customized Dialogs / XBundler / Plugins

- **Customized Dialogs:** leave default messages. (If we later want
  to identify a specific dialog ID in a trace, `MSG_ID_FILE_CORRUPTED`
  is the one tied to Anti-File Patching — which we disabled.)
- **XBundler:** do not embed any files. The test target is a single
  EXE; bundling would add noise.
- **Plugins:** none. No custom DLLs.

---

## 8. Extra Options / Advanced Options

- **Extra Options:**
  - Splash screen: **leave demo default** — the demo forces a
    splash regardless; we cannot remove it. Note its presence for
    trace analysis (the splash runs *before* the protection boot
    loader hands control to our code).
  - Favor size over protection: **Off** (default). Keep full
    protection; size is not a concern for a test sample.
  - Optimize for Windows on ARM: **Off** (default). We target x64.
- **Advanced Options:** leave untouched. These are hidden
  compatibility toggles only needed if the protected app
  misbehaves with defaults.

---

## 9. Build the protected file

1. Go to the final **Protect** tab. It lists every step that will
   be applied.
2. Click **Protect** (a.k.a. **Process**).
3. Themida writes the output to the **Output Filename** from
   step 3.
4. Verify the output exists and is larger than the input (file
   growth = protection code + VM; expected).
5. Compute the post-protection SHA-256 and paste it into section 0:
   ```powershell
   Get-FileHash <scratch>\hello_themida.exe -Algorithm SHA256
   ```
6. Copy the protected EXE into the repo:
   ```powershell
   Copy-Item <scratch>\hello_themida.exe samples\
   ```
   Use a descriptive name, e.g. `samples/hello_themida_demo.exe`.
7. Update section 0's "deposited path" with the actual filename.

### Command-line alternative (optional, for reproducibility)

Once the project file (`.tmd`) is saved from the GUI, future
re-protection can be scripted:

```cmd
Themida /protect hello.tmd /inputfile hello.exe /outputfile hello_themida.exe
```

Caveats:
- Themida reads an internal MySQL database, so **only one
  instance can protect at a time** (no parallel builds).
- To avoid the DB lock, export the project as a text/INI file via
  the Project Manager **Export** button and pass that instead.
- Add `/shareconsole` if invoking from Visual Studio build steps
  so output is logged correctly.

We do not need the CLI for the first sample; the GUI path is fine.

---

## 10. Post-protection checklist (run before midas)

- [x] Pre-protection SHA-256 recorded in section 0.
- [x] Post-protection SHA-256 recorded in section 0.
- [x] Protected EXE deposited in `samples/test_target_protected.exe`.
- [x] File size increased vs. original (298,390 → 1,651,622 bytes, ~5.5×).
- [x] Protected EXE launches standalone on Windows: demo splash
      appears, then the program prints output identical to the
      unprotected binary (byte-for-byte match against
      `expected_output.txt`).
- [x] Demo splash screen noted — present in pre-OEP region of any
      future midas trace.

---

## 11. What this means for midas

This section ties the protection choices back to what the unpacker
and devirt pipeline will see, so future-you doesn't have to
re-derive it.

| Protection feature present in sample | Where midas must handle it |
|---|---|
| Compression of app/resources/SecureEngine | `src/unpacker.rs` — emulation runs the decompression stub to OEP. |
| Anti-Debugger | `src/unpacker.rs` — Unicorn is not a kernel/software debugger, so checks should pass; if they don't, stub the relevant APIs in `src/win64/api/`. |
| Advanced API-Wrapping (if demo includes it) | `src/themida/iat.rs` — wrapped IAT recovery at OEP dump time. ⚠️ Not confirmed in demo UI — verify in trace whether IAT wrapping was actually applied. |
| Boot-loader VM (Falcon Tiny) | `src/devirt/vm/detector.rs` — pattern-based detection; must recognize Falcon Tiny dispatch. Constants must come from runtime auto-detection (axiom 1). |
| Demo splash screen | Runs before our code; midas should pass through it. Confirm the trace's pre-OEP region includes it and that OEP is *after* the splash + boot loader. |
| Detect file/registry monitors | Check code present; midas stubs file/registry APIs. If the check calls a stub we don't implement, add it to `src/win64/api/`. |
| Allow execution under VM/VPC | Prevents VM-detection refusal — good for Unicorn emulation. No specific code to write. |

**Not present in sample (do not expect to reverse these):**

| Feature | Why absent |
|---|---|
| Entry Point Virtualization | Left OFF (demo default). If baseline succeeds, re-protect a variant with this ON for a harder test. |
| Anti-File Patching | OFF. No `MSG_ID_FILE_CORRUPTED` dialog expected. |
| Anti-Sandbox | OFF. No sandbox-detection code expected. |
| String Encryption (STR_ENCRYPT) | Demo disables entirely + no macros in source. No string-encryption layer. |
| Inline VM/MUTATE macros | Source has 0 SecureEngine macros. Only boot-loader VM. |
| "Some internal protections" | Demo warning says some are disabled. Unknown which — do not assume any specific internal protection is present unless confirmed in trace. |

## 13. Protection log (verbatim, captured at protect-time)

Themida version: **3.2.4.34** (x64)

```
Input File:  test_target.exe
Output File: test_target_protected.exe

Examining Imported APIs . . . OK (94 references to wrap)

Virtual Machines Generation:
  Machine #1 (FALCON64 (Tiny) VM)    — size 166 KB
  Machine #2 (Internal (Falcon demo) VM) — size 166 KB

Compressing Application/Resources:
  Original:   259 KB
  Compressed:  94 KB  (ratio 36%)

Compressing SecureEngine:
  Original:   2800 KB
  Compressed: 1479 KB (ratio 52%)

Report:
  Input File Size:      291.4 kb
  Output File Size:     1,612.91 kb
  Increase in Size:     1,321.52 kb
  MD5 Hash:             ab233038e853d01827c01c5274d2f8b3
  Elapsed Time:         6 seconds (14 cores)
  *** File successfully protected ***
  [Demo Restrictions applied]
```

### Key facts extracted from the log

| Fact | Value | midas relevance |
|---|---|---|
| Themida version | 3.2.4.34 | Pin this for reproducibility — different versions may emit different VM layouts. |
| VM #1 architecture | FALCON64 (Tiny) | The primary VM protecting the boot loader. Detector must recognize Falcon Tiny dispatch. |
| VM #2 architecture | Internal (Falcon demo) | A second internal VM, also Falcon-based. Two distinct VM instances in one binary — the detector must not assume a single VM. |
| VM sizes | 166 KB each | Real VMs, not stubs. Non-trivial to devirt. |
| API references wrapped | 94 | API wrapping IS applied (this was unconfirmed from UI). `src/themida/iat.rs` must recover 94 wrapped references. |
| TLS processed | yes | The unpacker must handle TLS callbacks if Themida injected them. |
| Strings virtualized | none | No string-encryption layer (confirmed). |
| Compression ratio (app) | 36% | App code is compressed — unpacker must decompress to OEP. |
| Compression ratio (SecureEngine) | 52% | The protection engine itself is compressed. |
| Output size | 1,612.91 KB (1,651,622 bytes) | ~5.5× the input. Expected for Themida. |
| Two VM instances, both Falcon | — | `vm/detector.rs` must handle **multiple** VM contexts. DEVIRT.md already notes "3 unique VM contexts" on prior samples — this aligns. |

### What "Machine #2 (Internal (Falcon demo) VM)" means

Themida generated **two** VMs:
1. **FALCON64 (Tiny)** — the user-facing VM architecture (from
   `custom_vms/public/falcon64_tiny.vm`).
2. **Internal (Falcon demo)** — Themida's own internal protection
   engine VM, also Falcon-based in the demo (paid builds can use a
   different architecture for this).

Both are real VMs. The devirt pipeline must treat them as
independent contexts — do not assume a single VM or a single
opcode table.

---

## 14. What the demo did **not** do

Explicit list of protections/features **not** applied to this
sample, so we don't mistakenly attribute them to it:

- No inline SecureEngine macros (VM, MUTATE, STR_ENCRYPT, etc.) —
  the source has none. Only the boot-loader VM is present.
- No MAP-file-driven per-function VM assignment.
- No XBundler embedding of DLLs/data.
- No custom plugin DLLs.
- No custom dialog text edits.
- No Entry Point Virtualization (left OFF).
- No Anti-File Patching (OFF).
- No Anti-Sandbox (OFF).
- No String Encryption (demo disables entirely; source had no
  macros anyway).
- No "Favor size over protection" compression variant.
- No Windows-on-ARM optimization.
- No Advanced Options compatibility overrides.
- No paid/license unlock — the demo splash screen remains.
- **"Some internal protections are disabled"** (demo warning) —
  unspecified subset of internal protections absent. Unknown
  which; do not assert any specific internal protection is present.

This means the sample is a **single-layer Themida demo build** with
the demo-default protection options (see section 4 table). The VM
is Falcon Tiny (demo-enforced). Any behavior beyond the listed
features in the unpacked output is either original program code or
a Themida artifact we have not yet characterized — log it, don't
assume it.
