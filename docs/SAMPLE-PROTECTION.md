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
| Original source | trivial C program (`hello.exe`-class), Win64 |
| Pre-protection hash | _record SHA-256 of the unprotected EXE here before protecting_ |
| Post-protection hash | _record SHA-256 of `samples/<protected>.exe` after step 9_ |
| Deposited path | `samples/` (gitignored; lives only on disk) |
| Tool | Themida demo (free evaluation build) |

> Fill the two hash fields once you've produced the files. The
> pre-protection hash is the only way to confirm the unpacker
> recovered the original byte image — keep it.

---

## 1. Demo-version constraints (what the demo does and doesn't do)

Documented restrictions of the free DEMO build, per Oreans help:

- **Mandatory splash screen.** The demo inserts a splash image that
  runs **before** the protected app takes control. This is the most
  visible artifact and must not be confused with the protection boot
  loader's own behavior.
- **No Windows-service support.** The demo splash screen cannot
  display for a service, so a protected service will fail to start.
  Our test target is **not** a service — no impact.
- **No registration path.** The demo cannot be unlocked to the full
  product; the splash screen stays regardless. Treat any "fully
  functional protection" claims from third parties as unverified.
- **Protection techniques are exposed.** Anti-debug, encryption,
  obfuscation, and VM macros are available in the demo UI. Oreans
  does not officially state that demo protection strength equals
  the paid build — assume the *techniques* are present but do not
  assert strength parity in analysis notes.
- **License tiers (for context only):** Developer 249 EUR,
  Company 499 EUR. We are on demo; this is irrelevant to the
  sample but worth noting so nobody thinks we shipped a paid build.

What the demo **does not** add (per Oreans docs, not asserted
beyond what's documented):
- No licensing/registration unlock.
- No removal of the splash screen.

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

## 4. Protection Options — the toggles we set

The **Protection Options** panel has every option enabled by
default. For the test target we deliberately **keep defaults**
except where noted, so the sample exercises the features the
unpacker/devirt pipeline must handle.

| Option | Set to | Why |
|---|---|---|
| Anti-Debugger | **On** (default) | Unpacker must defeat anti-debug; keep it as a stress test. |
| Advanced API-Wrapping | **On** (default) | Wraps IAT — exercises `src/themida/iat.rs`. |
| Compress application / resources / boot loader | **On** (default) | Small startup penalty; standard for real samples. |
| Encrypt ASCII/Unicode on VM macros | **On** (default) | No VM macros in our target, but the flag is harmless. |
| Re-Encrypt after decryption | **On** (default) | Standard. |
| Detect File/Registry Monitors | **On** (default) | Keep; our unpacker stubs registry/file APIs anyway. |
| Entry Point Obfuscation | **On** (default) | Treats the first instructions as a VM macro. If the protected EXE fails to start under midas, **disable this first** — it is the documented incompatibility suspect. |
| Anti-File Patching | **Off** | We may re-sign/re-compress the output for testing; this flag would trip `MSG_ID_FILE_CORRUPTED`. Disable to avoid false positives. |
| Anti-Sandbox | **On** (default) | Keep; midas is not a sandbox so it shouldn't fire, but the check code is present in the binary. |
| Perform Protection checks on VM macros | **On** (default) | No VM macros in target; no effect. |

> **Decision rationale:** we deviate from defaults only on
> **Anti-File Patching** (off) to avoid post-protection tamper
> trips, and we flag **Entry Point Obfuscation** as the first knob
> to turn if the sample misbehaves. Everything else stays default
> so the sample is representative of a real-world Themida build.

---

## 5. Protection Macros panel

Our test target has **no inline SecureEngine macros** and we are
not importing a MAP file. Confirm the macro count is 0 and move
on. (If a MAP file were present, this is where we'd assign per-
function VM architectures; not applicable here.)

---

## 6. Virtual Machine panel

The boot loader is virtualized by Themida's internal VM. We leave
the default VM selection. Notes for later analysis:

- Themida generates multiple independent VM architectures (e.g.
  TIGER, LION, FISH). "Comparing two is like comparing x86 to ARM."
- The **Instances** column controls how many copies of a VM
  architecture are generated — even the same name yields different
  register positions, handlers, and opcode tables each build.
- This is why the devirt pipeline must be **sample-agnostic**
  (axiom 1 in `docs/WORKFLOW.md`): per-instance constants are not
  portable.

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

- [ ] Pre-protection SHA-256 recorded in section 0.
- [ ] Post-protection SHA-256 recorded in section 0.
- [ ] Protected EXE deposited in `samples/`.
- [ ] File size increased vs. original (sanity check).
- [ ] Protected EXE launches standalone on Windows (the demo
      splash appears, then the app). If it does **not** start,
      re-protect with **Entry Point Obfuscation** off (step 4).
- [ ] Note the demo splash screen is present — do not misread it
      as part of the protection boot loader in traces.

---

## 11. What this means for midas

This section ties the protection choices back to what the unpacker
and devirt pipeline will see, so future-you doesn't have to
re-derive it.

| Protection feature we enabled | Where midas must handle it |
|---|---|
| Compression of app/resources/boot loader | `src/unpacker.rs` — emulation runs the decompression stub to OEP. |
| Anti-Debugger | `src/unpacker.rs` — Unicorn is not a kernel/software debugger, so checks should pass; if they don't, stub the relevant APIs in `src/win64/api/`. |
| Advanced API-Wrapping | `src/themida/iat.rs` — wrapped IAT recovery at OEP dump time. |
| Entry Point Obfuscation | If enabled, the very first instructions are VM-virtualized; OEP detection must not assume a plain jump at the entry point. **First thing to disable if OEP recovery fails.** |
| Boot-loader VM | `src/devirt/vm/detector.rs` — pattern-based detection; constants must come from runtime auto-detection (axiom 1). |
| Demo splash screen | Runs before our code; midas should pass through it. Confirm the trace's pre-OEP region includes it and that OEP is *after* the splash + boot loader. |
| Anti-File Patching (OFF) | We disabled this, so no `MSG_ID_FILE_CORRUPTED` dialog in the binary. If a future sample needs it on, expect that dialog ID in the trace. |

---

## 12. What the demo did **not** do

Explicit list of protections/features **not** applied, so we don't
mistakenly attribute them to the sample:

- No inline SecureEngine macros (VM, MUTATE, STR_ENCRYPT, etc.) —
  the source has none. Only the boot-loader VM is present.
- No MAP-file-driven per-function VM assignment.
- No XBundler embedding of DLLs/data.
- No custom plugin DLLs.
- No custom dialog text edits.
- No "Favor size over protection" compression variant.
- No Windows-on-ARM optimization.
- No Advanced Options compatibility overrides.
- No paid/license unlock — the demo splash screen remains.

This means the sample is a **single-layer Themida demo build** with
default protection options (minus Anti-File Patching). Any behavior
beyond that in the unpacked output is either original program code
or a Themida artifact we have not yet characterized — log it, don't
assume it.
