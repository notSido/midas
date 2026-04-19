//! Per-instruction trace recorder, armed at OEP.
//!
//! `TraceBuilder` sits behind an `Arc<Mutex<_>>` shared with the Unicorn
//! code hook in `unpacker.rs`. It is **disarmed by default** so the
//! unpack-phase instruction storm (millions of decompression-loop steps)
//! doesn't bloat the trace. Arm it at breakout/OEP.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::{Result, UnpackError};

use super::trace_events::{Event, MemSnapshot, RegSnapshot};

pub struct TraceBuilder {
    writer: BufWriter<File>,
    path: PathBuf,
    tick: u64,
    armed: bool,
    limit: u64,
    /// RIPs at which a one-shot register snapshot should be emitted
    /// the first time each RIP is executed post-OEP. Entries are
    /// removed on capture so repeated firings don't spam the trace.
    capture_regs_at: HashSet<u64>,
    /// Tracks which indirect `jmp r<reg>` RIPs have already had a
    /// one-shot register snapshot emitted — used by the automatic-
    /// capture path so every unique dispatcher candidate produces
    /// exactly one `RegsAtRip` event without user-supplied config.
    auto_captured_indirect_jmps: HashSet<u64>,
}

impl TraceBuilder {
    /// Open `path` for JSONL writing. The file is created (truncated) now
    /// but nothing is emitted until `arm()` is called. `limit` is a hard
    /// cap on the number of post-OEP instructions recorded — once hit,
    /// `record_exec` returns `Ok(false)` and the caller should stop
    /// emulation.
    pub fn new<P: AsRef<Path>>(path: P, limit: u64) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::create(&path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            path,
            tick: 0,
            armed: false,
            limit,
            capture_regs_at: HashSet::new(),
            auto_captured_indirect_jmps: HashSet::new(),
        })
    }

    /// Return true if this is the first time we've seen an
    /// auto-capture-worthy instruction at `rip` and the recorder is
    /// armed. Two patterns qualify:
    ///
    /// - Indirect `jmp r<reg>` — dispatcher-exit shape; the
    ///   captured state has the decrypted-opcode handler address in
    ///   the target register.
    /// - `movzx r, word ptr [mem]` — VM opcode-fetch shape; the
    ///   captured state has the VM_PC pointer in the source base
    ///   register, i.e. everything the evaluator needs to run the
    ///   dispatcher forward.
    ///
    /// Pattern checks are inline byte-match — no iced-x86 decode in
    /// the hot path.
    pub fn should_auto_capture_indirect_jmp(&self, rip: u64, bytes: &[u8]) -> bool {
        if !self.armed {
            return false;
        }
        if !(is_indirect_reg_jmp_bytes(bytes) || is_movzx_word_ptr_mem_bytes(bytes)) {
            return false;
        }
        !self.auto_captured_indirect_jmps.contains(&rip)
    }

    /// Variant of `record_regs_at_rip` used by the automatic path —
    /// marks the RIP as captured so the same dispatcher doesn't emit
    /// a second event on its next firing.
    pub fn record_auto_captured_regs(
        &mut self,
        rip: u64,
        regs: RegSnapshot,
        mem: Option<MemSnapshot>,
    ) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.auto_captured_indirect_jmps.insert(rip);
        let event = Event::RegsAtRip {
            tick: self.tick,
            rip,
            regs,
            mem,
        };
        self.write_event(&event)?;
        Ok(())
    }

    /// Register a RIP at which a one-shot register snapshot should
    /// be emitted the first time that RIP fires post-OEP. Multiple
    /// RIPs may be registered; each fires once.
    pub fn add_capture_rip(&mut self, rip: u64) {
        self.capture_regs_at.insert(rip);
    }

    /// Called from the hook on every post-arm instruction. Returns
    /// true if this RIP is registered for a one-shot capture and
    /// hasn't yet fired — the caller should snapshot registers and
    /// pass them to `record_regs_at_rip`.
    pub fn should_capture_regs(&self, rip: u64) -> bool {
        self.armed && self.capture_regs_at.contains(&rip)
    }

    /// Record a RegsAtRip event with optional memory snapshot.
    /// Removes the RIP from the pending set so subsequent firings
    /// don't re-emit.
    pub fn record_regs_at_rip(
        &mut self,
        rip: u64,
        regs: RegSnapshot,
        mem: Option<MemSnapshot>,
    ) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.capture_regs_at.remove(&rip);
        let event = Event::RegsAtRip {
            tick: self.tick,
            rip,
            regs,
            mem,
        };
        self.write_event(&event)?;
        Ok(())
    }

    /// Switch recording on and emit a synthetic `OepReached` marker so
    /// downstream tools know where in the original stream we armed.
    /// Accepts an optional GPR snapshot — callers with access to the
    /// live emulator should pass one; tests/standalone callers can pass
    /// `None`.
    pub fn arm(&mut self, rip: u64, regs: Option<RegSnapshot>) -> Result<()> {
        if self.armed {
            return Ok(());
        }
        log::info!(
            "Devirt trace armed at RIP 0x{:x} (limit {} events, path {:?}, regs={})",
            rip,
            self.limit,
            self.path,
            if regs.is_some() { "yes" } else { "no" },
        );
        self.armed = true;
        let marker = Event::OepReached {
            tick: 0,
            rip,
            regs,
        };
        self.write_event(&marker)?;
        Ok(())
    }

    pub fn is_armed(&self) -> bool {
        self.armed
    }

    pub fn tick(&self) -> u64 {
        self.tick
    }

    /// Record a single executed instruction. Returns `Ok(true)` while the
    /// recorder is still accepting events, `Ok(false)` when the limit has
    /// been reached (caller should `emu_stop`). Disarmed recorders silently
    /// accept and return `Ok(true)` so the hook path stays branch-light.
    pub fn record_exec(&mut self, rip: u64, bytes: &[u8]) -> Result<bool> {
        if !self.armed {
            return Ok(true);
        }
        if self.tick >= self.limit {
            return Ok(false);
        }
        let event = Event::Exec {
            tick: self.tick,
            rip,
            bytes: bytes.to_vec(),
        };
        self.write_event(&event)?;
        self.tick += 1;
        Ok(true)
    }

    /// Flush buffered output to disk. Callable through a lock — useful
    /// because the Unicorn hook closure keeps a strong `Arc` reference
    /// alive for the whole engine lifetime, so we can't consume `self`
    /// with `finish()` from `run_emulation`.
    pub fn flush(&mut self) -> Result<u64> {
        self.writer.flush()?;
        log::info!(
            "Devirt trace flushed: {} exec events written to {:?}",
            self.tick,
            self.path
        );
        Ok(self.tick)
    }

    /// Flush and consume. Used by tests / standalone callers that own
    /// the builder outright.
    pub fn finish(mut self) -> Result<u64> {
        self.writer.flush()?;
        log::info!(
            "Devirt trace closed: {} exec events written to {:?}",
            self.tick,
            self.path
        );
        Ok(self.tick)
    }
}

/// Recognise the x86-64 `jmp r<reg>` register-indirect form from raw
/// bytes. Two encodings:
/// - `FF E0..FF E7` — RAX..RDI (2 bytes, no REX).
/// - `41 FF E0..41 FF E7` — R8..R15 (3 bytes, REX.B set).
/// Excludes indirect-through-memory (`jmp [mem]`) which uses different
/// ModR/M mode bits.
fn is_indirect_reg_jmp_bytes(bytes: &[u8]) -> bool {
    match bytes {
        [0xFF, m, ..] if (*m & 0xF8) == 0xE0 => true,
        [0x41, 0xFF, m, ..] if (*m & 0xF8) == 0xE0 => true,
        _ => false,
    }
}

/// Recognise `movzx r, word ptr [mem]` from raw bytes. Encoding is
/// (optional REX 0x40..0x4F) + `0F B7` + ModR/M with mem-mode (mod
/// bits != 11). Excludes register-source `movzx` since that's not a
/// memory fetch. Accepts any register-size destination (16/32/64
/// after zero-extend) — the VM dispatcher uses 64-bit dsts, but
/// Themida mutation can make it any width.
fn is_movzx_word_ptr_mem_bytes(bytes: &[u8]) -> bool {
    let (op_idx, rex_ok) = match bytes.first() {
        Some(b) if (0x40..=0x4F).contains(b) => (1, true),
        Some(_) => (0, true),
        None => (0, false),
    };
    if !rex_ok || bytes.len() < op_idx + 3 {
        return false;
    }
    if bytes[op_idx] != 0x0F || bytes[op_idx + 1] != 0xB7 {
        return false;
    }
    // ModR/M top two bits != 11 → memory addressing.
    let mod_bits = bytes[op_idx + 2] >> 6;
    mod_bits != 0b11
}

impl TraceBuilder {
    fn write_event(&mut self, event: &Event) -> Result<()> {
        serde_json::to_writer(&mut self.writer, event)
            .map_err(|e| UnpackError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        writeln!(&mut self.writer)?;
        Ok(())
    }
}
