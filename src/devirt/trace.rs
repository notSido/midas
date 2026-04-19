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

use super::trace_events::{Event, RegSnapshot};

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
        })
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

    /// Record a RegsAtRip event. Removes the RIP from the pending
    /// set so subsequent firings don't re-emit.
    pub fn record_regs_at_rip(&mut self, rip: u64, regs: RegSnapshot) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.capture_regs_at.remove(&rip);
        let event = Event::RegsAtRip {
            tick: self.tick,
            rip,
            regs,
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

    fn write_event(&mut self, event: &Event) -> Result<()> {
        serde_json::to_writer(&mut self.writer, event)
            .map_err(|e| UnpackError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        writeln!(&mut self.writer)?;
        Ok(())
    }
}
