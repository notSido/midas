//! Dispatcher / handler region detection (M1).
//!
//! A Themida VM runs a tight loop whose tail is an indirect branch to one
//! of N handler routines, which each end by jumping back to the dispatcher
//! loop. In a trace that means: one instruction address has *many*
//! distinct successor addresses. That's our dispatcher signal.
//!
//! For each instruction observed, we track:
//! - how often it executed (`exec_count`)
//! - the set of distinct next-instruction addresses (`successors`)
//!
//! High-fan-out, high-exec-count entries are dispatcher candidates.
//! Successors of the top candidate are candidate handler entry points.
//!
//! This pass is deliberately naive. It treats the trace as a flat sequence;
//! it does not try to disassemble or categorize instructions. That keeps
//! M1 cheap and useful as a sanity check on the trace itself, even before
//! the IR lifter (M3) exists.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::devirt::trace_events::Event;
use crate::{Result, UnpackError};

/// Per-address view of what the trace saw at that RIP.
#[derive(Debug, Default, Clone)]
pub struct AddressStats {
    pub exec_count: u64,
    pub successors: HashSet<u64>,
}

/// Result of scanning a trace file.
pub struct TraceAnalysis {
    pub total_events: u64,
    pub oep_rip: Option<u64>,
    pub per_addr: HashMap<u64, AddressStats>,
}

/// A scored guess at the VM dispatcher's final (indirect-branch) address.
#[derive(Debug, Clone)]
pub struct DispatcherCandidate {
    pub rip: u64,
    pub exec_count: u64,
    pub fan_out: usize,
    /// Sorted list of distinct successor addresses — candidate handler
    /// entry points when this is the real dispatcher tail.
    pub successors: Vec<u64>,
}

impl TraceAnalysis {
    /// Read a JSONL trace file produced by `TraceBuilder` and compute
    /// per-address stats.
    pub fn from_trace_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let reader = BufReader::new(file);
        Self::from_jsonl_lines(reader.lines().filter_map(|l| l.ok()))
    }

    /// Construct from an iterator of JSONL lines. Factored out so tests
    /// can feed synthetic traces without touching the filesystem.
    pub fn from_jsonl_lines<I: IntoIterator<Item = String>>(lines: I) -> Result<Self> {
        let mut total_events: u64 = 0;
        let mut oep_rip: Option<u64> = None;
        let mut per_addr: HashMap<u64, AddressStats> = HashMap::new();
        let mut prev: Option<u64> = None;

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line).map_err(|e| {
                UnpackError::DumpError(format!("bad trace line: {} (line: {:?})", e, line))
            })?;
            match event {
                Event::OepReached { rip, .. } => {
                    oep_rip = Some(rip);
                    prev = None;
                }
                Event::Exec { rip, .. } => {
                    total_events += 1;
                    let entry = per_addr.entry(rip).or_default();
                    entry.exec_count += 1;
                    if let Some(p) = prev {
                        if let Some(pe) = per_addr.get_mut(&p) {
                            pe.successors.insert(rip);
                        }
                    }
                    prev = Some(rip);
                }
            }
        }

        Ok(Self {
            total_events,
            oep_rip,
            per_addr,
        })
    }

    /// Return up to `n` dispatcher candidates, ranked by fan-out then by
    /// exec-count. The top hit is our best guess at the VM dispatcher's
    /// indirect-branch instruction.
    pub fn dispatcher_candidates(&self, n: usize) -> Vec<DispatcherCandidate> {
        let mut out: Vec<DispatcherCandidate> = self
            .per_addr
            .iter()
            .filter(|(_, s)| s.successors.len() >= 2)
            .map(|(rip, s)| {
                let mut succs: Vec<u64> = s.successors.iter().copied().collect();
                succs.sort_unstable();
                DispatcherCandidate {
                    rip: *rip,
                    exec_count: s.exec_count,
                    fan_out: s.successors.len(),
                    successors: succs,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.fan_out
                .cmp(&a.fan_out)
                .then_with(|| b.exec_count.cmp(&a.exec_count))
        });
        out.truncate(n);
        out
    }

    /// Total distinct RIPs seen in the post-OEP trace.
    pub fn unique_rips(&self) -> usize {
        self.per_addr.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_exec(tick: u64, rip: u64) -> String {
        format!(
            r#"{{"kind":"exec","tick":{},"rip":{},"bytes":"90"}}"#,
            tick, rip
        )
    }

    #[test]
    fn dispatcher_emerges_from_synthetic_trace() {
        // Synthetic: addr 0x1000 dispatches to 3 handlers, each returns
        // through addr 0x2000 back to 0x1000. 0x1000 should have fan-out
        // 3; 0x2000 should have fan-out 1.
        let mut lines: Vec<String> = vec![
            r#"{"kind":"oep_reached","tick":0,"rip":4096}"#.to_string(),
        ];
        let mut t = 0u64;
        // Each iteration: dispatcher (0x1000) -> handler -> handler tail
        // -> return trampoline (0x2000). The next iteration's leading
        // 0x1000 provides the return edge 0x2000 -> 0x1000.
        for handler in [0x1100u64, 0x1200u64, 0x1300u64] {
            for rip in [0x1000u64, handler, handler + 3, 0x2000] {
                lines.push(mk_exec(t, rip));
                t += 1;
            }
        }
        let a = TraceAnalysis::from_jsonl_lines(lines).unwrap();
        assert_eq!(a.oep_rip, Some(4096));
        let cands = a.dispatcher_candidates(5);
        assert_eq!(cands[0].rip, 0x1000, "top candidate should be dispatcher");
        assert_eq!(cands[0].fan_out, 3);
        // Handlers are the distinct successors of 0x1000.
        let succ: HashSet<u64> = cands[0].successors.iter().copied().collect();
        assert!(succ.contains(&0x1100));
        assert!(succ.contains(&0x1200));
        assert!(succ.contains(&0x1300));
    }
}
