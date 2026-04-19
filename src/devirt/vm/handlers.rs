//! Handler discovery, clustering, and dedup (M2).
//!
//! Given the dispatcher's indirect-branch RIP (found by `regions::M1`),
//! a trace can be segmented into handler invocations: each execution of
//! the dispatcher RIP marks the start of a new invocation, and the RIP
//! sequence between two consecutive dispatcher firings is one handler
//! body (plus the dispatch-prep suffix that leads back into the loop).
//!
//! Two handler invocations are **equivalent** when their RIP sequences
//! are identical — same code path, regardless of register contents.
//! We hash the sequence into a 64-bit signature for O(1) grouping.
//!
//! Limitations (acceptable for M2):
//! - RIP-sequence equality is coarser than semantic equality: two
//!   handlers with the same effect but different scheduling count as
//!   distinct.
//! - The "handler body" includes the dispatch-prep trailer of the
//!   current iteration. That trailer is shared across all handlers, so
//!   different handlers still have distinct signatures (their prefixes
//!   differ), but the fire-count and length figures reported here
//!   include the shared trailer.
//! - Single-dispatcher model: we treat one RIP as the dispatcher. The
//!   M1 findings suggest sometimes multiple indirect-branches sit in
//!   the same dispatcher. A future revision can take a set.

use std::collections::{hash_map::DefaultHasher, HashMap};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::devirt::trace_events::Event;
use crate::{Result, UnpackError};

/// One unique handler, identified by its RIP-sequence signature.
#[derive(Debug, Clone)]
pub struct Handler {
    /// 64-bit hash of the handler's RIP sequence.
    pub signature: u64,
    /// First RIP of the handler body (the indirect-branch target, i.e.
    /// the handler's entry point).
    pub entry_rip: u64,
    /// Number of RIPs in the recorded sequence (handler body length).
    pub length: usize,
    /// How many times this exact handler fired in the trace.
    pub fire_count: u64,
    /// First few RIPs of the sequence — useful for eyeballing.
    pub first_rips: Vec<u64>,
    /// One concrete invocation's full `(rip, bytes)` sequence. Populated
    /// from the first observation of this signature. Used by the IR
    /// lifter to turn a handler into `Vec<Effect>`.
    pub exemplar: Vec<(u64, Vec<u8>)>,
}

/// Result of handler extraction against a given dispatcher address.
pub struct HandlerCatalog {
    pub dispatcher_rip: u64,
    pub total_invocations: u64,
    pub handlers: Vec<Handler>,
}

impl HandlerCatalog {
    pub fn from_trace_file<P: AsRef<Path>>(path: P, dispatcher_rip: u64) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let reader = BufReader::new(file);
        Self::from_jsonl_lines(reader.lines().filter_map(|l| l.ok()), dispatcher_rip)
    }

    /// Extract the handler catalog from an iterator of JSONL event
    /// lines. The first invocation is skipped because we arm the trace
    /// on the first instruction at OEP, not at a dispatcher firing —
    /// the first dispatcher firing gives us an anchor to segment from.
    pub fn from_jsonl_lines<I: IntoIterator<Item = String>>(
        lines: I,
        dispatcher_rip: u64,
    ) -> Result<Self> {
        // `seen_dispatcher`: have we passed the first dispatcher RIP
        // yet? We only record invocations between consecutive firings.
        let mut seen_dispatcher = false;
        // `current`: (rip, bytes) pairs of the in-progress invocation.
        let mut current: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut groups: HashMap<u64, Handler> = HashMap::new();
        let mut total_invocations: u64 = 0;

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line).map_err(|e| {
                UnpackError::DumpError(format!("bad trace line: {}", e))
            })?;
            match event {
                Event::OepReached { .. } | Event::RegsAtRip { .. } => {
                    // markers / register snapshots — ignore for segmentation
                }
                Event::Exec { rip, bytes, .. } => {
                    if rip == dispatcher_rip {
                        if seen_dispatcher && !current.is_empty() {
                            finalize_invocation(&current, &mut groups);
                            total_invocations += 1;
                        }
                        seen_dispatcher = true;
                        current.clear();
                    } else if seen_dispatcher {
                        current.push((rip, bytes));
                    }
                }
            }
        }
        // Trailing invocation (if the trace ends mid-handler) is
        // deliberately discarded — it would be shorter than the real
        // body and skew the catalog.

        let mut handlers: Vec<Handler> = groups.into_values().collect();
        handlers.sort_by(|a, b| b.fire_count.cmp(&a.fire_count));

        Ok(Self {
            dispatcher_rip,
            total_invocations,
            handlers,
        })
    }

    /// Distinct handler count.
    pub fn unique_count(&self) -> usize {
        self.handlers.len()
    }
}

fn signature_of(pairs: &[(u64, Vec<u8>)]) -> u64 {
    let mut h = DefaultHasher::new();
    for (rip, _) in pairs {
        rip.hash(&mut h);
    }
    h.finish()
}

fn finalize_invocation(pairs: &[(u64, Vec<u8>)], groups: &mut HashMap<u64, Handler>) {
    let sig = signature_of(pairs);
    let entry = groups.entry(sig).or_insert_with(|| {
        let preview: Vec<u64> = pairs.iter().take(8).map(|(r, _)| *r).collect();
        Handler {
            signature: sig,
            entry_rip: pairs[0].0,
            length: pairs.len(),
            fire_count: 0,
            first_rips: preview,
            exemplar: pairs.to_vec(),
        }
    });
    entry.fire_count += 1;
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
    fn groups_identical_rip_sequences() {
        // Synthetic: two handler patterns (A and B), A fires 3x, B 2x.
        // Dispatcher RIP is 0x1000.
        let disp = 0x1000u64;
        let handler_a = [0x2000u64, 0x2003, 0x2007];
        let handler_b = [0x3000u64, 0x3004];

        let mut lines = Vec::new();
        let mut t = 0u64;
        lines.push(r#"{"kind":"oep_reached","tick":0,"rip":4096}"#.to_string());
        for seq in [&handler_a[..], &handler_a[..], &handler_b[..], &handler_a[..], &handler_b[..]] {
            lines.push(mk_exec(t, disp));
            t += 1;
            for &r in seq {
                lines.push(mk_exec(t, r));
                t += 1;
            }
        }
        // trailing dispatcher firing to close the last invocation
        lines.push(mk_exec(t, disp));

        let cat = HandlerCatalog::from_jsonl_lines(lines, disp).unwrap();
        assert_eq!(cat.dispatcher_rip, disp);
        assert_eq!(cat.total_invocations, 5);
        assert_eq!(cat.unique_count(), 2);
        // fire_count ordering: A (3) before B (2)
        assert_eq!(cat.handlers[0].fire_count, 3);
        assert_eq!(cat.handlers[0].entry_rip, 0x2000);
        assert_eq!(cat.handlers[0].length, 3);
        assert_eq!(cat.handlers[0].exemplar.len(), 3);
        assert_eq!(cat.handlers[1].fire_count, 2);
        assert_eq!(cat.handlers[1].entry_rip, 0x3000);
        assert_eq!(cat.handlers[1].length, 2);
    }
}
