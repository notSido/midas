//! Typed events emitted by the devirt trace recorder.
//!
//! The trace is an append-only stream of `Event`s, serialized one-per-line
//! as JSON (JSONL). Downstream milestones read this back and feed it into
//! VM region detection, handler discovery, and semantics lifting.
//!
//! Keeping events as a tagged enum (serde `tag = "kind"`) lets us add new
//! variants (memory r/w, reg delta, OEP marker, etc.) without breaking the
//! existing reader.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Marker emitted once when the trace arms (OEP reached). The
    /// optional `regs` field carries a full GPR snapshot at the
    /// exact instant of arming — consumers can use it to resolve
    /// `[rbp + X]`-style VM-state addresses at OEP without a second
    /// emulation pass. `None` on older traces or in tests that don't
    /// care about register state.
    OepReached {
        tick: u64,
        rip: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        regs: Option<RegSnapshot>,
    },

    /// A single instruction executed by the guest.
    Exec {
        tick: u64,
        rip: u64,
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,
    },

    /// Register snapshot captured the first time a specific RIP is
    /// executed post-OEP. Triggered by auto-capture on indirect
    /// `jmp r<reg>` / `movzx r, word ptr [...]` (or by the explicit
    /// `--devirt-capture-regs-at` back-door). Used to recover
    /// register state at known-interesting points (e.g. VM
    /// dispatcher entry) so the offline bytecode walker can resolve
    /// `[rbp + X]`-style VM-state pointers without a second emulator
    /// run.
    ///
    /// The optional `mem` snapshot carries the live memory around
    /// RBP at capture time — needed because the OEP dump has
    /// pre-VM-init memory, but the VM state cells (rolling key,
    /// possibly handler-table pointer) have been rewritten by the
    /// time the dispatcher fires. Having both regs and a memory
    /// window lets an offline evaluator reproduce dispatcher
    /// execution exactly.
    RegsAtRip {
        tick: u64,
        rip: u64,
        regs: RegSnapshot,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mem: Option<MemSnapshot>,
    },
}

/// Slice of live memory captured at a trace event. `base_va` is the
/// virtual address the slice starts at; `bytes` is the raw content.
/// Intended to accompany `RegsAtRip` so downstream tooling has
/// ground-truth memory at the capture tick, not just at OEP-dump
/// time.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct MemSnapshot {
    pub base_va: u64,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
}

/// Full 16-GPR + RIP snapshot. Stored in JSONL as a flat object so
/// a human eyeballing the trace can grep for a specific register.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RegSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oep_event_without_regs_round_trips() {
        // Older traces with no regs field must still parse cleanly.
        let line = r#"{"kind":"oep_reached","tick":0,"rip":5384112206}"#;
        let e: Event = serde_json::from_str(line).unwrap();
        match e {
            Event::OepReached { tick, rip, regs } => {
                assert_eq!(tick, 0);
                assert_eq!(rip, 5384112206);
                assert!(regs.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn oep_event_with_regs_round_trips() {
        let ev = Event::OepReached {
            tick: 0,
            rip: 0x140eb084e,
            regs: Some(RegSnapshot {
                rbp: 0xdead_beef,
                rsp: 0xcafe_f00d,
                ..Default::default()
            }),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Event::OepReached {
            regs: Some(RegSnapshot { rbp: 0xdead_beef, rsp: 0xcafe_f00d, .. }),
            ..
        }));
    }

    #[test]
    fn regs_at_rip_with_mem_round_trips() {
        let ev = Event::RegsAtRip {
            tick: 100,
            rip: 0x141048853,
            regs: RegSnapshot {
                rbp: 0x1412c1a1e,
                ..Default::default()
            },
            mem: Some(MemSnapshot {
                base_va: 0x1412c1a1e,
                bytes: vec![0x11, 0x22, 0x33, 0x44],
            }),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        if let Event::RegsAtRip { mem: Some(m), .. } = back {
            assert_eq!(m.base_va, 0x1412c1a1e);
            assert_eq!(m.bytes, vec![0x11, 0x22, 0x33, 0x44]);
        } else {
            panic!("expected RegsAtRip with mem");
        }
    }

    #[test]
    fn regs_at_rip_without_mem_back_compat() {
        // Old traces (pre-MemSnapshot) had no `mem` field.
        let line = r#"{"kind":"regs_at_rip","tick":0,"rip":100,"regs":{"rax":0,"rbx":0,"rcx":0,"rdx":0,"rsi":0,"rdi":0,"rbp":0,"rsp":0,"r8":0,"r9":0,"r10":0,"r11":0,"r12":0,"r13":0,"r14":0,"r15":0,"rip":0}}"#;
        let ev: Event = serde_json::from_str(line).unwrap();
        if let Event::RegsAtRip { mem, .. } = ev {
            assert!(mem.is_none());
        } else {
            panic!("wrong variant");
        }
    }
}

/// Serialize instruction bytes as a lowercase hex string — both compact on
/// disk and easy to eyeball in JSONL dumps.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            hex.push_str(&format!("{:02x}", b));
        }
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("hex string has odd length"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}
