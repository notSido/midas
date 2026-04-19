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
    /// Marker emitted once when the trace arms (OEP reached).
    OepReached {
        tick: u64,
        rip: u64,
    },

    /// A single instruction executed by the guest.
    Exec {
        tick: u64,
        rip: u64,
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,
    },
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
