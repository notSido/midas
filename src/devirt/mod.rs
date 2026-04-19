//! Devirtualization infrastructure.
//!
//! The unpacker reaches OEP, but on Themida-virtualized binaries execution
//! lands on VM-mutated micro-ops (xor / and / cmp+jne dispatched through a
//! central loop) rather than the original program. This module hosts the
//! analysis pipeline that turns that VM execution back into readable code.
//!
//! Incremental milestones (see `/Users/sido/.claude/plans/…` for detail):
//! - **M0** (current): per-instruction trace recorder, armed at OEP.
//! - **M1**: VM dispatcher + handler region detection from the trace.
//! - **M2**: handler discovery, clustering, dedup.
//! - **M3**: IR + iced-x86 → `Expr` lifter.
//! - **M4**: per-handler semantics via simplification.

pub mod trace;
pub mod trace_events;
pub mod vm;

pub use trace::TraceBuilder;
pub use trace_events::Event;
pub use vm::{DispatcherCandidate, Handler, HandlerCatalog, TraceAnalysis};
