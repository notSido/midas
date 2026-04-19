//! VM analysis passes over a recorded execution trace.
//!
//! These passes run *offline* on the JSONL trace produced by the
//! `TraceBuilder` (see `devirt::trace`). They don't touch the emulator,
//! which means they are cheap to iterate on and easy to unit-test with
//! synthetic traces.

pub mod detector;
pub mod handlers;
pub mod regions;

pub use detector::{detect_vm, RbpOffset, VmDescriptor};
pub use handlers::{Handler, HandlerCatalog};
pub use regions::{DispatcherCandidate, TraceAnalysis};
