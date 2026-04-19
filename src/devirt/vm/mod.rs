//! VM analysis passes over a recorded execution trace.
//!
//! These passes run *offline* on the JSONL trace produced by the
//! `TraceBuilder` (see `devirt::trace`). They don't touch the emulator,
//! which means they are cheap to iterate on and easy to unit-test with
//! synthetic traces.

pub mod detector;
pub mod eval;
pub mod handlers;
pub mod regions;

pub use detector::{
    detect_vm, group_into_contexts, resolve_vm_addresses, RbpOffset, VmContext, VmDescriptor,
};
pub use eval::{
    dispatch_target_register, evaluate_linear, walk_bytecode, EvalOutcome, EvalState, WalkStep,
};
pub use handlers::{Handler, HandlerCatalog};
pub use regions::{DispatcherCandidate, TraceAnalysis};
