//! IR and lifter for devirtualization analysis (M3).
//!
//! The devirt IR is a small, opinionated, pure-Rust expression tree
//! representing the semantic effect of a straight-line block of x86-64
//! instructions. It is lifted from `iced_x86::Instruction`s, intended
//! to be simplified by the algebraic passes in M4/M6, and emitted by
//! M7.
//!
//! Design notes:
//!
//! - **Minimal surface, maximal extensibility.** `Expr` covers the
//!   operators Themida VM handlers actually use. Anything unsupported
//!   produces `LiftError::Unsupported` — we never lie about what the
//!   lifter covered. Extend by adding variants, not flags.
//! - **64-bit-only first cut.** Narrower writes (e.g. `mov al, 0x10`)
//!   interact with register aliasing in non-trivial ways on x86-64; we
//!   flag them Unsupported rather than silently dropping the upper
//!   bits. A later pass can model partial-register writes explicitly.
//! - **Pure values in expressions, impurities in effects.** `Expr` is
//!   pure (reads only). Writes are `Effect`. This separation is what
//!   makes the algebraic simplifier safe: we can rewrite inside an
//!   `Expr` without worrying about ordering vs memory.

pub mod emit;
pub mod expr;
pub mod lifter;
pub mod simplify;

pub use emit::{emit_effect, emit_effects, emit_expr};
pub use expr::{Effect, Expr, RegId};
pub use lifter::{lift_instruction, LiftError};
pub use simplify::{simplify_effects, simplify_expr};
