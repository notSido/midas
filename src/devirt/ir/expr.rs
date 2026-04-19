//! Expression AST and effect types for the devirt IR.
//!
//! `Expr` is a *pure* value expression — reading a register, loading
//! from memory, or combining values. Anything that *changes* state is
//! an `Effect` (register write, memory store). This split is the
//! simplifier's contract: any `Expr` can be rewritten freely; `Effect`
//! order must be preserved.

use iced_x86::Register;

/// Architectural register. We re-use `iced_x86::Register` rather than
/// minting a new enum — it already covers every x86 register, and using
/// the same type as the decoder means no lossy conversion.
pub type RegId = Register;

/// Pure value expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    Const(u64),
    Reg(RegId),
    /// Memory load. `size` is the read width in bytes (1/2/4/8).
    MemLoad {
        addr: Box<Expr>,
        size: u8,
    },

    // Arithmetic / bitwise binops. Operands are always 64-bit in this
    // first cut — the lifter rejects narrower ops as Unsupported.
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),

    // Unary.
    Not(Box<Expr>),
    Neg(Box<Expr>),
}

impl Expr {
    pub fn add(a: Expr, b: Expr) -> Expr {
        Expr::Add(Box::new(a), Box::new(b))
    }
    pub fn sub(a: Expr, b: Expr) -> Expr {
        Expr::Sub(Box::new(a), Box::new(b))
    }
    pub fn and(a: Expr, b: Expr) -> Expr {
        Expr::And(Box::new(a), Box::new(b))
    }
    pub fn or(a: Expr, b: Expr) -> Expr {
        Expr::Or(Box::new(a), Box::new(b))
    }
    pub fn xor(a: Expr, b: Expr) -> Expr {
        Expr::Xor(Box::new(a), Box::new(b))
    }
    pub fn shl(a: Expr, b: Expr) -> Expr {
        Expr::Shl(Box::new(a), Box::new(b))
    }
    pub fn shr(a: Expr, b: Expr) -> Expr {
        Expr::Shr(Box::new(a), Box::new(b))
    }
    pub fn not(a: Expr) -> Expr {
        Expr::Not(Box::new(a))
    }
    pub fn neg(a: Expr) -> Expr {
        Expr::Neg(Box::new(a))
    }
}

/// Side-effecting operation emitted by a single instruction. One
/// instruction can emit multiple effects (e.g. `push` = memory store
/// + RSP decrement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Write a value to a register.
    SetReg(RegId, Expr),
    /// Write a value to memory. `size` in bytes (1/2/4/8).
    MemStore { addr: Expr, value: Expr, size: u8 },
}
