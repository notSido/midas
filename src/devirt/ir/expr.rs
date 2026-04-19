//! Expression AST and effect types for the devirt IR.
//!
//! `Expr` is a *pure* value expression — reading a register/flag, loading
//! from memory, or combining values. Anything that *changes* state is an
//! `Effect` (register write, flag write, memory store, branch). This
//! split is the simplifier's contract: any `Expr` can be rewritten
//! freely; `Effect` order must be preserved.

use iced_x86::Register;

/// Architectural register. We re-use `iced_x86::Register` rather than
/// minting a new enum — it already covers every x86 register, and using
/// the same type as the decoder means no lossy conversion.
///
/// Narrow GPR aliases (AL, AH, EAX, ...) are not used as `RegId` values.
/// Partial-width reads/writes are modelled explicitly via mask/shift/blend
/// expressions over the *full* register (see `lifter::partial_reg_read`
/// and `lifter::partial_reg_write`).
pub type RegId = Register;

/// Pseudo-register for an x86 status flag. Kept as a separate type so
/// `RegId` can stay equal to `iced_x86::Register` — architectural state
/// and flag state have different lifecycle and different simplification
/// rules, and conflating them would make both messier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    /// Carry flag — unsigned overflow / borrow.
    CF,
    /// Parity flag — even parity of the low byte of the result.
    PF,
    /// Auxiliary-carry — BCD carry out of bit 3.
    AF,
    /// Zero flag — result was zero.
    ZF,
    /// Sign flag — high bit of result.
    SF,
    /// Overflow flag — signed overflow.
    OF,
}

/// Pure value expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    Const(u64),
    Reg(RegId),
    Flag(Flag),
    /// Memory load. `size` is the read width in bytes (1/2/4/8). The
    /// loaded value is zero-extended to a 64-bit `Expr` value.
    MemLoad {
        addr: Box<Expr>,
        size: u8,
    },

    // Arithmetic / bitwise binops. Operands are treated as 64-bit values;
    // width-truncation is modelled explicitly via `And(x, mask)` so the
    // simplifier can reason about it.
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

    /// Boolean equality — evaluates to 1 if `lhs == rhs`, else 0. Used to
    /// express flag values (`ZF = Eq(result, 0)`) and branch conditions
    /// (`Branch.cond = Eq(Flag(ZF), 0)` for `jne`).
    Eq(Box<Expr>, Box<Expr>),
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
    pub fn eq(a: Expr, b: Expr) -> Expr {
        Expr::Eq(Box::new(a), Box::new(b))
    }
}

/// Side-effecting operation emitted by a single instruction. One
/// instruction can emit multiple effects (e.g. `sub` = register write +
/// ZF/SF flag writes; `push` = memory store + RSP decrement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Write a value to a register.
    SetReg(RegId, Expr),
    /// Write a value to a status flag (the value is 0 or 1, represented
    /// as a `u64`-valued `Expr`).
    SetFlag(Flag, Expr),
    /// Write a value to memory. `size` in bytes (1/2/4/8).
    MemStore { addr: Expr, value: Expr, size: u8 },
    /// Conditional branch. If `cond` evaluates to non-zero, control
    /// transfers to `target`. For static devirt these are *descriptors*
    /// recorded for the emitter — the lifter does not materialize the
    /// jump at lift time. Unconditional jumps lift to `cond: Const(1)`.
    Branch { cond: Expr, target: u64 },
}
