//! Minimal-but-useful IR simplifier (M6 MVP).
//!
//! Three layers, applied in order:
//!
//! 1. **Per-expression peepholes.** Bottom-up rewrite of an `Expr`:
//!    constant folding, absorbing identities (`x + 0 → x`, `x ^ x → 0`,
//!    `x & 0 → 0`, `x & ~0 → x`, …), double-negation cancel, and
//!    simple xor cancellation `(x ^ y) ^ y → x`. Canonicalisation
//!    puts constants on the RHS of commutative ops so more peepholes
//!    fire.
//!
//! 2. **Forward substitution** (reg/flag only). We walk effects
//!    top-down maintaining `reg → most-recent-definition`. When we
//!    encounter `Reg(r)` inside a subsequent expression, we inline
//!    the definition and re-simplify. This is what makes pattern
//!    like `xor rcx,rbx; xor rcx,rbx` collapse — the second read of
//!    `rcx` gets the first's definition inlined, then the peephole
//!    `(x ^ y) ^ y → x` fires. Memory aliasing is intentionally not
//!    handled — addresses are expressions, pretending we can compare
//!    them for equality is a bigger can of worms.
//!
//! 3. **Dead-effect elimination.** Backwards pass with a conservative
//!    live-out set (all 16 GPR64s). If an effect writes a register or
//!    flag that nothing between here and EOF reads, drop it.
//!    `MemStore` and `Branch` are always kept (side-effecting /
//!    control flow). Identity self-copies `SetReg(r, Reg(r))` are
//!    dropped too — they materialise post-substitution when the only
//!    register a handler touches "cancels out".

use std::collections::{HashMap, HashSet};

use iced_x86::Register;

use super::expr::{Effect, Expr, Flag, RegId};

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

pub fn simplify_expr(e: Expr) -> Expr {
    peephole(descend(e))
}

pub fn simplify_effects(effects: Vec<Effect>) -> Vec<Effect> {
    let substituted = forward_substitute(effects);
    dead_effect_elim(substituted)
}

// -------------------------------------------------------------------
// Peepholes
// -------------------------------------------------------------------

fn descend(e: Expr) -> Expr {
    match e {
        Expr::Add(a, b) => Expr::add(simplify_expr(*a), simplify_expr(*b)),
        Expr::Sub(a, b) => Expr::sub(simplify_expr(*a), simplify_expr(*b)),
        Expr::And(a, b) => Expr::and(simplify_expr(*a), simplify_expr(*b)),
        Expr::Or(a, b) => Expr::or(simplify_expr(*a), simplify_expr(*b)),
        Expr::Xor(a, b) => Expr::xor(simplify_expr(*a), simplify_expr(*b)),
        Expr::Shl(a, b) => Expr::shl(simplify_expr(*a), simplify_expr(*b)),
        Expr::Shr(a, b) => Expr::shr(simplify_expr(*a), simplify_expr(*b)),
        Expr::Not(a) => Expr::not(simplify_expr(*a)),
        Expr::Neg(a) => Expr::neg(simplify_expr(*a)),
        Expr::Eq(a, b) => Expr::eq(simplify_expr(*a), simplify_expr(*b)),
        Expr::MemLoad { addr, size } => Expr::MemLoad {
            addr: Box::new(simplify_expr(*addr)),
            size,
        },
        leaf => leaf,
    }
}

fn peephole(e: Expr) -> Expr {
    match e {
        Expr::Add(a, b) => ph_add(*a, *b),
        Expr::Sub(a, b) => ph_sub(*a, *b),
        Expr::And(a, b) => ph_and(*a, *b),
        Expr::Or(a, b) => ph_or(*a, *b),
        Expr::Xor(a, b) => ph_xor(*a, *b),
        Expr::Shl(a, b) => ph_shl(*a, *b),
        Expr::Shr(a, b) => ph_shr(*a, *b),
        Expr::Not(a) => ph_not(*a),
        Expr::Neg(a) => ph_neg(*a),
        Expr::Eq(a, b) => ph_eq(*a, *b),
        other => other,
    }
}

fn ph_add(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(y)) => Expr::Const(x.wrapping_add(y)),
        (x, Expr::Const(0)) => x,
        (Expr::Const(0), x) => x,
        (Expr::Const(c), x) => peephole(Expr::add(x, Expr::Const(c))),
        // Re-associate over constants: (x op c1) + c2 → x op' combined.
        // Inner operation has a const on its RHS (canonicalised upstream).
        (Expr::Add(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => {
                peephole(Expr::add(*x, Expr::Const(v1.wrapping_add(c2))))
            }
            other => Expr::add(Expr::Add(x, Box::new(other)), Expr::Const(c2)),
        },
        (Expr::Sub(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => {
                peephole(Expr::add(*x, Expr::Const(c2.wrapping_sub(v1))))
            }
            other => Expr::add(Expr::Sub(x, Box::new(other)), Expr::Const(c2)),
        },
        (a, b) => Expr::add(a, b),
    }
}

fn ph_sub(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(y)) => Expr::Const(x.wrapping_sub(y)),
        (x, Expr::Const(0)) => x,
        (a, b) if a == b => Expr::Const(0),
        // (x + c1) - c2 → x + (c1 - c2)
        (Expr::Add(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => {
                peephole(Expr::add(*x, Expr::Const(v1.wrapping_sub(c2))))
            }
            other => Expr::sub(Expr::Add(x, Box::new(other)), Expr::Const(c2)),
        },
        // (x - c1) - c2 → x - (c1 + c2)
        (Expr::Sub(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => {
                peephole(Expr::sub(*x, Expr::Const(v1.wrapping_add(c2))))
            }
            other => Expr::sub(Expr::Sub(x, Box::new(other)), Expr::Const(c2)),
        },
        (a, b) => Expr::sub(a, b),
    }
}

fn ph_and(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(y)) => Expr::Const(x & y),
        (_, Expr::Const(0)) => Expr::Const(0),
        (Expr::Const(0), _) => Expr::Const(0),
        (x, Expr::Const(m)) if m == u64::MAX => x,
        (Expr::Const(m), x) if m == u64::MAX => x,
        (Expr::Const(c), x) => peephole(Expr::and(x, Expr::Const(c))),
        (a, b) if a == b => a,
        // (x & c1) & c2 → x & (c1 & c2). Kills `((X & 0xffffffff) &
        // 0xffffffff)` chains from narrow-reg reads piling up.
        (Expr::And(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => peephole(Expr::and(*x, Expr::Const(v1 & c2))),
            other => Expr::and(Expr::And(x, Box::new(other)), Expr::Const(c2)),
        },
        (a, b) => Expr::and(a, b),
    }
}

fn ph_or(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(y)) => Expr::Const(x | y),
        (x, Expr::Const(0)) => x,
        (Expr::Const(0), x) => x,
        (_, Expr::Const(m)) if m == u64::MAX => Expr::Const(u64::MAX),
        (Expr::Const(m), _) if m == u64::MAX => Expr::Const(u64::MAX),
        (Expr::Const(c), x) => peephole(Expr::or(x, Expr::Const(c))),
        (a, b) if a == b => a,
        (Expr::Or(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => peephole(Expr::or(*x, Expr::Const(v1 | c2))),
            other => Expr::or(Expr::Or(x, Box::new(other)), Expr::Const(c2)),
        },
        (a, b) => Expr::or(a, b),
    }
}

fn ph_xor(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(y)) => Expr::Const(x ^ y),
        (x, Expr::Const(0)) => x,
        (Expr::Const(0), x) => x,
        (Expr::Const(c), x) => peephole(Expr::xor(x, Expr::Const(c))),
        (a, b) if a == b => Expr::Const(0),
        // (x ^ y) ^ y  →  x
        (Expr::Xor(inner_a, inner_b), rhs) if *inner_b == rhs => *inner_a,
        // (x ^ y) ^ x  →  y
        (Expr::Xor(inner_a, inner_b), rhs) if *inner_a == rhs => *inner_b,
        // (x ^ c1) ^ c2 → x ^ (c1 ^ c2)
        (Expr::Xor(x, c1), Expr::Const(c2)) => match *c1 {
            Expr::Const(v1) => peephole(Expr::xor(*x, Expr::Const(v1 ^ c2))),
            other => Expr::xor(Expr::Xor(x, Box::new(other)), Expr::Const(c2)),
        },
        (a, b) => Expr::xor(a, b),
    }
}

fn ph_shl(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(n)) if n < 64 => Expr::Const(x.wrapping_shl(n as u32)),
        (Expr::Const(_), Expr::Const(_)) => Expr::Const(0),
        (x, Expr::Const(0)) => x,
        (Expr::Const(0), _) => Expr::Const(0),
        (a, b) => Expr::shl(a, b),
    }
}

fn ph_shr(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(n)) if n < 64 => Expr::Const(x.wrapping_shr(n as u32)),
        (Expr::Const(_), Expr::Const(_)) => Expr::Const(0),
        (x, Expr::Const(0)) => x,
        (Expr::Const(0), _) => Expr::Const(0),
        (a, b) => Expr::shr(a, b),
    }
}

fn ph_not(a: Expr) -> Expr {
    match a {
        Expr::Const(x) => Expr::Const(!x),
        Expr::Not(x) => *x,
        other => Expr::not(other),
    }
}

fn ph_neg(a: Expr) -> Expr {
    match a {
        Expr::Const(x) => Expr::Const(x.wrapping_neg()),
        Expr::Neg(x) => *x,
        other => Expr::neg(other),
    }
}

fn ph_eq(a: Expr, b: Expr) -> Expr {
    match (a, b) {
        (Expr::Const(x), Expr::Const(y)) => Expr::Const(if x == y { 1 } else { 0 }),
        (a, b) if a == b => Expr::Const(1),
        (a, b) => Expr::eq(a, b),
    }
}

// -------------------------------------------------------------------
// Forward substitution
// -------------------------------------------------------------------

fn forward_substitute(effects: Vec<Effect>) -> Vec<Effect> {
    let mut reg_defs: HashMap<RegId, Expr> = HashMap::new();
    let mut flag_defs: HashMap<Flag, Expr> = HashMap::new();
    let mut out = Vec::with_capacity(effects.len());

    for eff in effects {
        match eff {
            Effect::SetReg(r, value) => {
                let value = simplify_expr(substitute_reads(value, &reg_defs, &flag_defs));
                reg_defs.insert(r, value.clone());
                out.push(Effect::SetReg(r, value));
            }
            Effect::SetFlag(f, value) => {
                let value = simplify_expr(substitute_reads(value, &reg_defs, &flag_defs));
                flag_defs.insert(f, value.clone());
                out.push(Effect::SetFlag(f, value));
            }
            Effect::MemStore { addr, value, size } => {
                let addr = simplify_expr(substitute_reads(addr, &reg_defs, &flag_defs));
                let value = simplify_expr(substitute_reads(value, &reg_defs, &flag_defs));
                out.push(Effect::MemStore { addr, value, size });
            }
            Effect::Branch { cond, target } => {
                let cond = simplify_expr(substitute_reads(cond, &reg_defs, &flag_defs));
                out.push(Effect::Branch { cond, target });
            }
        }
    }
    out
}

fn substitute_reads(
    e: Expr,
    regs: &HashMap<RegId, Expr>,
    flags: &HashMap<Flag, Expr>,
) -> Expr {
    match e {
        Expr::Const(_) => e,
        Expr::Reg(r) => regs.get(&r).cloned().unwrap_or(Expr::Reg(r)),
        Expr::Flag(f) => flags.get(&f).cloned().unwrap_or(Expr::Flag(f)),
        Expr::MemLoad { addr, size } => Expr::MemLoad {
            addr: Box::new(substitute_reads(*addr, regs, flags)),
            size,
        },
        Expr::Add(a, b) => Expr::add(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::Sub(a, b) => Expr::sub(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::And(a, b) => Expr::and(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::Or(a, b) => Expr::or(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::Xor(a, b) => Expr::xor(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::Shl(a, b) => Expr::shl(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::Shr(a, b) => Expr::shr(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
        Expr::Not(a) => Expr::not(substitute_reads(*a, regs, flags)),
        Expr::Neg(a) => Expr::neg(substitute_reads(*a, regs, flags)),
        Expr::Eq(a, b) => Expr::eq(
            substitute_reads(*a, regs, flags),
            substitute_reads(*b, regs, flags),
        ),
    }
}

// -------------------------------------------------------------------
// Dead-effect elimination
// -------------------------------------------------------------------

fn dead_effect_elim(effects: Vec<Effect>) -> Vec<Effect> {
    // After forward-substitution, every `SetReg(r, v)` has `v`
    // expressed in terms of ORIGINAL register/flag values — each
    // write is an independent definition of `r`'s final value.
    // Only the LAST write per reg/flag contributes; everything
    // before it is redundantly re-defining the same thing and can
    // be dropped. This is cleaner than classical liveness-DCE
    // (which would keep every link in a chain like `r15 = r15 ^
    // k1; r15 = (r15 ^ k1) + k2; ...` because each link "reads" r15).
    //
    // MemStore and Branch are always kept — their addr/value/cond
    // expressions have already been forward-substituted, so they
    // capture the correct intermediate state even if earlier
    // SetRegs get dropped.
    let live_regs: HashSet<RegId> = all_gpr64().into_iter().collect();
    let live_flags: HashSet<Flag> = all_flags().into_iter().collect();

    // First pass: find the index of the last SetReg per register
    // and the last SetFlag per flag.
    let mut last_reg_write: HashMap<RegId, usize> = HashMap::new();
    let mut last_flag_write: HashMap<Flag, usize> = HashMap::new();
    for (i, eff) in effects.iter().enumerate() {
        match eff {
            Effect::SetReg(r, _) => {
                last_reg_write.insert(*r, i);
            }
            Effect::SetFlag(f, _) => {
                last_flag_write.insert(*f, i);
            }
            _ => {}
        }
    }

    let mut out = Vec::with_capacity(effects.len());
    for (i, eff) in effects.into_iter().enumerate() {
        let keep = match &eff {
            Effect::SetReg(r, v) => {
                if last_reg_write.get(r) != Some(&i) {
                    false
                } else if matches!(v, Expr::Reg(rr) if rr == r) {
                    false
                } else {
                    live_regs.contains(r)
                }
            }
            Effect::SetFlag(f, _) => {
                if last_flag_write.get(f) != Some(&i) {
                    false
                } else {
                    live_flags.contains(f)
                }
            }
            Effect::MemStore { .. } | Effect::Branch { .. } => true,
        };
        if keep {
            out.push(eff);
        }
    }
    out
}

fn all_gpr64() -> Vec<RegId> {
    vec![
        Register::RAX,
        Register::RBX,
        Register::RCX,
        Register::RDX,
        Register::RSI,
        Register::RDI,
        Register::RBP,
        Register::RSP,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ]
}

fn all_flags() -> Vec<Flag> {
    vec![Flag::CF, Flag::PF, Flag::AF, Flag::ZF, Flag::SF, Flag::OF]
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: u64) -> Expr {
        Expr::Const(v)
    }
    fn r(reg: Register) -> Expr {
        Expr::Reg(reg)
    }

    #[test]
    fn add_const_fold() {
        assert_eq!(simplify_expr(Expr::add(c(1), c(2))), c(3));
    }

    #[test]
    fn add_zero_identity() {
        assert_eq!(simplify_expr(Expr::add(r(Register::RAX), c(0))), r(Register::RAX));
        assert_eq!(simplify_expr(Expr::add(c(0), r(Register::RAX))), r(Register::RAX));
    }

    #[test]
    fn xor_self_is_zero() {
        assert_eq!(simplify_expr(Expr::xor(r(Register::RAX), r(Register::RAX))), c(0));
    }

    #[test]
    fn xor_cancel_sequence() {
        // (rcx ^ rbx) ^ rbx  →  rcx
        let e = Expr::xor(
            Expr::xor(r(Register::RCX), r(Register::RBX)),
            r(Register::RBX),
        );
        assert_eq!(simplify_expr(e), r(Register::RCX));
    }

    #[test]
    fn and_zero_absorbs() {
        assert_eq!(simplify_expr(Expr::and(r(Register::RAX), c(0))), c(0));
    }

    #[test]
    fn and_all_ones_identity() {
        assert_eq!(
            simplify_expr(Expr::and(r(Register::RAX), c(u64::MAX))),
            r(Register::RAX)
        );
    }

    #[test]
    fn not_not_x() {
        assert_eq!(
            simplify_expr(Expr::not(Expr::not(r(Register::RAX)))),
            r(Register::RAX)
        );
    }

    #[test]
    fn neg_neg_x() {
        assert_eq!(
            simplify_expr(Expr::neg(Expr::neg(r(Register::RAX)))),
            r(Register::RAX)
        );
    }

    #[test]
    fn canonicalize_const_to_right() {
        // 5 + rax  →  rax + 5
        let e = Expr::add(c(5), r(Register::RAX));
        match simplify_expr(e) {
            Expr::Add(a, b) => {
                assert!(matches!(*a, Expr::Reg(Register::RAX)));
                assert!(matches!(*b, Expr::Const(5)));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn forward_sub_eliminates_double_xor() {
        // `xor rcx, rbx; xor rcx, rbx` should produce ZERO non-
        // trivial effects after simplification: the second SetReg
        // becomes identity (rcx = rcx) and drops, the first is dead
        // because nothing reads its rcx before iter-ends and live-out
        // keeps only "all-GPR" which means the ORIGINAL rcx is live,
        // so the first xor is dead too (wait — live-out is "all GPRs
        // live", so post-forward-sub the first write of rcx is
        // visible to nothing downstream, kill). Expected: `[]` or
        // at most the flag writes (which we don't assert here).
        let effects = vec![
            Effect::SetReg(
                Register::RCX,
                Expr::xor(r(Register::RCX), r(Register::RBX)),
            ),
            Effect::SetReg(
                Register::RCX,
                Expr::xor(r(Register::RCX), r(Register::RBX)),
            ),
        ];
        let out = simplify_effects(effects);
        // Neither SetReg should remain.
        assert!(
            out.iter()
                .all(|e| !matches!(e, Effect::SetReg(Register::RCX, _))),
            "got: {:?}",
            out
        );
    }

    #[test]
    fn identity_self_copy_dropped() {
        let effects = vec![Effect::SetReg(Register::RAX, r(Register::RAX))];
        let out = simplify_effects(effects);
        assert!(out.is_empty());
    }

    #[test]
    fn memstore_kept() {
        let effects = vec![Effect::MemStore {
            addr: c(0x1000),
            value: c(0),
            size: 8,
        }];
        let out = simplify_effects(effects.clone());
        assert_eq!(out, effects);
    }

    #[test]
    fn dead_flag_write_dropped() {
        // Two SetFlag(ZF, ...) back to back — the first is dead.
        let effects = vec![
            Effect::SetFlag(Flag::ZF, c(0)),
            Effect::SetFlag(Flag::ZF, c(1)),
        ];
        let out = simplify_effects(effects);
        assert_eq!(out, vec![Effect::SetFlag(Flag::ZF, c(1))]);
    }
}
