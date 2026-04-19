//! Pseudo-C emitter for the devirt IR.
//!
//! Produces readable textual output from `Vec<Effect>` — the final
//! artifact of the devirt pipeline when a reassembled PE isn't
//! required. Expression precedence is handled by parenthesising
//! liberally; register names come from iced-x86's lowercase
//! conventions (`rax`, `r11`, etc.) and flag names are lowercase
//! (`zf`, `sf`, …). Hex literals for constants ≥ 16 to match
//! what a reverser eyeballing the output expects.

use super::expr::{Effect, Expr, Flag, RegId};

/// Render a single `Expr` as pseudo-C.
pub fn emit_expr(e: &Expr) -> String {
    render_expr(e, /*parens=*/ false)
}

/// Render a single `Effect` as one line of pseudo-C.
pub fn emit_effect(e: &Effect) -> String {
    match e {
        Effect::SetReg(r, v) => format!("{} = {};", reg_name(*r), emit_expr(v)),
        Effect::SetFlag(f, v) => format!("{} = {};", flag_name(*f), emit_expr(v)),
        Effect::MemStore { addr, value, size } => format!(
            "*({}*)({}) = {};",
            mem_ty(*size),
            emit_expr(addr),
            emit_expr(value)
        ),
        Effect::Branch { cond, target } => {
            if matches!(cond, Expr::Const(1)) {
                format!("goto 0x{:x};", target)
            } else {
                format!("if ({}) goto 0x{:x};", emit_expr(cond), target)
            }
        }
    }
}

/// Render a whole effect sequence, one statement per line.
pub fn emit_effects(effects: &[Effect]) -> String {
    let mut out = String::new();
    for eff in effects {
        out.push_str(&emit_effect(eff));
        out.push('\n');
    }
    out
}

fn render_expr(e: &Expr, parens: bool) -> String {
    match e {
        Expr::Const(v) => format_const(*v),
        Expr::Reg(r) => reg_name(*r),
        Expr::Flag(f) => flag_name(*f).to_string(),
        Expr::MemLoad { addr, size } => {
            format!("*({}*)({})", mem_ty(*size), render_expr(addr, false))
        }
        Expr::Add(a, b) => wrap(parens, &format!("{} + {}", render_expr(a, true), render_expr(b, true))),
        Expr::Sub(a, b) => wrap(parens, &format!("{} - {}", render_expr(a, true), render_expr(b, true))),
        Expr::And(a, b) => wrap(parens, &format!("{} & {}", render_expr(a, true), render_expr(b, true))),
        Expr::Or(a, b) => wrap(parens, &format!("{} | {}", render_expr(a, true), render_expr(b, true))),
        Expr::Xor(a, b) => wrap(parens, &format!("{} ^ {}", render_expr(a, true), render_expr(b, true))),
        Expr::Shl(a, b) => wrap(parens, &format!("{} << {}", render_expr(a, true), render_expr(b, true))),
        Expr::Shr(a, b) => wrap(parens, &format!("{} >> {}", render_expr(a, true), render_expr(b, true))),
        Expr::Not(a) => format!("~{}", render_expr(a, true)),
        Expr::Neg(a) => format!("-{}", render_expr(a, true)),
        Expr::Eq(a, b) => wrap(parens, &format!("{} == {}", render_expr(a, true), render_expr(b, true))),
    }
}

fn wrap(parens: bool, s: &str) -> String {
    if parens {
        format!("({})", s)
    } else {
        s.to_string()
    }
}

fn format_const(v: u64) -> String {
    if v < 16 {
        format!("{}", v)
    } else {
        format!("0x{:x}", v)
    }
}

fn reg_name(r: RegId) -> String {
    // iced-x86's Debug prints `RAX`, `R11`, etc. — lowercase it.
    format!("{:?}", r).to_lowercase()
}

fn flag_name(f: Flag) -> &'static str {
    match f {
        Flag::CF => "cf",
        Flag::PF => "pf",
        Flag::AF => "af",
        Flag::ZF => "zf",
        Flag::SF => "sf",
        Flag::OF => "of",
    }
}

fn mem_ty(size: u8) -> &'static str {
    match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        _ => "u?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::Register;

    #[test]
    fn const_hex_when_large() {
        assert_eq!(emit_expr(&Expr::Const(5)), "5");
        assert_eq!(emit_expr(&Expr::Const(16)), "0x10");
        assert_eq!(emit_expr(&Expr::Const(0xDEAD)), "0xdead");
    }

    #[test]
    fn reg_names_lowercase() {
        assert_eq!(emit_expr(&Expr::Reg(Register::RAX)), "rax");
        assert_eq!(emit_expr(&Expr::Reg(Register::R11)), "r11");
    }

    #[test]
    fn binop_parens_nested() {
        // (rax + 1) + rbx
        let e = Expr::add(
            Expr::add(Expr::Reg(Register::RAX), Expr::Const(1)),
            Expr::Reg(Register::RBX),
        );
        assert_eq!(emit_expr(&e), "(rax + 1) + rbx");
    }

    #[test]
    fn setreg_emits_assignment() {
        let eff = Effect::SetReg(
            Register::R11,
            Expr::add(Expr::Reg(Register::R12), Expr::Const(0x8)),
        );
        assert_eq!(emit_effect(&eff), "r11 = r12 + 8;");
    }

    #[test]
    fn memstore_emits_dereference_assignment() {
        let eff = Effect::MemStore {
            addr: Expr::add(Expr::Reg(Register::RBP), Expr::Const(0x88)),
            value: Expr::Reg(Register::RAX),
            size: 8,
        };
        assert_eq!(emit_effect(&eff), "*(u64*)(rbp + 0x88) = rax;");
    }

    #[test]
    fn memload_inline() {
        let eff = Effect::SetReg(
            Register::RCX,
            Expr::MemLoad {
                addr: Box::new(Expr::Reg(Register::RBX)),
                size: 4,
            },
        );
        assert_eq!(emit_effect(&eff), "rcx = *(u32*)(rbx);");
    }

    #[test]
    fn branch_unconditional() {
        let eff = Effect::Branch {
            cond: Expr::Const(1),
            target: 0x1234,
        };
        assert_eq!(emit_effect(&eff), "goto 0x1234;");
    }

    #[test]
    fn branch_conditional() {
        let eff = Effect::Branch {
            cond: Expr::eq(Expr::Flag(Flag::ZF), Expr::Const(0)),
            target: 0x1234,
        };
        assert_eq!(emit_effect(&eff), "if (zf == 0) goto 0x1234;");
    }
}
