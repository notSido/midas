//! iced-x86 → devirt IR lifter.
//!
//! Consumes a single `iced_x86::Instruction` and returns the `Effect`s
//! it would produce. Scope of this first cut:
//!
//! - 64-bit general-purpose register operands only (RAX..R15, RSP, RBP,
//!   RIP). Narrower or non-GPR operands → `LiftError::Unsupported`.
//! - The core data-movement and arithmetic mnemonics Themida VM handlers
//!   exercise most heavily: `mov`, `add`, `sub`, `xor`, `and`, `or`,
//!   `shl`, `shr`, `not`, `neg`. Everything else is `Unsupported`.
//! - Simple addressing modes for memory operands: `[base]` and
//!   `[base + disp32]`. Scaled-index, RIP-relative, and segment-overridden
//!   forms will be handled later.
//! - **No flag effects.** `add` does not model OF/SF/ZF/CF. Themida
//!   handler simplification doesn't need them for value-flow analysis;
//!   when we get to control-flow / `cmp+jne` we'll add a rflags model.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::expr::{Effect, Expr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftError {
    Unsupported(&'static str),
    BadOperand(&'static str),
}

pub fn lift_instruction(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    match insn.mnemonic() {
        Mnemonic::Mov => lift_mov(insn),
        Mnemonic::Add => lift_binop(insn, Expr::add),
        Mnemonic::Sub => lift_binop(insn, Expr::sub),
        Mnemonic::Xor => lift_binop(insn, Expr::xor),
        Mnemonic::And => lift_binop(insn, Expr::and),
        Mnemonic::Or => lift_binop(insn, Expr::or),
        Mnemonic::Shl => lift_binop(insn, Expr::shl),
        Mnemonic::Shr => lift_binop(insn, Expr::shr),
        Mnemonic::Not => lift_unop(insn, Expr::not),
        Mnemonic::Neg => lift_unop(insn, Expr::neg),
        _ => Err(LiftError::Unsupported("mnemonic")),
    }
}

fn lift_mov(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let src = lift_read_operand(insn, 1)?;
    match insn.op0_kind() {
        OpKind::Register => {
            let dst = require_gpr64(insn.op0_register())?;
            Ok(vec![Effect::SetReg(dst, src)])
        }
        OpKind::Memory => {
            let addr = lift_mem_addr(insn)?;
            let size = require_std_size(insn.memory_size().size())?;
            Ok(vec![Effect::MemStore { addr, value: src, size }])
        }
        _ => Err(LiftError::Unsupported("mov dst operand kind")),
    }
}

fn lift_binop(insn: &Instruction, build: fn(Expr, Expr) -> Expr) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let lhs = lift_read_operand(insn, 0)?;
    let rhs = lift_read_operand(insn, 1)?;
    let value = build(lhs, rhs);
    match insn.op0_kind() {
        OpKind::Register => {
            let dst = require_gpr64(insn.op0_register())?;
            Ok(vec![Effect::SetReg(dst, value)])
        }
        OpKind::Memory => {
            let addr = lift_mem_addr(insn)?;
            let size = require_std_size(insn.memory_size().size())?;
            Ok(vec![Effect::MemStore { addr, value, size }])
        }
        _ => Err(LiftError::Unsupported("binop dst operand kind")),
    }
}

fn lift_unop(insn: &Instruction, build: fn(Expr) -> Expr) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 1)?;
    let v = lift_read_operand(insn, 0)?;
    let value = build(v);
    match insn.op0_kind() {
        OpKind::Register => {
            let dst = require_gpr64(insn.op0_register())?;
            Ok(vec![Effect::SetReg(dst, value)])
        }
        OpKind::Memory => {
            let addr = lift_mem_addr(insn)?;
            let size = require_std_size(insn.memory_size().size())?;
            Ok(vec![Effect::MemStore { addr, value, size }])
        }
        _ => Err(LiftError::Unsupported("unop dst operand kind")),
    }
}

fn lift_read_operand(insn: &Instruction, idx: u32) -> Result<Expr, LiftError> {
    match insn.op_kind(idx) {
        OpKind::Register => {
            let r = require_gpr64(insn.op_register(idx))?;
            Ok(Expr::Reg(r))
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Ok(Expr::Const(insn.immediate(idx))),
        OpKind::Memory => {
            let addr = lift_mem_addr(insn)?;
            let size = require_std_size(insn.memory_size().size())?;
            Ok(Expr::MemLoad { addr: Box::new(addr), size })
        }
        _ => Err(LiftError::Unsupported("source operand kind")),
    }
}

/// Build an `Expr` for the instruction's memory address, `[base +
/// disp32]`. Scaled index, segment override, and RIP-relative are not
/// yet supported.
fn lift_mem_addr(insn: &Instruction) -> Result<Expr, LiftError> {
    if insn.memory_index() != Register::None {
        return Err(LiftError::Unsupported("indexed memory addressing"));
    }
    if insn.segment_prefix() != Register::None {
        return Err(LiftError::Unsupported("segment-prefixed memory"));
    }
    let base = insn.memory_base();
    let disp = insn.memory_displacement64();
    match base {
        Register::None => Ok(Expr::Const(disp)),
        Register::RIP => Err(LiftError::Unsupported("RIP-relative memory")),
        _ => {
            let base_reg = require_gpr64(base)?;
            if disp == 0 {
                Ok(Expr::Reg(base_reg))
            } else {
                Ok(Expr::add(Expr::Reg(base_reg), Expr::Const(disp)))
            }
        }
    }
}

fn require_op_count(insn: &Instruction, want: u32) -> Result<(), LiftError> {
    if insn.op_count() == want {
        Ok(())
    } else {
        Err(LiftError::BadOperand("unexpected op_count"))
    }
}

fn require_gpr64(r: Register) -> Result<Register, LiftError> {
    // iced-x86 reports GPRs as RAX..R15, RSP, RBP with size 8. Narrower
    // aliases (EAX, AX, AL, AH, ...) have size 4/2/1 and are deliberately
    // rejected for this first cut to avoid silently dropping upper bits.
    if r.is_gpr64() {
        Ok(r)
    } else {
        Err(LiftError::Unsupported("non-64-bit GPR"))
    }
}

fn require_std_size(size: usize) -> Result<u8, LiftError> {
    match size {
        1 | 2 | 4 | 8 => Ok(size as u8),
        _ => Err(LiftError::Unsupported("unusual memory access size")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_one(bytes: &[u8]) -> Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    #[test]
    fn lift_mov_reg_reg() {
        // mov rax, rbx   (48 89 d8)
        let insn = decode_one(&[0x48, 0x89, 0xD8]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(effs, vec![Effect::SetReg(Register::RAX, Expr::Reg(Register::RBX))]);
    }

    #[test]
    fn lift_xor_reg_reg() {
        // xor rax, rsi   (48 31 f0)
        let insn = decode_one(&[0x48, 0x31, 0xF0]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![Effect::SetReg(
                Register::RAX,
                Expr::xor(Expr::Reg(Register::RAX), Expr::Reg(Register::RSI))
            )]
        );
    }

    #[test]
    fn lift_and_reg_imm() {
        // and r11, 0x20 via REX+and r/m64, imm8 sign-extended
        // 49 83 e3 20
        let insn = decode_one(&[0x49, 0x83, 0xE3, 0x20]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![Effect::SetReg(
                Register::R11,
                Expr::and(Expr::Reg(Register::R11), Expr::Const(0x20))
            )]
        );
    }

    #[test]
    fn lift_add_reg_reg() {
        // add rdx, r8    (4c 01 c2)
        let insn = decode_one(&[0x4C, 0x01, 0xC2]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![Effect::SetReg(
                Register::RDX,
                Expr::add(Expr::Reg(Register::RDX), Expr::Reg(Register::R8))
            )]
        );
    }

    #[test]
    fn narrow_write_is_unsupported() {
        // mov al, 0x10 (b0 10)  — intentionally not supported in this cut
        let insn = decode_one(&[0xB0, 0x10]);
        assert!(matches!(lift_instruction(&insn), Err(LiftError::Unsupported(_))));
    }

    #[test]
    fn unknown_mnemonic_is_unsupported() {
        // nop
        let insn = decode_one(&[0x90]);
        assert!(matches!(lift_instruction(&insn), Err(LiftError::Unsupported("mnemonic"))));
    }
}
