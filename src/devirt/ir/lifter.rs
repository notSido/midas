//! iced-x86 → devirt IR lifter.
//!
//! Consumes a single `iced_x86::Instruction` and returns the `Effect`s it
//! would produce. Scope after M3.5:
//!
//! - **GPRs at all widths.** 8/16/32/64-bit operands. Narrower writes are
//!   modelled explicitly: `mov al, X` lifts as a blend — the full
//!   register is rewritten to preserve the untouched upper bits. 32-bit
//!   writes on x86-64 zero-extend, which we emit as a mask.
//! - **Status flags.** SF and ZF are modelled as pseudo-registers
//!   (`Flag::SF`, `Flag::ZF`); arithmetic and logic ops set them via
//!   `SetFlag(ZF, Eq(result, 0))` and `SetFlag(SF, sign_bit(result))`.
//!   CF/OF/PF/AF are not yet modelled — the simplifier can drop dead
//!   flag writes later, so over-emitting is wasteful.
//! - **`cmp` and `test`** are lifted as `sub` / `and` that discard the
//!   numeric result but update flags.
//! - **`jcc` and `jmp`** lift to an `Effect::Branch { cond, target }`
//!   descriptor (not executed at lift time). Condition codes handled:
//!   `je, jne, js, jns` (only the flags we model). Unconditional `jmp`
//!   near-branches lift with `cond: Const(1)`.
//! - **Memory addressing** is still `[base]` or `[base + disp32]`.
//!   Scaled-index, RIP-relative, and segment-overridden forms return
//!   `Unsupported` — not common in Themida VM handler bodies.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::expr::{Effect, Expr, Flag};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftError {
    Unsupported(&'static str),
    BadOperand(&'static str),
}

pub fn lift_instruction(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    match insn.mnemonic() {
        Mnemonic::Mov => lift_mov(insn),

        Mnemonic::Add => lift_arith(insn, ArithKind::Add),
        Mnemonic::Sub => lift_arith(insn, ArithKind::Sub),

        Mnemonic::And => lift_logic(insn, LogicKind::And),
        Mnemonic::Or => lift_logic(insn, LogicKind::Or),
        Mnemonic::Xor => lift_logic(insn, LogicKind::Xor),

        Mnemonic::Shl => lift_shift(insn, ShiftKind::Shl),
        Mnemonic::Shr => lift_shift(insn, ShiftKind::Shr),

        Mnemonic::Not => lift_not(insn),
        Mnemonic::Neg => lift_neg(insn),

        Mnemonic::Cmp => lift_cmp(insn),
        Mnemonic::Test => lift_test(insn),

        Mnemonic::Inc => lift_inc_dec(insn, IncDec::Inc),
        Mnemonic::Dec => lift_inc_dec(insn, IncDec::Dec),
        Mnemonic::Lea => lift_lea(insn),
        Mnemonic::Movzx => lift_movzx(insn),
        Mnemonic::Movsxd => lift_movsxd(insn),
        Mnemonic::Push => lift_push(insn),
        Mnemonic::Pop => lift_pop(insn),

        Mnemonic::Je | Mnemonic::Jne | Mnemonic::Js | Mnemonic::Jns => lift_jcc(insn),
        Mnemonic::Jmp => lift_jmp_unconditional(insn),

        _ => Err(LiftError::Unsupported("mnemonic")),
    }
}

// --------------------------------------------------------------------------
// Core mnemonic handlers
// --------------------------------------------------------------------------

#[derive(Copy, Clone)]
enum ArithKind {
    Add,
    Sub,
}
#[derive(Copy, Clone)]
enum LogicKind {
    And,
    Or,
    Xor,
}
#[derive(Copy, Clone)]
enum ShiftKind {
    Shl,
    Shr,
}

fn lift_mov(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let width_bits = op_width_bits(insn, 0)?;
    let src = lift_read_operand(insn, 1, width_bits)?;
    write_dst(insn, src, width_bits)
}

fn lift_arith(insn: &Instruction, kind: ArithKind) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let width_bits = op_width_bits(insn, 0)?;
    let lhs = lift_read_operand(insn, 0, width_bits)?;
    let rhs = lift_read_operand(insn, 1, width_bits)?;
    let raw = match kind {
        ArithKind::Add => Expr::add(lhs, rhs),
        ArithKind::Sub => Expr::sub(lhs, rhs),
    };
    let mut effects = write_dst(insn, raw.clone(), width_bits)?;
    emit_zf_sf(&mut effects, raw, width_bits);
    Ok(effects)
}

fn lift_logic(insn: &Instruction, kind: LogicKind) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let width_bits = op_width_bits(insn, 0)?;
    let lhs = lift_read_operand(insn, 0, width_bits)?;
    let rhs = lift_read_operand(insn, 1, width_bits)?;
    let raw = match kind {
        LogicKind::And => Expr::and(lhs, rhs),
        LogicKind::Or => Expr::or(lhs, rhs),
        LogicKind::Xor => Expr::xor(lhs, rhs),
    };
    let mut effects = write_dst(insn, raw.clone(), width_bits)?;
    emit_zf_sf(&mut effects, raw, width_bits);
    Ok(effects)
}

fn lift_shift(insn: &Instruction, kind: ShiftKind) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let width_bits = op_width_bits(insn, 0)?;
    let lhs = lift_read_operand(insn, 0, width_bits)?;
    let rhs = lift_shift_count(insn)?;
    let raw = match kind {
        ShiftKind::Shl => Expr::shl(lhs, rhs),
        ShiftKind::Shr => Expr::shr(lhs, rhs),
    };
    // Flags for shifts are count-dependent (CF = last bit shifted out),
    // which is hard to express cleanly without a count-0 special case.
    // Skip emitting flag effects for shifts in this cut; they're rarely
    // the input to a branch condition inside a Themida handler.
    write_dst(insn, raw, width_bits)
}

fn lift_not(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 1)?;
    let width_bits = op_width_bits(insn, 0)?;
    let v = lift_read_operand(insn, 0, width_bits)?;
    write_dst(insn, Expr::not(v), width_bits)
}

fn lift_neg(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 1)?;
    let width_bits = op_width_bits(insn, 0)?;
    let v = lift_read_operand(insn, 0, width_bits)?;
    let raw = Expr::neg(v);
    let mut effects = write_dst(insn, raw.clone(), width_bits)?;
    emit_zf_sf(&mut effects, raw, width_bits);
    Ok(effects)
}

fn lift_cmp(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let width_bits = op_width_bits(insn, 0)?;
    let lhs = lift_read_operand(insn, 0, width_bits)?;
    let rhs = lift_read_operand(insn, 1, width_bits)?;
    let raw = Expr::sub(lhs, rhs);
    let mut effects = Vec::new();
    emit_zf_sf(&mut effects, raw, width_bits);
    Ok(effects)
}

fn lift_test(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let width_bits = op_width_bits(insn, 0)?;
    let lhs = lift_read_operand(insn, 0, width_bits)?;
    let rhs = lift_read_operand(insn, 1, width_bits)?;
    let raw = Expr::and(lhs, rhs);
    let mut effects = Vec::new();
    emit_zf_sf(&mut effects, raw, width_bits);
    Ok(effects)
}

#[derive(Copy, Clone)]
enum IncDec {
    Inc,
    Dec,
}

fn lift_inc_dec(insn: &Instruction, kind: IncDec) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 1)?;
    let width_bits = op_width_bits(insn, 0)?;
    let v = lift_read_operand(insn, 0, width_bits)?;
    // inc/dec set ZF/SF/OF/AF/PF but deliberately leave CF alone. We
    // model ZF/SF; CF is preserved naturally by not emitting a SetFlag
    // for it, matching the hardware.
    let raw = match kind {
        IncDec::Inc => Expr::add(v, Expr::Const(1)),
        IncDec::Dec => Expr::sub(v, Expr::Const(1)),
    };
    let mut effects = write_dst(insn, raw.clone(), width_bits)?;
    emit_zf_sf(&mut effects, raw, width_bits);
    Ok(effects)
}

fn lift_lea(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    // op1 must be memory; op0 is the destination register.
    if insn.op_kind(1) != OpKind::Memory {
        return Err(LiftError::BadOperand("lea source not memory"));
    }
    let addr = lift_mem_addr(insn)?;
    let width_bits = op_width_bits(insn, 0)?;
    // 32-bit dst zero-extends; 16/8-bit dst blends — handled inside
    // `write_dst` via `partial_reg_write`.
    write_dst(insn, addr, width_bits)
}

fn lift_movzx(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let dst_width = op_width_bits(insn, 0)?;
    // Source width is deliberately distinct from dst width for movzx.
    // Read the source at its own width; the resulting `Expr` is already
    // zero-extended to a 64-bit value by our read helpers (partial-reg
    // reads mask to width; memory loads zero-extend natively).
    let src_width = match insn.op_kind(1) {
        OpKind::Register => {
            let r = insn.op_register(1);
            if !r.is_gpr() {
                return Err(LiftError::Unsupported("movzx non-GPR src"));
            }
            (r.size() as u8) * 8
        }
        OpKind::Memory => {
            let sz = insn.memory_size().size();
            match sz {
                1 | 2 => (sz as u8) * 8,
                _ => return Err(LiftError::Unsupported("movzx unusual mem src size")),
            }
        }
        _ => return Err(LiftError::Unsupported("movzx src kind")),
    };
    let src = lift_read_operand(insn, 1, src_width)?;
    write_dst(insn, src, dst_width)
}

fn lift_movsxd(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    require_op_count(insn, 2)?;
    let dst_width = op_width_bits(insn, 0)?;
    if dst_width != 64 {
        // MOVSXD has only one canonical form in x86-64: 64-bit dst
        // from 32-bit src. The 16-bit dst encoding is legal but
        // vanishingly rare in Themida dispatchers; reject cleanly.
        return Err(LiftError::Unsupported("movsxd non-64-bit dst"));
    }
    // Source width is always 32 for movsxd; read with that width so
    // `lift_read_operand` masks to the low 32 bits before we sign-
    // extend explicitly here.
    let src = lift_read_operand(insn, 1, 32)?;
    // Sign-extend 32 -> 64:
    //   sign_bit = (src >> 31) & 1          (0 or 1)
    //   ext     = (~~(-sign_bit)) << 32     (0 or 0xffff_ffff_0000_0000)
    //   result  = ext | src
    // The `Neg` pulls 1 up to u64::MAX (two's complement); shifting
    // by 32 isolates that into the upper 32 bits.
    let sign_bit = Expr::and(Expr::shr(src.clone(), Expr::Const(31)), Expr::Const(1));
    let ext = Expr::shl(Expr::neg(sign_bit), Expr::Const(32));
    let value = Expr::or(ext, src);
    write_dst(insn, value, dst_width)
}

fn lift_push(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    // 64-bit push only. `stack_pointer_increment` is -8 for the default
    // long-mode push; -2 with an operand-size prefix (rare enough to
    // reject here).
    if insn.stack_pointer_increment() != -8 {
        return Err(LiftError::Unsupported("non-64-bit push"));
    }
    let value = lift_read_operand(insn, 0, 64)?;
    // Effects both reference the *pre-instruction* RSP — the convention
    // used everywhere else in the lifter, letting the consumer sequence
    // effects across instructions without worrying about intra-insn
    // ordering. The MemStore lands at RSP-8 (the final RSP); the SetReg
    // advances RSP by the same amount.
    let new_rsp = Expr::sub(Expr::Reg(Register::RSP), Expr::Const(8));
    Ok(vec![
        Effect::MemStore {
            addr: new_rsp.clone(),
            value,
            size: 8,
        },
        Effect::SetReg(Register::RSP, new_rsp),
    ])
}

fn lift_pop(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    if insn.stack_pointer_increment() != 8 {
        return Err(LiftError::Unsupported("non-64-bit pop"));
    }
    // `pop rsp` is legal but the two effects in our flat model both
    // target RSP — the ordering semantics would be ambiguous without a
    // sequential execution model. Skip it; Themida handlers don't use it.
    if insn.op0_kind() == OpKind::Register && insn.op0_register() == Register::RSP {
        return Err(LiftError::Unsupported("pop rsp"));
    }
    let loaded = Expr::MemLoad {
        addr: Box::new(Expr::Reg(Register::RSP)),
        size: 8,
    };
    let mut effects = write_dst(insn, loaded, 64)?;
    effects.push(Effect::SetReg(
        Register::RSP,
        Expr::add(Expr::Reg(Register::RSP), Expr::Const(8)),
    ));
    Ok(effects)
}

fn lift_jcc(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    let target = require_near_branch_target(insn)?;
    let cond = match insn.mnemonic() {
        Mnemonic::Je => Expr::eq(Expr::Flag(Flag::ZF), Expr::Const(1)),
        Mnemonic::Jne => Expr::eq(Expr::Flag(Flag::ZF), Expr::Const(0)),
        Mnemonic::Js => Expr::eq(Expr::Flag(Flag::SF), Expr::Const(1)),
        Mnemonic::Jns => Expr::eq(Expr::Flag(Flag::SF), Expr::Const(0)),
        _ => return Err(LiftError::Unsupported("jcc condition")),
    };
    Ok(vec![Effect::Branch { cond, target }])
}

fn lift_jmp_unconditional(insn: &Instruction) -> Result<Vec<Effect>, LiftError> {
    // Only near jumps with a static target; indirect `jmp reg` / `jmp
    // [mem]` don't have one.
    match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target = insn.near_branch_target();
            Ok(vec![Effect::Branch {
                cond: Expr::Const(1),
                target,
            }])
        }
        _ => Err(LiftError::Unsupported("indirect jmp")),
    }
}

// --------------------------------------------------------------------------
// Operand reading / dst writing
// --------------------------------------------------------------------------

fn lift_read_operand(
    insn: &Instruction,
    idx: u32,
    width_bits: u8,
) -> Result<Expr, LiftError> {
    match insn.op_kind(idx) {
        OpKind::Register => {
            let r = insn.op_register(idx);
            let (full, shift, r_width) = gpr_info(r)?;
            if r_width != width_bits {
                return Err(LiftError::BadOperand("operand width mismatch"));
            }
            Ok(partial_reg_read(full, shift, r_width))
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            let raw = insn.immediate(idx);
            Ok(Expr::Const(mask_const(raw, width_bits)))
        }
        OpKind::Memory => {
            let addr = lift_mem_addr(insn)?;
            let size = width_bits / 8;
            if !matches!(size, 1 | 2 | 4 | 8) {
                return Err(LiftError::Unsupported("unusual memory access size"));
            }
            Ok(Expr::MemLoad {
                addr: Box::new(addr),
                size,
            })
        }
        _ => Err(LiftError::Unsupported("source operand kind")),
    }
}

fn write_dst(
    insn: &Instruction,
    value: Expr,
    width_bits: u8,
) -> Result<Vec<Effect>, LiftError> {
    match insn.op0_kind() {
        OpKind::Register => {
            let r = insn.op0_register();
            let (full, shift, r_width) = gpr_info(r)?;
            if r_width != width_bits {
                return Err(LiftError::BadOperand("dst width mismatch"));
            }
            let stored = partial_reg_write(full, shift, r_width, value);
            Ok(vec![Effect::SetReg(full, stored)])
        }
        OpKind::Memory => {
            let addr = lift_mem_addr(insn)?;
            let size = width_bits / 8;
            if !matches!(size, 1 | 2 | 4 | 8) {
                return Err(LiftError::Unsupported("unusual memory store size"));
            }
            Ok(vec![Effect::MemStore { addr, value, size }])
        }
        _ => Err(LiftError::Unsupported("dst operand kind")),
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
            let (full, shift, width) = gpr_info(base)?;
            if width != 64 || shift != 0 {
                return Err(LiftError::Unsupported("non-64-bit memory base"));
            }
            if disp == 0 {
                Ok(Expr::Reg(full))
            } else {
                Ok(Expr::add(Expr::Reg(full), Expr::Const(disp)))
            }
        }
    }
}

/// Read the shift-count operand of `shl`/`shr`. Always treated as the
/// low 8 bits of `CL` (for the `*, cl` form) or of the 8-bit immediate.
fn lift_shift_count(insn: &Instruction) -> Result<Expr, LiftError> {
    match insn.op_kind(1) {
        OpKind::Register => {
            let r = insn.op_register(1);
            if r != Register::CL {
                return Err(LiftError::Unsupported("shift count register != CL"));
            }
            Ok(Expr::and(Expr::Reg(Register::RCX), Expr::Const(0xff)))
        }
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64 => Ok(Expr::Const(insn.immediate(1) & 0xff)),
        _ => Err(LiftError::Unsupported("shift count kind")),
    }
}

// --------------------------------------------------------------------------
// Partial-register read / write helpers
// --------------------------------------------------------------------------

/// Decompose a GPR into `(full_register, bit_shift, width_bits)`. The
/// bit-shift is 8 for the high-byte aliases `AH/BH/CH/DH` and 0
/// otherwise.
fn gpr_info(r: Register) -> Result<(Register, u8, u8), LiftError> {
    if !r.is_gpr() {
        return Err(LiftError::Unsupported("non-GPR operand"));
    }
    let width_bits = (r.size() as u8) * 8;
    let full = r.full_register();
    let shift = match r {
        Register::AH | Register::BH | Register::CH | Register::DH => 8,
        _ => 0,
    };
    Ok((full, shift, width_bits))
}

/// Read the narrow view of `full` at `[shift .. shift+width_bits)`. For
/// `width_bits == 64` this is just `Reg(full)`.
fn partial_reg_read(full: Register, shift: u8, width_bits: u8) -> Expr {
    if width_bits == 64 {
        return Expr::Reg(full);
    }
    let mask = (1u64 << width_bits) - 1;
    let base = if shift == 0 {
        Expr::Reg(full)
    } else {
        Expr::shr(Expr::Reg(full), Expr::Const(shift as u64))
    };
    Expr::and(base, Expr::Const(mask))
}

/// Produce the post-write full-register value when a narrow write of
/// `value` lands at `[shift .. shift+width_bits)` of `full`.
///
/// - 64-bit write: just `value`, unchanged.
/// - 32-bit write (shift 0): zero-extend — upper 32 bits become zero
///   per the x86-64 ISA rule.
/// - Otherwise: blend — keep the bits of `Reg(full)` outside the
///   written window, replace the bits inside with the low `width_bits`
///   of `value`.
fn partial_reg_write(full: Register, shift: u8, width_bits: u8, value: Expr) -> Expr {
    if width_bits == 64 {
        return value;
    }
    if width_bits == 32 && shift == 0 {
        return Expr::and(value, Expr::Const(0xffff_ffff));
    }
    let mask = (1u64 << width_bits) - 1;
    let keep_mask = !(mask << shift);
    let keep = Expr::and(Expr::Reg(full), Expr::Const(keep_mask));
    let masked_val = Expr::and(value, Expr::Const(mask));
    let shifted = if shift == 0 {
        masked_val
    } else {
        Expr::shl(masked_val, Expr::Const(shift as u64))
    };
    Expr::or(keep, shifted)
}

// --------------------------------------------------------------------------
// Flag helpers
// --------------------------------------------------------------------------

/// Push `SetFlag(ZF)` and `SetFlag(SF)` onto `effects` for an arithmetic
/// or logic result expression of width `width_bits`. Other flags
/// (CF/OF/PF/AF) are not yet modelled — the simplifier can prune dead
/// flag writes, so under-emitting is the safer default.
fn emit_zf_sf(effects: &mut Vec<Effect>, raw_result: Expr, width_bits: u8) {
    let masked = mask_to_width(raw_result, width_bits);
    effects.push(Effect::SetFlag(
        Flag::ZF,
        Expr::eq(masked.clone(), Expr::Const(0)),
    ));
    effects.push(Effect::SetFlag(Flag::SF, sign_bit_expr(masked, width_bits)));
}

fn mask_to_width(val: Expr, width_bits: u8) -> Expr {
    if width_bits == 64 {
        val
    } else {
        let mask = (1u64 << width_bits) - 1;
        Expr::and(val, Expr::Const(mask))
    }
}

fn sign_bit_expr(val: Expr, width_bits: u8) -> Expr {
    let shifted = Expr::shr(val, Expr::Const((width_bits - 1) as u64));
    Expr::and(shifted, Expr::Const(1))
}

fn mask_const(v: u64, width_bits: u8) -> u64 {
    if width_bits == 64 {
        v
    } else {
        v & ((1u64 << width_bits) - 1)
    }
}

// --------------------------------------------------------------------------
// Small glue
// --------------------------------------------------------------------------

fn op_width_bits(insn: &Instruction, idx: u32) -> Result<u8, LiftError> {
    match insn.op_kind(idx) {
        OpKind::Register => {
            let r = insn.op_register(idx);
            if !r.is_gpr() {
                return Err(LiftError::Unsupported("non-GPR operand"));
            }
            Ok((r.size() as u8) * 8)
        }
        OpKind::Memory => {
            let sz = insn.memory_size().size();
            match sz {
                1 | 2 | 4 | 8 => Ok((sz as u8) * 8),
                _ => Err(LiftError::Unsupported("unusual memory access size")),
            }
        }
        _ => Err(LiftError::Unsupported("operand kind for width probe")),
    }
}

fn require_op_count(insn: &Instruction, want: u32) -> Result<(), LiftError> {
    if insn.op_count() == want {
        Ok(())
    } else {
        Err(LiftError::BadOperand("unexpected op_count"))
    }
}

fn require_near_branch_target(insn: &Instruction) -> Result<u64, LiftError> {
    match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Ok(insn.near_branch_target())
        }
        _ => Err(LiftError::Unsupported("non-near-branch target")),
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_one(bytes: &[u8]) -> Instruction {
        decode_one_at(bytes, 0x1000)
    }

    fn decode_one_at(bytes: &[u8], ip: u64) -> Instruction {
        let mut dec = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        dec.decode()
    }

    #[test]
    fn lift_mov_reg_reg() {
        // mov rax, rbx   (48 89 d8)
        let insn = decode_one(&[0x48, 0x89, 0xD8]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![Effect::SetReg(Register::RAX, Expr::Reg(Register::RBX))]
        );
    }

    #[test]
    fn lift_xor_reg_reg() {
        // xor rax, rsi   (48 31 f0)  — sets ZF/SF in addition to SetReg.
        let insn = decode_one(&[0x48, 0x31, 0xF0]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(effs.len(), 3);
        assert_eq!(
            effs[0],
            Effect::SetReg(
                Register::RAX,
                Expr::xor(Expr::Reg(Register::RAX), Expr::Reg(Register::RSI))
            )
        );
        assert!(matches!(effs[1], Effect::SetFlag(Flag::ZF, _)));
        assert!(matches!(effs[2], Effect::SetFlag(Flag::SF, _)));
    }

    #[test]
    fn lift_and_reg_imm() {
        // and r11, 0x20 via REX+and r/m64, imm8 sign-extended (49 83 e3 20).
        let insn = decode_one(&[0x49, 0x83, 0xE3, 0x20]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs[0],
            Effect::SetReg(
                Register::R11,
                Expr::and(Expr::Reg(Register::R11), Expr::Const(0x20))
            )
        );
    }

    #[test]
    fn lift_add_reg_reg() {
        // add rdx, r8    (4c 01 c2)
        let insn = decode_one(&[0x4C, 0x01, 0xC2]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs[0],
            Effect::SetReg(
                Register::RDX,
                Expr::add(Expr::Reg(Register::RDX), Expr::Reg(Register::R8))
            )
        );
    }

    #[test]
    fn lift_narrow_mov_blends() {
        // mov al, 0x10   (b0 10)
        let insn = decode_one(&[0xB0, 0x10]);
        let effs = lift_instruction(&insn).unwrap();
        // Expected: SetReg(RAX, (RAX & 0xffff...00) | (0x10 & 0xff)).
        assert_eq!(effs.len(), 1);
        let want = Effect::SetReg(
            Register::RAX,
            Expr::or(
                Expr::and(
                    Expr::Reg(Register::RAX),
                    Expr::Const(0xffff_ffff_ffff_ff00),
                ),
                Expr::and(Expr::Const(0x10), Expr::Const(0xff)),
            ),
        );
        assert_eq!(effs[0], want);
    }

    #[test]
    fn lift_narrow_sub_to_blend_with_flags() {
        // sub r11b, 0EEh    (41 80 eb ee)
        let insn = decode_one(&[0x41, 0x80, 0xEB, 0xEE]);
        let effs = lift_instruction(&insn).unwrap();
        // Three effects: SetReg(R11, blend), SetFlag(ZF), SetFlag(SF).
        assert_eq!(effs.len(), 3);
        match &effs[0] {
            Effect::SetReg(Register::R11, _) => {}
            other => panic!("unexpected dst effect: {:?}", other),
        }
        assert!(matches!(effs[1], Effect::SetFlag(Flag::ZF, _)));
        assert!(matches!(effs[2], Effect::SetFlag(Flag::SF, _)));
    }

    #[test]
    fn lift_mov_eax_zero_extends() {
        // mov eax, 0x12345678   (b8 78 56 34 12)
        let insn = decode_one(&[0xB8, 0x78, 0x56, 0x34, 0x12]);
        let effs = lift_instruction(&insn).unwrap();
        // Expected: SetReg(RAX, 0x12345678 & 0xffff_ffff).
        let want = Effect::SetReg(
            Register::RAX,
            Expr::and(Expr::Const(0x1234_5678), Expr::Const(0xffff_ffff)),
        );
        assert_eq!(effs, vec![want]);
    }

    #[test]
    fn lift_cmp_then_jne_descriptor() {
        // cmp r11b, 0     (41 80 fb 00)       at IP 0x1000
        // jne +2 (target 0x1008)              (75 02)     at IP 0x1004
        let cmp = decode_one_at(&[0x41, 0x80, 0xFB, 0x00], 0x1000);
        let jne = decode_one_at(&[0x75, 0x02], 0x1004);

        let cmp_effs = lift_instruction(&cmp).unwrap();
        // cmp writes no register / memory; only flags.
        assert_eq!(cmp_effs.len(), 2);
        assert!(matches!(cmp_effs[0], Effect::SetFlag(Flag::ZF, _)));
        assert!(matches!(cmp_effs[1], Effect::SetFlag(Flag::SF, _)));

        let jne_effs = lift_instruction(&jne).unwrap();
        assert_eq!(
            jne_effs,
            vec![Effect::Branch {
                cond: Expr::eq(Expr::Flag(Flag::ZF), Expr::Const(0)),
                target: 0x1008,
            }]
        );
    }

    #[test]
    fn lift_unknown_mnemonic_is_unsupported() {
        // nop — we don't handle it yet.
        let insn = decode_one(&[0x90]);
        assert!(matches!(
            lift_instruction(&insn),
            Err(LiftError::Unsupported("mnemonic"))
        ));
    }

    #[test]
    fn lift_push_reg() {
        // push r9   (41 51)
        let insn = decode_one(&[0x41, 0x51]);
        let effs = lift_instruction(&insn).unwrap();
        let new_rsp = Expr::sub(Expr::Reg(Register::RSP), Expr::Const(8));
        assert_eq!(
            effs,
            vec![
                Effect::MemStore {
                    addr: new_rsp.clone(),
                    value: Expr::Reg(Register::R9),
                    size: 8,
                },
                Effect::SetReg(Register::RSP, new_rsp),
            ]
        );
    }

    #[test]
    fn lift_pop_reg() {
        // pop r9    (41 59)
        let insn = decode_one(&[0x41, 0x59]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![
                Effect::SetReg(
                    Register::R9,
                    Expr::MemLoad {
                        addr: Box::new(Expr::Reg(Register::RSP)),
                        size: 8,
                    }
                ),
                Effect::SetReg(
                    Register::RSP,
                    Expr::add(Expr::Reg(Register::RSP), Expr::Const(8))
                ),
            ]
        );
    }

    #[test]
    fn lift_inc_rax_sets_flags() {
        // inc rax   (48 ff c0)
        let insn = decode_one(&[0x48, 0xFF, 0xC0]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(effs.len(), 3);
        assert_eq!(
            effs[0],
            Effect::SetReg(
                Register::RAX,
                Expr::add(Expr::Reg(Register::RAX), Expr::Const(1))
            )
        );
        assert!(matches!(effs[1], Effect::SetFlag(Flag::ZF, _)));
        assert!(matches!(effs[2], Effect::SetFlag(Flag::SF, _)));
    }

    #[test]
    fn lift_lea_base_plus_disp() {
        // lea rax, [rbx + 0x10]   (48 8d 43 10)
        let insn = decode_one(&[0x48, 0x8D, 0x43, 0x10]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![Effect::SetReg(
                Register::RAX,
                Expr::add(Expr::Reg(Register::RBX), Expr::Const(0x10))
            )]
        );
    }

    #[test]
    fn lift_movzx_reg_mem_byte() {
        // movzx rsi, byte ptr [rsi]   (48 0f b6 36)
        let insn = decode_one(&[0x48, 0x0F, 0xB6, 0x36]);
        let effs = lift_instruction(&insn).unwrap();
        assert_eq!(
            effs,
            vec![Effect::SetReg(
                Register::RSI,
                Expr::MemLoad {
                    addr: Box::new(Expr::Reg(Register::RSI)),
                    size: 1,
                }
            )]
        );
    }
}
