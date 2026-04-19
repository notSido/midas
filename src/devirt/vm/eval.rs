//! Concrete evaluator for the devirt IR.
//!
//! Given a starting register state and an OEP dump for memory reads,
//! runs a `Vec<Effect>` forward, updating register / flag / memory
//! state. Used to statically evaluate the VM dispatcher from a
//! captured register snapshot to recover the decrypted opcode and
//! handler address for each VM bytecode record — replacing what
//! would otherwise require a second emulator run.
//!
//! Out-of-scope for this first cut:
//! - Control flow. `Effect::Branch` is ignored; the evaluator is
//!   linear. Dispatcher bodies are straight-line after opcode
//!   decrypt, so this works there. Handler bodies need full
//!   control-flow handling (future slice).
//! - Symbolic values. Everything is concrete `u64`s; if an input
//!   register isn't in the initial state or a memory read falls
//!   outside the dump, evaluation returns `None` and the caller
//!   decides what to do.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

use super::super::ir::expr::Flag;
use super::super::ir::{lift_instruction, Effect, Expr, LiftError};
use super::super::oep_dump::OepDump;
use super::super::trace_events::RegSnapshot;

pub struct EvalState<'a> {
    regs: HashMap<Register, u64>,
    flags: HashMap<Flag, u64>,
    /// Byte-level overlay on top of `dump` — memory stores go here,
    /// memory reads consult this first before falling back to the
    /// dump.
    mem_overlay: HashMap<u64, u8>,
    dump: &'a OepDump,
}

impl<'a> EvalState<'a> {
    /// Seed register state from a `RegSnapshot`, flags empty, no
    /// memory overlay yet.
    pub fn from_snapshot(regs: &RegSnapshot, dump: &'a OepDump) -> Self {
        let mut m: HashMap<Register, u64> = HashMap::new();
        m.insert(Register::RAX, regs.rax);
        m.insert(Register::RBX, regs.rbx);
        m.insert(Register::RCX, regs.rcx);
        m.insert(Register::RDX, regs.rdx);
        m.insert(Register::RSI, regs.rsi);
        m.insert(Register::RDI, regs.rdi);
        m.insert(Register::RBP, regs.rbp);
        m.insert(Register::RSP, regs.rsp);
        m.insert(Register::R8, regs.r8);
        m.insert(Register::R9, regs.r9);
        m.insert(Register::R10, regs.r10);
        m.insert(Register::R11, regs.r11);
        m.insert(Register::R12, regs.r12);
        m.insert(Register::R13, regs.r13);
        m.insert(Register::R14, regs.r14);
        m.insert(Register::R15, regs.r15);
        m.insert(Register::RIP, regs.rip);
        Self {
            regs: m,
            flags: HashMap::new(),
            mem_overlay: HashMap::new(),
            dump,
        }
    }

    pub fn reg(&self, r: Register) -> Option<u64> {
        self.regs.get(&r.full_register()).copied()
    }

    pub fn set_reg(&mut self, r: Register, v: u64) {
        self.regs.insert(r.full_register(), v);
    }

    pub fn read_mem(&self, addr: u64, size: u8) -> Option<u64> {
        let mut val: u64 = 0;
        for i in 0..size as u64 {
            let byte_addr = addr + i;
            let b = match self.mem_overlay.get(&byte_addr) {
                Some(b) => *b,
                None => self.dump.read_bytes_at_va(byte_addr, 1)?[0],
            };
            val |= (b as u64) << (8 * i);
        }
        Some(val)
    }

    pub fn write_mem(&mut self, addr: u64, value: u64, size: u8) {
        for i in 0..size as u64 {
            let b = ((value >> (8 * i)) & 0xff) as u8;
            self.mem_overlay.insert(addr + i, b);
        }
    }

    pub fn eval(&self, expr: &Expr) -> Option<u64> {
        match expr {
            Expr::Const(v) => Some(*v),
            Expr::Reg(r) => self.reg(*r),
            Expr::Flag(f) => self.flags.get(f).copied().or(Some(0)),
            Expr::MemLoad { addr, size } => {
                let a = self.eval(addr)?;
                self.read_mem(a, *size)
            }
            Expr::Add(a, b) => Some(self.eval(a)?.wrapping_add(self.eval(b)?)),
            Expr::Sub(a, b) => Some(self.eval(a)?.wrapping_sub(self.eval(b)?)),
            Expr::And(a, b) => Some(self.eval(a)? & self.eval(b)?),
            Expr::Or(a, b) => Some(self.eval(a)? | self.eval(b)?),
            Expr::Xor(a, b) => Some(self.eval(a)? ^ self.eval(b)?),
            Expr::Shl(a, b) => {
                let v = self.eval(a)?;
                let n = (self.eval(b)? & 63) as u32;
                Some(v.wrapping_shl(n))
            }
            Expr::Shr(a, b) => {
                let v = self.eval(a)?;
                let n = (self.eval(b)? & 63) as u32;
                Some(v.wrapping_shr(n))
            }
            Expr::Not(a) => Some(!self.eval(a)?),
            Expr::Neg(a) => Some(0u64.wrapping_sub(self.eval(a)?)),
            Expr::Eq(a, b) => Some(if self.eval(a)? == self.eval(b)? { 1 } else { 0 }),
        }
    }

    pub fn apply(&mut self, eff: &Effect) -> Option<()> {
        match eff {
            Effect::SetReg(r, v) => {
                let val = self.eval(v)?;
                self.set_reg(*r, val);
            }
            Effect::SetFlag(f, v) => {
                let val = self.eval(v)?;
                self.flags.insert(*f, val);
            }
            Effect::MemStore { addr, value, size } => {
                let a = self.eval(addr)?;
                let v = self.eval(value)?;
                self.write_mem(a, v, *size);
            }
            Effect::Branch { .. } => {
                // Linear evaluator — branches ignored. Dispatcher
                // bodies up to the final indirect jmp are straight-
                // line; if we hit a branch effect here it's usually
                // a cmp+jne inside a handler body we aren't trying
                // to execute.
            }
        }
        Some(())
    }
}

/// Outcome of evaluating a straight-line instruction range.
#[derive(Debug)]
pub enum EvalOutcome {
    /// Every instruction lifted and its effects applied successfully.
    Ok,
    /// An instruction didn't lift (hit a mnemonic or operand the
    /// current lifter doesn't support). Carries the offending
    /// instruction's RIP and the lifter's error.
    LiftFailure { rip: u64, err: LiftError },
    /// An effect's evaluation failed (unknown register, out-of-dump
    /// memory read). Carries the offending RIP.
    EvalFailure { rip: u64 },
}

/// Decode + lift + apply every instruction at `rips` (in ascending
/// order) against `state`. Stops early and reports the reason on the
/// first failure. RIPs are looked up in `instructions` as a
/// `(rip → bytes)` map — typically a slice of a trace.
pub fn evaluate_linear<'a, I>(
    state: &mut EvalState<'a>,
    instructions: &I,
    start_rip: u64,
    end_rip: u64,
) -> EvalOutcome
where
    I: InstructionMap,
{
    for (rip, bytes) in instructions.range_inclusive(start_rip, end_rip) {
        let mut dec = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
        let insn: Instruction = dec.decode();
        let effects = match lift_instruction(&insn) {
            Ok(e) => e,
            // Indirect `jmp r<reg>` is the expected terminator of a
            // dispatcher slice — it has no static target to lift, so
            // treat it as a clean end-of-evaluation. The caller can
            // read the jmp's target register out of state to get the
            // handler address.
            Err(LiftError::Unsupported("indirect jmp")) if rip == end_rip => {
                return EvalOutcome::Ok;
            }
            Err(err) => return EvalOutcome::LiftFailure { rip, err },
        };
        for eff in effects {
            if state.apply(&eff).is_none() {
                return EvalOutcome::EvalFailure { rip };
            }
        }
    }
    EvalOutcome::Ok
}

/// Abstraction so the evaluator doesn't hard-bind to `BTreeMap`.
/// Callers implement this over whatever instruction-store they have.
pub trait InstructionMap {
    fn range_inclusive<'b>(&'b self, start: u64, end: u64)
        -> Box<dyn Iterator<Item = (u64, &'b [u8])> + 'b>;
}

impl InstructionMap for std::collections::BTreeMap<u64, Vec<u8>> {
    fn range_inclusive<'b>(
        &'b self,
        start: u64,
        end: u64,
    ) -> Box<dyn Iterator<Item = (u64, &'b [u8])> + 'b> {
        Box::new(
            self.range(start..=end)
                .map(|(rip, bytes)| (*rip, bytes.as_slice())),
        )
    }
}

/// Retrieve the register targeted by a `jmp r<reg>` at `dispatch_rip`
/// in `instructions`. Returns `None` if the instruction at that RIP
/// isn't an indirect-register jmp.
pub fn dispatch_target_register(
    instructions: &std::collections::BTreeMap<u64, Vec<u8>>,
    dispatch_rip: u64,
) -> Option<Register> {
    let bytes = instructions.get(&dispatch_rip)?;
    let mut dec = Decoder::with_ip(64, bytes, dispatch_rip, DecoderOptions::NONE);
    let insn = dec.decode();
    if insn.mnemonic() != iced_x86::Mnemonic::Jmp {
        return None;
    }
    if insn.op0_kind() != OpKind::Register {
        return None;
    }
    Some(insn.op0_register())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_dump() -> OepDump {
        // Minimal valid PE32+ with ImageBase 0; writes into overlay
        // cover the rest.
        let mut v = vec![0u8; 0x200];
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x98..0x9A].copy_from_slice(&0x20bu16.to_le_bytes());
        OepDump::from_bytes(v).unwrap()
    }

    #[test]
    fn eval_const() {
        let dump = dummy_dump();
        let snap = RegSnapshot::default();
        let state = EvalState::from_snapshot(&snap, &dump);
        assert_eq!(state.eval(&Expr::Const(42)), Some(42));
    }

    #[test]
    fn eval_reg_from_snapshot() {
        let dump = dummy_dump();
        let snap = RegSnapshot {
            rbp: 0xdead_beef,
            ..Default::default()
        };
        let state = EvalState::from_snapshot(&snap, &dump);
        assert_eq!(state.eval(&Expr::Reg(Register::RBP)), Some(0xdead_beef));
    }

    #[test]
    fn eval_arithmetic_chain() {
        // (rbp + 0x9A) & 0xFF_FF simulates what the dispatcher's
        // decrypt-chain looks like at the bit level.
        let dump = dummy_dump();
        let snap = RegSnapshot {
            rbp: 0x100,
            ..Default::default()
        };
        let state = EvalState::from_snapshot(&snap, &dump);
        let e = Expr::and(
            Expr::add(Expr::Reg(Register::RBP), Expr::Const(0x9a)),
            Expr::Const(0xffff),
        );
        assert_eq!(state.eval(&e), Some(0x19a));
    }

    #[test]
    fn memstore_overlay_then_memload() {
        let dump = dummy_dump();
        let snap = RegSnapshot::default();
        let mut state = EvalState::from_snapshot(&snap, &dump);
        state.write_mem(0x1000, 0xdead_beef, 4);
        assert_eq!(state.read_mem(0x1000, 4), Some(0xdead_beef));
        // u8 slices of the same region should reflect the overlay.
        assert_eq!(state.read_mem(0x1000, 1), Some(0xef));
        assert_eq!(state.read_mem(0x1003, 1), Some(0xde));
    }
}
