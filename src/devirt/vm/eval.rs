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
use super::super::trace_events::{MemSnapshot, RegSnapshot};

pub struct EvalState<'a> {
    regs: HashMap<Register, u64>,
    flags: HashMap<Flag, u64>,
    /// Byte-level overlay on top of `dump` — memory stores go here,
    /// memory reads consult this first before falling back to other
    /// sources.
    mem_overlay: HashMap<u64, u8>,
    /// Captured memory slices from the trace (e.g. the RBP-window
    /// snapshot recorded alongside each RegsAtRip event). Consulted
    /// after the overlay, before the OEP dump. Sorted by base_va for
    /// binary-searchable lookup.
    mem_snapshots: Vec<MemSnapshot>,
    dump: &'a OepDump,
}

impl<'a> EvalState<'a> {
    /// Seed register state from a `RegSnapshot`, flags empty, no
    /// memory overlay yet. Attach an optional live-memory snapshot
    /// captured at the same tick; consulted before the OEP dump.
    pub fn from_snapshot(
        regs: &RegSnapshot,
        dump: &'a OepDump,
        mem: Option<&MemSnapshot>,
    ) -> Self {
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
        let mem_snapshots = mem.cloned().into_iter().collect::<Vec<_>>();
        Self {
            regs: m,
            flags: HashMap::new(),
            mem_overlay: HashMap::new(),
            mem_snapshots,
            dump,
        }
    }

    /// Attach an additional captured memory slice. Used when the
    /// evaluator is seeded from one capture but has access to more
    /// snapshots from the trace (e.g. the dispatch-site capture
    /// supplements the fetch-site capture).
    pub fn add_mem_snapshot(&mut self, snap: MemSnapshot) {
        self.mem_snapshots.push(snap);
    }

    /// Overwrite the current register state with values from
    /// `regs`. Flags are cleared; memory overlay untouched.
    pub fn restore_gprs(&mut self, regs: &RegSnapshot) {
        self.set_reg(Register::RAX, regs.rax);
        self.set_reg(Register::RBX, regs.rbx);
        self.set_reg(Register::RCX, regs.rcx);
        self.set_reg(Register::RDX, regs.rdx);
        self.set_reg(Register::RSI, regs.rsi);
        self.set_reg(Register::RDI, regs.rdi);
        self.set_reg(Register::RBP, regs.rbp);
        self.set_reg(Register::RSP, regs.rsp);
        self.set_reg(Register::R8, regs.r8);
        self.set_reg(Register::R9, regs.r9);
        self.set_reg(Register::R10, regs.r10);
        self.set_reg(Register::R11, regs.r11);
        self.set_reg(Register::R12, regs.r12);
        self.set_reg(Register::R13, regs.r13);
        self.set_reg(Register::R14, regs.r14);
        self.set_reg(Register::R15, regs.r15);
        self.set_reg(Register::RIP, regs.rip);
        self.flags.clear();
    }

    /// Dump the current register state to a `RegSnapshot`. Missing
    /// registers default to 0 (they haven't been written).
    pub fn gpr_snapshot(&self) -> RegSnapshot {
        let g = |r: Register| self.reg(r).unwrap_or(0);
        RegSnapshot {
            rax: g(Register::RAX),
            rbx: g(Register::RBX),
            rcx: g(Register::RCX),
            rdx: g(Register::RDX),
            rsi: g(Register::RSI),
            rdi: g(Register::RDI),
            rbp: g(Register::RBP),
            rsp: g(Register::RSP),
            r8: g(Register::R8),
            r9: g(Register::R9),
            r10: g(Register::R10),
            r11: g(Register::R11),
            r12: g(Register::R12),
            r13: g(Register::R13),
            r14: g(Register::R14),
            r15: g(Register::R15),
            rip: g(Register::RIP),
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
            let b = self.read_byte(byte_addr)?;
            val |= (b as u64) << (8 * i);
        }
        Some(val)
    }

    fn read_byte(&self, addr: u64) -> Option<u8> {
        if let Some(b) = self.mem_overlay.get(&addr) {
            return Some(*b);
        }
        // Live memory from a captured snapshot (most specific source
        // of truth for cells the VM mutated during init).
        for snap in &self.mem_snapshots {
            if addr >= snap.base_va {
                let off = (addr - snap.base_va) as usize;
                if off < snap.bytes.len() {
                    return Some(snap.bytes[off]);
                }
            }
        }
        // Fallback: OEP-dumped PE. Still the right source for static
        // data (handler table, bytecode stream, .text).
        self.dump.read_bytes_at_va(addr, 1).map(|s| s[0])
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

/// One step of iterative bytecode-walking: values observed at the
/// moment the dispatcher is about to transfer control to a handler.
#[derive(Debug, Clone)]
pub struct WalkStep {
    /// 0-based iteration count (0 = first dispatch after the seed).
    pub iter: usize,
    /// VM_PC read from the VM state cell *before* this iteration's
    /// dispatcher evaluation — i.e. the bytecode-stream offset of
    /// the VM instruction about to fire.
    pub vm_pc: u64,
    /// Handler address the dispatcher computed (= value of the jmp
    /// target register after evaluation).
    pub handler_addr: u64,
    /// Snapshot of all 16 GPRs at the moment of dispatch. Captures
    /// everything downstream might want: the decrypted opcode lives
    /// in whatever register the dispatcher shifted+indexed (usually
    /// R11 for sample 2, R15 for sample 1). Not sample-specific in
    /// the walker; the caller inspects per descriptor if needed.
    pub gprs_at_dispatch: crate::devirt::trace_events::RegSnapshot,
}

/// Iterate the VM dispatcher forward, simulating bytecode execution
/// offline. Each iteration re-evaluates the dispatcher slice
/// (`dispatcher_start_rip ..= dispatch_rip`); state carries forward
/// via the mem overlay (VM_PC and rolling key cells the dispatcher
/// mutates).
///
/// Stops early on evaluator failure, when VM_PC repeats (loop), or
/// after `max_iters`. Returns the sequence of `(vm_pc, handler)`
/// observed — one entry per successful iteration.
///
/// The caller must have already seeded `state` with the fetch-site
/// register snapshot AND the corresponding mem-snapshot so the VM
/// state cells are live.
pub fn walk_bytecode<I>(
    state: &mut EvalState,
    instructions: &I,
    dispatcher_start_rip: u64,
    dispatch_rip: u64,
    vm_pc_cell_addr: u64,
    dispatch_target_reg: Register,
    max_iters: usize,
) -> Vec<WalkStep>
where
    I: InstructionMap,
{
    // Snapshot the seed register state so we can reset to it at the
    // start of every iteration. The dispatcher prelude re-initializes
    // the registers it uses, but any dispatcher that reads a
    // register not covered by its prelude would otherwise inherit
    // stale values from the previous iteration. Resetting is
    // defensive: correctness comes from the memory overlay, which we
    // deliberately let carry forward.
    let seed_regs = state.gpr_snapshot();
    let mut out = Vec::new();
    let mut seen_vm_pc: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for iter in 0..max_iters {
        if iter > 0 {
            // Restore GPRs to the seed state; memory overlay (and
            // thus VM_PC cell, rolling key cell, any other
            // dispatcher-written bytes) stays as the previous
            // iteration left it.
            state.restore_gprs(&seed_regs);
        }
        let Some(vm_pc) = state.read_mem(vm_pc_cell_addr, 8) else {
            break;
        };
        if !seen_vm_pc.insert(vm_pc) {
            break;
        }
        match evaluate_linear(state, instructions, dispatcher_start_rip, dispatch_rip) {
            EvalOutcome::Ok => {}
            _ => break,
        }
        let Some(handler_addr) = state.reg(dispatch_target_reg) else {
            break;
        };
        out.push(WalkStep {
            iter,
            vm_pc,
            handler_addr,
            gprs_at_dispatch: state.gpr_snapshot(),
        });
    }
    out
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
        let state = EvalState::from_snapshot(&snap, &dump, None);
        assert_eq!(state.eval(&Expr::Const(42)), Some(42));
    }

    #[test]
    fn eval_reg_from_snapshot() {
        let dump = dummy_dump();
        let snap = RegSnapshot {
            rbp: 0xdead_beef,
            ..Default::default()
        };
        let state = EvalState::from_snapshot(&snap, &dump, None);
        assert_eq!(state.eval(&Expr::Reg(Register::RBP)), Some(0xdead_beef));
    }

    #[test]
    fn eval_arithmetic_chain() {
        let dump = dummy_dump();
        let snap = RegSnapshot {
            rbp: 0x100,
            ..Default::default()
        };
        let state = EvalState::from_snapshot(&snap, &dump, None);
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
        let mut state = EvalState::from_snapshot(&snap, &dump, None);
        state.write_mem(0x1000, 0xdead_beef, 4);
        assert_eq!(state.read_mem(0x1000, 4), Some(0xdead_beef));
        assert_eq!(state.read_mem(0x1000, 1), Some(0xef));
        assert_eq!(state.read_mem(0x1003, 1), Some(0xde));
    }

    #[test]
    fn mem_snapshot_precedes_dump() {
        // Captured snapshot at base 0x2000 should shadow the dump.
        let dump = dummy_dump();
        let snap = RegSnapshot::default();
        let mem = MemSnapshot {
            base_va: 0x2000,
            bytes: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        let state = EvalState::from_snapshot(&snap, &dump, Some(&mem));
        // Read from the captured slice.
        assert_eq!(state.read_mem(0x2000, 1), Some(0xaa));
        assert_eq!(state.read_mem(0x2001, 2), Some(0xccbb));
        // Outside both the snapshot and the 512-byte synthetic
        // dump (image_base 0): read returns None.
        assert_eq!(state.read_mem(0x5000, 1), None);
    }
}
