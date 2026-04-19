//! Sample-agnostic VM-interpreter detector (M5 prep).
//!
//! Scans a collection of `(rip, bytes)` pairs (sourced either from a
//! recorded trace or an OEP-dumped `.text` region) for the canonical
//! Themida VM dispatcher pattern:
//!
//! ```text
//! mov  rX, rbp
//! add  rX, IMM                ; rX = rbp + vm_state_offset
//! ... (possibly more)
//! movzx rY, word ptr [...]    ; opcode fetch (encrypted)
//! ... (decrypt + handler-table lookup)
//! jmp  r<reg>                 ; dispatch to handler
//! ```
//!
//! The *pattern* is invariant across Themida samples; the *parameters*
//! (which RBP offset is VM_PC, handler-table base, rolling key) differ.
//! This detector outputs the invariant skeleton plus the observed
//! RBP-relative offsets; classification of each offset (VM_PC vs table
//! vs key) is left to downstream analysis that watches how each offset
//! is used.
//!
//! **Design axiom:** no sample-specific constants may land in this
//! code (see `feedback_sample_agnostic` in auto-memory). The detector
//! must return correct descriptors for *every* sample in `samples/`,
//! present and future, without per-sample code paths.

use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// A single VM dispatcher located in the input. Multiple VMs in one
/// binary produce multiple descriptors; each one is independent.
#[derive(Debug, Clone)]
pub struct VmDescriptor {
    /// RIP of the final indirect-branch `jmp r<reg>` that transfers
    /// control to the selected handler.
    pub dispatch_rip: u64,
    /// RIP of the `movzx r, word ptr [...]` that fetches the
    /// encrypted opcode. Used as an anchor when further analysis
    /// wants to inspect the fetch site.
    pub opcode_fetch_rip: u64,
    /// All `(register, offset)` pairs observed in the window where
    /// the dispatcher does `mov rX, rbp; add rX, IMM`. Candidates
    /// for VM_PC / handler-table base / rolling-key storage.
    /// Sorted by RIP of the `add` instruction.
    pub rbp_state_offsets: Vec<RbpOffset>,
    /// Best-guess RBP-relative offset of the VM_PC pointer. Derived
    /// post-detection by tracing the opcode-fetch base register back
    /// to its most recent `rbp + IMM` definition. `None` if the
    /// classifier can't resolve it.
    pub vm_pc_offset: Option<i64>,
    /// Best-guess RBP-relative offset of the handler-table base
    /// pointer. Derived by tracing the dispatch target register back
    /// through its most recent `mov target, [base]` load, then the
    /// base register's most recent `rbp + IMM` definition.
    pub handler_table_offset: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct RbpOffset {
    /// Register that held `rbp + offset` after the `mov rX, rbp; add
    /// rX, imm` pair.
    pub reg: Register,
    /// Offset immediate (`add rX, imm`). Signed because `add r, -k`
    /// is legal though rarely used here.
    pub offset: i64,
    /// RIP of the `add rX, imm` instruction.
    pub add_rip: u64,
}

/// A set of dispatcher sites that share the same `(vm_pc_offset,
/// handler_table_offset)` classification — i.e. they're plural
/// dispatch *sites* for the same VM *context*. Themida frequently
/// inlines a VM dispatcher into many call sites; treating them as
/// one context is usually what you want for M5.
#[derive(Debug, Clone)]
pub struct VmContext {
    pub vm_pc_offset: i64,
    pub handler_table_offset: i64,
    /// All descriptor dispatch RIPs that map to this context.
    pub dispatch_rips: Vec<u64>,
}

/// Collapse a list of descriptors into one `VmContext` per unique
/// `(vm_pc_offset, handler_table_offset)` pair. Descriptors missing
/// either classification are skipped (they can't be placed in any
/// context confidently). The resulting list is sorted by
/// dispatch-site count, descending.
pub fn group_into_contexts(descriptors: &[VmDescriptor]) -> Vec<VmContext> {
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<(i64, i64), Vec<u64>> = BTreeMap::new();
    for d in descriptors {
        if let (Some(pc), Some(tbl)) = (d.vm_pc_offset, d.handler_table_offset) {
            by_key.entry((pc, tbl)).or_default().push(d.dispatch_rip);
        }
    }
    let mut out: Vec<VmContext> = by_key
        .into_iter()
        .map(|((pc, tbl), rips)| VmContext {
            vm_pc_offset: pc,
            handler_table_offset: tbl,
            dispatch_rips: rips,
        })
        .collect();
    out.sort_by(|a, b| b.dispatch_rips.len().cmp(&a.dispatch_rips.len()));
    out
}

/// Scan the given `(rip -> bytes)` map for VM dispatcher patterns.
/// The map is typically built from a trace's `Exec` events but could
/// equally well come from a disassembled OEP dump.
///
/// Returns zero or more descriptors, one per distinct dispatcher found.
pub fn detect_vm(instructions: &BTreeMap<u64, Vec<u8>>) -> Vec<VmDescriptor> {
    let sorted: Vec<(&u64, &Vec<u8>)> = instructions.iter().collect();
    let mut descriptors = Vec::new();

    for (i, (jmp_rip, jmp_bytes)) in sorted.iter().enumerate() {
        let jmp = decode_at(jmp_bytes, **jmp_rip);
        if !is_indirect_reg_jmp(&jmp) {
            continue;
        }

        // Scan backward through sorted neighbors, bounded by both a
        // step count and a RIP-proximity check, so we don't pick up
        // instructions from a faraway basic block.
        let mut opcode_fetch_rip: Option<u64> = None;
        let mut rbp_state_offsets: Vec<RbpOffset> = Vec::new();
        let window = scan_window(&sorted, i);
        for (rip, bytes) in window.iter().rev() {
            let insn = decode_at(bytes, **rip);
            if opcode_fetch_rip.is_none() && is_word_movzx(&insn) {
                opcode_fetch_rip = Some(**rip);
            }
        }

        // Second walk: pick up `mov rX, rbp` + `add rX, imm` pairs.
        // Themida frequently interleaves multiple such pairs — `mov
        // rA, rbp; mov rB, rbp; add rA, imm_a; ...; add rB, imm_b`.
        // So after finding a `mov rX, rbp`, scan forward through the
        // window for the *first* matching `add rX, imm` that hasn't
        // already been claimed by an earlier pair.
        let mut claimed: Vec<usize> = Vec::new(); // indices of consumed `add` insns
        for (k, (mov_rip, mov_bytes)) in window.iter().enumerate() {
            let mov = decode_at(mov_bytes, **mov_rip);
            if !is_mov_reg_rbp(&mov) {
                continue;
            }
            let rx = mov.op0_register();
            if !rx.is_gpr64() {
                continue;
            }
            for m in (k + 1)..window.len() {
                if claimed.contains(&m) {
                    continue;
                }
                let (add_rip, add_bytes) = window[m];
                let add = decode_at(add_bytes, *add_rip);
                if let Some(off) = add_imm_to(&add, rx) {
                    rbp_state_offsets.push(RbpOffset {
                        reg: rx,
                        offset: off,
                        add_rip: *add_rip,
                    });
                    claimed.push(m);
                    break;
                }
                // If some other instruction writes to rx, the pair is
                // broken — abandon this mov.
                if writes_register(&add, rx) {
                    break;
                }
            }
        }

        if let Some(fetch_rip) = opcode_fetch_rip {
            let mut d = VmDescriptor {
                dispatch_rip: **jmp_rip,
                opcode_fetch_rip: fetch_rip,
                rbp_state_offsets,
                vm_pc_offset: None,
                handler_table_offset: None,
            };
            d.vm_pc_offset = classify_vm_pc(&d, instructions);
            d.handler_table_offset = classify_handler_table(&d, instructions);
            descriptors.push(d);
        }
    }

    descriptors
}

/// Return the RBP-relative offset that feeds the opcode fetch's
/// memory base register, tracing the register back through the
/// dispatcher body. Returns the last `rbp + IMM` value assigned to
/// that register before the fetch fires.
fn classify_vm_pc(d: &VmDescriptor, instructions: &BTreeMap<u64, Vec<u8>>) -> Option<i64> {
    let fetch_bytes = instructions.get(&d.opcode_fetch_rip)?;
    let fetch = decode_at(fetch_bytes, d.opcode_fetch_rip);
    if fetch.op1_kind() != OpKind::Memory {
        return None;
    }
    let base = fetch.memory_base();
    if !base.is_gpr64() {
        return None;
    }
    most_recent_rbp_offset(d, base, d.opcode_fetch_rip)
}

/// Return the RBP-relative offset that feeds the dispatch's handler-
/// table load. The path: `jmp target` → find the most recent `mov
/// target, [base]` before dispatch → that `base` register's most
/// recent `rbp + IMM` definition.
fn classify_handler_table(
    d: &VmDescriptor,
    instructions: &BTreeMap<u64, Vec<u8>>,
) -> Option<i64> {
    let dispatch_bytes = instructions.get(&d.dispatch_rip)?;
    let dispatch = decode_at(dispatch_bytes, d.dispatch_rip);
    if dispatch.op0_kind() != OpKind::Register {
        return None;
    }
    let target = dispatch.op0_register();
    if !target.is_gpr64() {
        return None;
    }

    // Walk back from dispatch_rip for the most recent `mov target,
    // [base]`. Bail if target is redefined by a non-memory-load along
    // the way — only a direct load exposes a usable `base`.
    let sorted: Vec<(&u64, &Vec<u8>)> = instructions.iter().collect();
    let dispatch_idx = sorted.iter().position(|(r, _)| **r == d.dispatch_rip)?;
    let mut base_reg: Option<Register> = None;
    for j in (0..dispatch_idx).rev() {
        let (rip, bytes) = sorted[j];
        let insn = decode_at(bytes, *rip);
        if insn.mnemonic() == Mnemonic::Mov
            && insn.op_count() == 2
            && insn.op0_kind() == OpKind::Register
            && insn.op0_register() == target
            && insn.op1_kind() == OpKind::Memory
        {
            base_reg = Some(insn.memory_base());
            break;
        }
        if writes_register(&insn, target) {
            break;
        }
    }
    let base = base_reg?;
    if !base.is_gpr64() {
        return None;
    }
    most_recent_rbp_offset(d, base, d.dispatch_rip)
}

fn most_recent_rbp_offset(d: &VmDescriptor, reg: Register, before_rip: u64) -> Option<i64> {
    let reg_full = reg.full_register();
    let mut best: Option<&RbpOffset> = None;
    for off in &d.rbp_state_offsets {
        if off.reg.full_register() == reg_full && off.add_rip < before_rip {
            match best {
                None => best = Some(off),
                Some(prev) if off.add_rip > prev.add_rip => best = Some(off),
                _ => {}
            }
        }
    }
    best.map(|o| o.offset)
}

/// Window of up to `MAX_WINDOW_STEPS` sorted neighbors preceding
/// position `i`, cut short when a RIP gap larger than
/// `MAX_RIP_GAP_BYTES` appears (which usually signals a basic-block
/// boundary). Returns entries in their original sorted order.
fn scan_window<'a>(
    sorted: &'a [(&u64, &Vec<u8>)],
    i: usize,
) -> Vec<(&'a u64, &'a Vec<u8>)> {
    const MAX_WINDOW_STEPS: usize = 80;
    const MAX_RIP_GAP_BYTES: u64 = 256;

    let mut out = Vec::new();
    let mut prev = *sorted[i].0;
    let start = i.saturating_sub(MAX_WINDOW_STEPS);
    for j in (start..i).rev() {
        let (rip, _) = sorted[j];
        if prev.saturating_sub(*rip) > MAX_RIP_GAP_BYTES {
            break;
        }
        prev = *rip;
        out.push((sorted[j].0, sorted[j].1));
    }
    out.reverse();
    out
}

fn decode_at(bytes: &[u8], rip: u64) -> Instruction {
    let mut dec = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
    dec.decode()
}

fn is_indirect_reg_jmp(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Jmp
        && insn.op0_kind() == OpKind::Register
        && insn.op0_register().is_gpr64()
}

/// Matches `movzx <reg>, word ptr [<mem>]` — the VM opcode fetch
/// shape. We're loose about the destination register width (some
/// handlers use `movzx r64, word ptr` and some `movzx r32, word ptr`).
fn is_word_movzx(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Movzx
        && insn.op1_kind() == OpKind::Memory
        && insn.memory_size().size() == 2
}

fn is_mov_reg_rbp(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Mov
        && insn.op0_kind() == OpKind::Register
        && insn.op1_kind() == OpKind::Register
        && insn.op1_register() == Register::RBP
}

/// If `insn` is `add <reg>, imm` with `<reg> == expected`, returns the
/// sign-extended immediate. Otherwise `None`.
/// Does `insn` write to `reg` (as its first-operand register dst)?
fn writes_register(insn: &Instruction, reg: Register) -> bool {
    if insn.op_count() == 0 {
        return false;
    }
    if insn.op0_kind() != OpKind::Register {
        return false;
    }
    // Conservative: match when the FULL register is reg. Narrower
    // aliases count because they also modify `reg`.
    let w = insn.op0_register();
    w == reg || (w.is_gpr() && w.full_register() == reg)
}

fn add_imm_to(insn: &Instruction, expected: Register) -> Option<i64> {
    if insn.mnemonic() != Mnemonic::Add {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Register || insn.op0_register() != expected {
        return None;
    }
    match insn.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(insn.immediate(1) as i64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_from_pairs(pairs: Vec<(u64, &[u8])>) -> BTreeMap<u64, Vec<u8>> {
        pairs.into_iter().map(|(r, b)| (r, b.to_vec())).collect()
    }

    #[test]
    fn detects_synthetic_vm_dispatcher() {
        // Synthetic mini-dispatcher at 0x1000:
        //   mov r11, rbp
        //   add r11, 0x9A
        //   mov r11, [r11]
        //   movzx r11, word ptr [r11]
        //   jmp r10
        let bytes: Vec<(u64, &[u8])> = vec![
            (0x1000, &[0x49, 0x89, 0xEB]),                   // mov r11, rbp
            (0x1003, &[0x49, 0x81, 0xC3, 0x9A, 0, 0, 0]),    // add r11, 0x9A
            (0x100A, &[0x4D, 0x8B, 0x1B]),                   // mov r11, [r11]
            (0x100D, &[0x4D, 0x0F, 0xB7, 0x1B]),             // movzx r11, word ptr [r11]
            (0x1011, &[0x41, 0xFF, 0xE2]),                   // jmp r10
        ];
        let map = map_from_pairs(bytes);
        let found = detect_vm(&map);
        assert_eq!(found.len(), 1);
        let d = &found[0];
        assert_eq!(d.dispatch_rip, 0x1011);
        assert_eq!(d.opcode_fetch_rip, 0x100D);
        assert_eq!(d.rbp_state_offsets.len(), 1);
        assert_eq!(d.rbp_state_offsets[0].reg, Register::R11);
        assert_eq!(d.rbp_state_offsets[0].offset, 0x9A);
        // Classifier should trace the fetch's base (R11) back to
        // the single rbp+0x9A offset.
        assert_eq!(d.vm_pc_offset, Some(0x9A));
    }

    #[test]
    fn rejects_jmp_without_word_movzx() {
        // Just: xor rbx,0x7FFFFFFF; sub rdx,0xD3; jmp r13
        // (mirrors the sample-2 threaded-dispatch site at 0x14112462f)
        let bytes: Vec<(u64, &[u8])> = vec![
            (0x2000, &[0x48, 0x81, 0xF3, 0xFF, 0xFF, 0xFF, 0x7F]),
            (0x2007, &[0x48, 0x81, 0xEA, 0xD3, 0, 0, 0]),
            (0x200E, &[0x41, 0xFF, 0xE5]),
        ];
        let map = map_from_pairs(bytes);
        let found = detect_vm(&map);
        assert!(found.is_empty());
    }

    #[test]
    fn rejects_rel32_jmp() {
        // jmp rel32 is not an indirect jmp.
        let bytes: Vec<(u64, &[u8])> = vec![
            (0x3000, &[0x4D, 0x0F, 0xB7, 0x1B]),     // movzx r11, word ptr [r11]
            (0x3004, &[0xE9, 0x00, 0x00, 0x00, 0x00]), // jmp rel32
        ];
        let map = map_from_pairs(bytes);
        let found = detect_vm(&map);
        assert!(found.is_empty());
    }

    #[test]
    fn captures_multiple_rbp_state_offsets() {
        // Three (mov rX, rbp; add rX, imm) pairs, typical of Themida
        // dispatchers that prep VM_PC, handler-table, and key pointers.
        let bytes: Vec<(u64, &[u8])> = vec![
            (0x4000, &[0x49, 0x89, 0xEB]),                   // mov r11, rbp
            (0x4003, &[0x49, 0x81, 0xC3, 0x9A, 0, 0, 0]),    // add r11, 0x9A
            (0x400A, &[0x49, 0x89, 0xE9]),                   // mov r9, rbp
            (0x400D, &[0x49, 0x81, 0xC1, 0x26, 0, 0, 0]),    // add r9, 0x26
            (0x4014, &[0x48, 0x89, 0xEA]),                   // mov rdx, rbp
            (0x4017, &[0x48, 0x81, 0xC2, 0xD4, 0, 0, 0]),    // add rdx, 0xD4
            (0x401E, &[0x4D, 0x0F, 0xB7, 0x1B]),             // movzx r11, word ptr [r11]
            (0x4022, &[0x41, 0xFF, 0xE2]),                   // jmp r10
        ];
        let map = map_from_pairs(bytes);
        let found = detect_vm(&map);
        assert_eq!(found.len(), 1);
        let offsets: Vec<i64> = found[0]
            .rbp_state_offsets
            .iter()
            .map(|o| o.offset)
            .collect();
        assert_eq!(offsets, vec![0x9A, 0x26, 0xD4]);
    }
}
