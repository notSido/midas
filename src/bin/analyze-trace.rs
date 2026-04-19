//! Offline trace analyzer — reads a `--devirt-trace` JSONL file and prints
//! per-address stats plus the top dispatcher candidates (M1).
//!
//! Separate binary (not a subcommand) so it can run without Unicorn / the
//! emulator being usable — useful on laptops where the Docker build is
//! elsewhere but the trace file is local.

use clap::Parser;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use midas::devirt::{
    detect_vm, dispatch_target_register, emit_effects, evaluate_linear, group_into_contexts,
    lift_instruction, resolve_vm_addresses, simplify_effects_with_live_out, EvalOutcome,
    EvalState, HandlerCatalog, LiftError, MemSnapshot, OepDump, RegSnapshot, TraceAnalysis,
    VmDescriptor,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "analyze-trace")]
#[command(about = "Analyze a midas devirt-trace JSONL file", long_about = None)]
struct Args {
    /// Path to a JSONL trace produced by `midas --devirt-trace`.
    #[arg(short, long)]
    input: PathBuf,

    /// Number of dispatcher candidates to print (M1 mode).
    #[arg(long, default_value = "10")]
    top: usize,

    /// Also print up to N successors per candidate (handler entries).
    #[arg(long, default_value = "16")]
    successors_per_candidate: usize,

    /// Extract a handler catalog by segmenting the trace at every
    /// execution of `--dispatcher`. M2 mode.
    #[arg(long, conflicts_with = "top")]
    extract_handlers: bool,

    /// Dispatcher RIP (hex with 0x prefix or decimal). Required when
    /// `--extract-handlers` is set.
    #[arg(long, value_parser = parse_hex_or_dec)]
    dispatcher: Option<u64>,

    /// In handler-extract mode, print up to this many handlers.
    #[arg(long, default_value = "30")]
    handlers_to_print: usize,

    /// Lift handler #N (0 = top by fire_count) to IR and report
    /// per-instruction lift success. Requires `--dispatcher`.
    #[arg(long)]
    lift_handler: Option<usize>,

    /// Cap on the number of handler instructions lifted when
    /// `--lift-handler` is used.
    #[arg(long, default_value = "200")]
    lift_limit: usize,

    /// Dump all unique (rip, bytes) pairs observed in the trace whose
    /// RIP is in `[dump_region_start .. dump_region_end)`, sorted by
    /// RIP, disassembled via iced-x86. Useful for reading a code
    /// region (e.g. a VM dispatcher body) out of the OEP memory dump
    /// without re-disassembling the whole PE.
    #[arg(long, value_parser = parse_hex_or_dec)]
    dump_region_start: Option<u64>,

    /// Exclusive upper bound for `--dump-region-start`.
    #[arg(long, value_parser = parse_hex_or_dec)]
    dump_region_end: Option<u64>,

    /// Scan every unique `(rip, bytes)` pair in the trace for the
    /// canonical Themida VM dispatcher pattern and print one
    /// `VmDescriptor` per candidate found. Sample-agnostic — the
    /// detector uses an invariant pattern and returns sample-
    /// specific parameters.
    #[arg(long)]
    detect_vm: bool,
}

/// Preview the first 64 bytes of the bytecode stream starting at
/// `vm_pc_value`. Purely raw — opcode decryption is sample-specific
/// and belongs to the walker.
fn print_bytecode_preview(dump: &OepDump, vm_pc_value: u64) {
    match dump.read_bytes_at_va(vm_pc_value, 64) {
        Some(bytes) => {
            println!("  bytecode preview (@0x{:x}, 64 bytes):", vm_pc_value);
            for chunk in bytes.chunks(16) {
                let mut hex = String::with_capacity(48);
                for b in chunk {
                    hex.push_str(&format!("{:02x} ", b));
                }
                println!("    {}", hex);
            }
        }
        None => println!(
            "  bytecode preview: (VM_PC 0x{:x} out of image)",
            vm_pc_value
        ),
    }
}

/// Read the first 16 u64 entries of the handler table. Each entry is
/// a candidate handler address — we don't filter for plausibility
/// yet (e.g. "is this RIP in .text"), just dump.
fn print_handler_table_preview(dump: &OepDump, table_base: u64) {
    println!(
        "  handler table preview (@0x{:x}, first 16 entries):",
        table_base
    );
    for i in 0..16u64 {
        match dump.read_u64_at_va(table_base + i * 8) {
            Some(v) => println!("    [{:>2}] 0x{:016x}", i, v),
            None => {
                println!("    [{:>2}] (out of image)", i);
                break;
            }
        }
    }
}

/// Run the dispatcher instructions from `opcode_fetch_rip` through
/// `dispatch_rip` (inclusive) against a captured register snapshot +
/// OEP dump, then report the computed target register value and how
/// it compares against the captured one. A match proves the
/// evaluator handles this sample's dispatch logic — the piece we'd
/// then extend to walk the bytecode stream.
fn print_dispatcher_evaluation(
    d: &VmDescriptor,
    instructions: &std::collections::BTreeMap<u64, Vec<u8>>,
    dump: &OepDump,
    regs: &RegSnapshot,
    ground_truth: Option<&RegSnapshot>,
    fetch_mems: Option<&Vec<MemSnapshot>>,
    dispatch_mems: Option<&Vec<MemSnapshot>>,
) {
    let Some(target_reg) = dispatch_target_register(instructions, d.dispatch_rip) else {
        println!("  dispatch evaluation:   (target reg not identified)");
        return;
    };
    let captured = ground_truth.and_then(|g| snapshot_reg_by_name(g, target_reg));
    let mut state = EvalState::from_snapshot(regs, dump, None);
    if let Some(ms) = fetch_mems {
        for m in ms {
            state.add_mem_snapshot(m.clone());
        }
    }
    if let Some(ms) = dispatch_mems {
        for m in ms {
            state.add_mem_snapshot(m.clone());
        }
    }
    let outcome = evaluate_linear(
        &mut state,
        instructions,
        d.opcode_fetch_rip,
        d.dispatch_rip,
    );
    let computed = state.reg(target_reg);
    match outcome {
        EvalOutcome::Ok => match (computed, captured) {
            (Some(c), Some(cap)) if c == cap => println!(
                "  dispatch evaluation:   OK — {:?} = 0x{:x}  (matches captured)",
                target_reg, c
            ),
            (Some(c), Some(cap)) => println!(
                "  dispatch evaluation:   mismatch — evaluated {:?}=0x{:x}, captured=0x{:x}",
                target_reg, c, cap
            ),
            (Some(c), None) => println!(
                "  dispatch evaluation:   evaluated {:?}=0x{:x} (no captured value)",
                target_reg, c
            ),
            _ => println!("  dispatch evaluation:   no value produced"),
        },
        EvalOutcome::LiftFailure { rip, err } => println!(
            "  dispatch evaluation:   lift failed at 0x{:x}: {:?}",
            rip, err
        ),
        EvalOutcome::EvalFailure { rip } => println!(
            "  dispatch evaluation:   eval failed at 0x{:x} (unknown reg / OOB mem read)",
            rip
        ),
    }
}

/// Replay-mode walk: for each recorded firing of the dispatcher's
/// opcode-fetch RIP, seed an `EvalState` from that firing's exact
/// captured state and evaluate the dispatcher forward to the jmp.
/// This mirrors the runtime instead of relying on state flowing
/// forward via overlay — so the bytecode bytes the walker sees at
/// iter N are the exact bytes the real VM saw at that moment.
fn print_trace_replay_walk(
    d: &VmDescriptor,
    instructions: &std::collections::BTreeMap<u64, Vec<u8>>,
    dump: &OepDump,
    firings: &[(u64, RegSnapshot, Vec<MemSnapshot>)],
) {
    let Some(target_reg) = dispatch_target_register(instructions, d.dispatch_rip) else {
        return;
    };
    println!(
        "  bytecode walk ({} captured firings, replay mode from dispatcher_start 0x{:x}):",
        firings.len(),
        d.dispatcher_start_rip
    );
    for (i, (tick, regs, mems)) in firings.iter().enumerate() {
        let mut state = EvalState::from_snapshot(regs, dump, None);
        for m in mems {
            state.add_mem_snapshot(m.clone());
        }
        let outcome = midas::devirt::evaluate_linear(
            &mut state,
            instructions,
            d.dispatcher_start_rip,
            d.dispatch_rip,
        );
        let handler = state.reg(target_reg).unwrap_or(0);
        let g = state.gpr_snapshot();
        let status = match outcome {
            midas::devirt::EvalOutcome::Ok => "OK",
            midas::devirt::EvalOutcome::LiftFailure { rip, .. } => {
                println!(
                    "    [{:>3}] tick={:>10}  LIFT FAIL at 0x{:x}",
                    i, tick, rip
                );
                continue;
            }
            midas::devirt::EvalOutcome::EvalFailure { rip } => {
                println!(
                    "    [{:>3}] tick={:>10}  EVAL FAIL at 0x{:x}",
                    i, tick, rip
                );
                continue;
            }
        };
        // VM_PC at fetch time = (base reg of fetch instr); we
        // approximate via R11-or-whichever. Use rip from regs minus 4
        // is sample-specific; just read VM_PC from the regs' actual
        // known-to-be-fetch-base (r11 for sample 2, r15 for sample
        // 1). Report both.
        println!(
            "    [{:>3}] tick={:>10}  {}  handler=0x{:x}  r11=0x{:x} r15=0x{:x}",
            i, tick, status, handler, g.r11, g.r15
        );
    }
}

/// For each captured dispatcher firing, evaluate to get the handler
/// address, then emit every unique handler body as labelled pseudo-C
/// and list the VM-program firing sequence below. This is the
/// whole-observed-VM-program output — the "Deliverable B text form"
/// at the current level of cleanup.
fn print_full_vm_program(
    d: &VmDescriptor,
    instructions: &std::collections::BTreeMap<u64, Vec<u8>>,
    dump: &OepDump,
    firings: &[(u64, RegSnapshot, Vec<MemSnapshot>)],
) {
    use std::collections::BTreeMap;
    let Some(target_reg) = dispatch_target_register(instructions, d.dispatch_rip) else {
        return;
    };

    // Resolve each firing → handler address. Build the program as
    // (tick, handler_addr) pairs; collect the unique set of handler
    // addresses for body emission.
    let mut program: Vec<(u64, u64)> = Vec::with_capacity(firings.len());
    let mut unique_handlers: BTreeMap<u64, ()> = BTreeMap::new();
    for (tick, regs, mems) in firings {
        let mut state = EvalState::from_snapshot(regs, dump, None);
        for m in mems {
            state.add_mem_snapshot(m.clone());
        }
        let outcome = evaluate_linear(
            &mut state,
            instructions,
            d.dispatcher_start_rip,
            d.dispatch_rip,
        );
        if !matches!(outcome, EvalOutcome::Ok) {
            continue;
        }
        if let Some(handler) = state.reg(target_reg) {
            program.push((*tick, handler));
            unique_handlers.insert(handler, ());
        }
    }
    if unique_handlers.is_empty() {
        return;
    }

    println!();
    println!(
        "  observed VM program: {} dispatches, {} unique handlers",
        program.len(),
        unique_handlers.len()
    );
    println!();

    // Emit each unique handler body, simplified + pseudo-C.
    for (i, (entry, ())) in unique_handlers.iter().enumerate() {
        print_handler_body(i + 1, *entry, instructions, d.dispatch_rip);
    }

    // Emit the VM-program sequence.
    println!();
    println!("  // VM program trace (tick → handler)");
    for (tick, handler) in &program {
        println!("  //   tick {:>10}  handler_0x{:x}()", tick, handler);
    }
}

fn print_handler_body(
    index: usize,
    entry: u64,
    instructions: &std::collections::BTreeMap<u64, Vec<u8>>,
    dispatch_rip: u64,
) {
    use iced_x86::{Decoder, DecoderOptions, Instruction};
    const MAX_INSNS: usize = 256;
    let mut handler_insns: Vec<(u64, &[u8])> = Vec::new();
    for (rip, bytes) in instructions.range(entry..) {
        if *rip == dispatch_rip {
            break;
        }
        handler_insns.push((*rip, bytes.as_slice()));
        if handler_insns.len() >= MAX_INSNS {
            break;
        }
    }
    if handler_insns.is_empty() {
        return;
    }
    let mut lifted: Vec<midas::devirt::Effect> = Vec::new();
    let mut skipped = 0usize;
    for (rip, bytes) in &handler_insns {
        let mut dec = Decoder::with_ip(64, bytes, *rip, DecoderOptions::NONE);
        let insn: Instruction = dec.decode();
        match lift_instruction(&insn) {
            Ok(effs) => lifted.extend(effs),
            Err(_) => skipped += 1,
        }
    }
    let simplified = simplify_effects_with_live_out(
        lifted,
        vec![iced_x86::Register::RBP, iced_x86::Register::RSP],
        vec![],
    );
    println!(
        "  // handler #{} @ 0x{:x}  ({} insns, {} effects, {} skipped)",
        index,
        entry,
        handler_insns.len(),
        simplified.len(),
        skipped
    );
    println!("  handler_0x{:x}() {{", entry);
    let text = emit_effects(&simplified);
    for line in text.lines().take(32) {
        println!("      {}", line);
    }
    let lines_total = text.lines().count();
    if lines_total > 32 {
        println!("      // ... ({} more lines)", lines_total - 32);
    }
    println!("  }}");
    println!();
}

fn snapshot_reg_by_name(regs: &RegSnapshot, r: iced_x86::Register) -> Option<u64> {
    use iced_x86::Register::*;
    match r.full_register() {
        RAX => Some(regs.rax),
        RBX => Some(regs.rbx),
        RCX => Some(regs.rcx),
        RDX => Some(regs.rdx),
        RSI => Some(regs.rsi),
        RDI => Some(regs.rdi),
        RBP => Some(regs.rbp),
        RSP => Some(regs.rsp),
        R8 => Some(regs.r8),
        R9 => Some(regs.r9),
        R10 => Some(regs.r10),
        R11 => Some(regs.r11),
        R12 => Some(regs.r12),
        R13 => Some(regs.r13),
        R14 => Some(regs.r14),
        R15 => Some(regs.r15),
        RIP => Some(regs.rip),
        _ => Option::None,
    }
}

/// Turn `<stem>.trace.jsonl` (the path midas writes) into
/// `<stem>.exe` (the OEP dump path midas writes alongside). Returns
/// `None` for non-matching suffixes — user can still view the
/// detector output without a dump.
fn derive_oep_dump_path(trace_path: &PathBuf) -> Option<PathBuf> {
    let file_name = trace_path.file_name()?.to_str()?;
    let stem = file_name.strip_suffix(".trace.jsonl")?;
    let mut p = trace_path.clone();
    p.set_file_name(format!("{}.exe", stem));
    Some(p)
}

fn parse_hex_or_dec(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (radix, body) = if let Some(r) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, r)
    } else {
        (10, s)
    };
    u64::from_str_radix(body, radix).map_err(|e| format!("bad address {:?}: {}", s, e))
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .target(env_logger::Target::Stderr)
        .init();
    let args = Args::parse();
    match run(args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("analyze-trace: {}", e);
            process::exit(1);
        }
    }
}

fn run(args: Args) -> midas::Result<()> {
    if args.detect_vm {
        return run_detect_vm(&args);
    }
    if args.dump_region_start.is_some() {
        return run_dump_region(&args);
    }
    if args.lift_handler.is_some() {
        return run_lift_handler(&args);
    }
    if args.extract_handlers {
        return run_extract_handlers(&args);
    }
    run_dispatcher_candidates(&args)
}

fn run_detect_vm(args: &Args) -> midas::Result<()> {
    use midas::devirt::Event;
    use std::collections::{BTreeMap, HashMap};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(&args.input)?;
    let reader = BufReader::new(file);
    let mut instructions: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut reg_captures: HashMap<u64, RegSnapshot> = HashMap::new();
    let mut mem_captures: HashMap<u64, Vec<MemSnapshot>> = HashMap::new();
    // Multi-shot captures (one entry per firing) in tick order.
    // The movzx auto-capture path emits one per dispatcher iteration
    // so the walker can seed each iter from its ground-truth state.
    let mut multi_captures: HashMap<u64, Vec<(u64, RegSnapshot, Vec<MemSnapshot>)>> =
        HashMap::new();
    for line in reader.lines().flatten() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        match event {
            Event::Exec { rip, bytes, .. } => {
                instructions.entry(rip).or_insert(bytes);
            }
            Event::RegsAtRip {
                tick,
                rip,
                regs,
                mems,
            } => {
                reg_captures.entry(rip).or_insert_with(|| regs.clone());
                if !mems.is_empty() {
                    mem_captures
                        .entry(rip)
                        .or_insert_with(|| mems.clone());
                }
                multi_captures
                    .entry(rip)
                    .or_default()
                    .push((tick, regs, mems));
            }
            Event::OepReached { .. } => {}
        }
    }

    let mut descriptors = detect_vm(&instructions);
    resolve_vm_addresses(&mut descriptors, &reg_captures);

    // Auto-derive the OEP dump path from the trace path: the unpacker
    // writes the trace as `<stem>.trace.jsonl` alongside the PE at
    // `<stem>.exe`. No flag — zero-config, same layout as the
    // unpacker produces.
    let dump = derive_oep_dump_path(&args.input)
        .and_then(|p| match OepDump::load(&p) {
            Ok(d) => {
                eprintln!("analyze-trace: loaded OEP dump {:?}", p);
                Some(d)
            }
            Err(e) => {
                eprintln!("analyze-trace: OEP dump {:?} not loaded: {}", p, e);
                None
            }
        });
    let contexts = group_into_contexts(&descriptors);
    let resolved_count = descriptors.iter().filter(|d| d.vm_pc_addr.is_some()).count();
    println!("== VM detector ==");
    println!("input:                 {:?}", args.input);
    println!("unique instructions:   {}", instructions.len());
    println!("reg captures:          {}", reg_captures.len());
    println!("descriptors found:     {}", descriptors.len());
    println!(
        "descriptors with addrs:{}  (RegsAtRip captures matched to dispatcher RIP)",
        resolved_count
    );
    println!(
        "unique VM contexts: {}  (dedup by (vm_pc_offset, handler_table_offset))",
        contexts.len()
    );
    for (i, c) in contexts.iter().enumerate() {
        println!(
            "  ctx #{}: vm_pc=rbp+0x{:x}, table=rbp+0x{:x}, {} dispatch sites",
            i + 1,
            c.vm_pc_offset,
            c.handler_table_offset,
            c.dispatch_rips.len()
        );
    }
    println!();
    if descriptors.is_empty() {
        println!("(no VM dispatchers detected — either the trace doesn't");
        println!(" cover a VM-protected region, or the pattern is different)");
        return Ok(());
    }
    for (i, d) in descriptors.iter().enumerate() {
        println!("--- descriptor #{} ---", i + 1);
        println!("  dispatch_rip:         0x{:x}", d.dispatch_rip);
        println!("  opcode_fetch_rip:     0x{:x}", d.opcode_fetch_rip);
        match d.vm_pc_offset {
            Some(o) => println!("  vm_pc_offset:         rbp + 0x{:x}", o),
            None => println!("  vm_pc_offset:         (unresolved)"),
        }
        match d.handler_table_offset {
            Some(o) => println!("  handler_table_offset: rbp + 0x{:x}", o),
            None => println!("  handler_table_offset: (unresolved)"),
        }
        match d.vm_pc_addr {
            Some(a) => {
                let val = dump.as_ref().and_then(|d| d.read_u64_at_va(a));
                match val {
                    Some(v) => println!(
                        "  vm_pc_addr:           0x{:x}  *(u64*) = 0x{:x}",
                        a, v
                    ),
                    None => println!("  vm_pc_addr:           0x{:x}  (no dump read)", a),
                }
            }
            None => println!("  vm_pc_addr:           (no capture / unresolved)"),
        }
        match d.handler_table_addr {
            Some(a) => {
                let val = dump.as_ref().and_then(|d| d.read_u64_at_va(a));
                match val {
                    Some(v) => println!(
                        "  handler_table_addr:   0x{:x}  *(u64*) = 0x{:x}",
                        a, v
                    ),
                    None => println!("  handler_table_addr:   0x{:x}  (no dump read)", a),
                }
            }
            None => println!("  handler_table_addr:   (no capture / unresolved)"),
        }
        // Preview the bytecode stream and handler table when both the
        // dump and the resolved pointers are available. Only prints
        // for descriptor #1 of each unique VM context to avoid
        // spamming the same values across all dispatch sites.
        if i == 0 {
            if let (Some(dump), Some(pc_addr), Some(tbl_addr)) =
                (dump.as_ref(), d.vm_pc_addr, d.handler_table_addr)
            {
                if let (Some(pc_val), Some(tbl_val)) =
                    (dump.read_u64_at_va(pc_addr), dump.read_u64_at_va(tbl_addr))
                {
                    print_bytecode_preview(dump, pc_val);
                    print_handler_table_preview(dump, tbl_val);
                }
            }
        }
        // Evaluate the dispatcher slice. We need state *at the
        // opcode fetch* (where the source reg still holds the VM_PC
        // pointer) — the captured state at `dispatch_rip` is too
        // late because the dispatcher has already rewritten the reg
        // with the decrypted opcode. Falls back to the dispatch_rip
        // capture if we don't have one at fetch.
        let fetch_regs = reg_captures
            .get(&d.opcode_fetch_rip)
            .or_else(|| reg_captures.get(&d.dispatch_rip));
        if let (Some(dump), Some(regs)) = (dump.as_ref(), fetch_regs) {
            let ground_truth = reg_captures.get(&d.dispatch_rip);
            let fetch_mems = mem_captures.get(&d.opcode_fetch_rip);
            let dispatch_mems = mem_captures.get(&d.dispatch_rip);
            print_dispatcher_evaluation(
                d,
                &instructions,
                dump,
                regs,
                ground_truth,
                fetch_mems,
                dispatch_mems,
            );
            if i == 0 {
                if let Some(firings) = multi_captures.get(&d.opcode_fetch_rip) {
                    if !firings.is_empty() {
                        print_trace_replay_walk(d, &instructions, dump, firings);
                        print_full_vm_program(d, &instructions, dump, firings);
                    }
                }
            }
        }
        if d.rbp_state_offsets.is_empty() {
            println!("  rbp_state_offsets: (none observed in window)");
        } else {
            println!("  rbp_state_offsets:");
            for off in &d.rbp_state_offsets {
                println!(
                    "    [rbp + 0x{:x}]  reg={:?}  add@0x{:x}",
                    off.offset, off.reg, off.add_rip
                );
            }
        }
    }
    Ok(())
}

fn run_dump_region(args: &Args) -> midas::Result<()> {
    use midas::devirt::Event;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let start = args.dump_region_start.unwrap();
    let end = args.dump_region_end.ok_or_else(|| {
        midas::UnpackError::DumpError(
            "--dump-region-end <RIP> is required with --dump-region-start".into(),
        )
    })?;

    let file = File::open(&args.input)?;
    let reader = BufReader::new(file);
    let mut seen: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut hits: u64 = 0;
    for line in reader.lines().flatten() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Event::Exec { rip, bytes, .. } = event {
            if rip >= start && rip < end {
                hits += 1;
                seen.entry(rip).or_insert(bytes);
            }
        }
    }

    println!("== region 0x{:x} .. 0x{:x} ==", start, end);
    println!("exec hits:    {}", hits);
    println!("unique rips:  {}", seen.len());
    println!();
    let mut formatter = IntelFormatter::new();
    let mut disasm = String::new();
    for (rip, bytes) in &seen {
        let mut dec = Decoder::with_ip(64, bytes, *rip, DecoderOptions::NONE);
        let insn = dec.decode();
        disasm.clear();
        formatter.format(&insn, &mut disasm);
        // Hex bytes (up to 10 shown).
        let take = bytes.len().min(10);
        let mut hex = String::with_capacity(take * 3);
        for b in &bytes[..take] {
            hex.push_str(&format!("{:02x} ", b));
        }
        if bytes.len() > take {
            hex.push_str("...");
        }
        println!("  0x{:x}  {:<30} {}", rip, hex, disasm);
    }
    Ok(())
}

fn run_lift_handler(args: &Args) -> midas::Result<()> {
    let dispatcher = args.dispatcher.ok_or_else(|| {
        midas::UnpackError::DumpError("--dispatcher <RIP> is required with --lift-handler".into())
    })?;
    let idx = args.lift_handler.unwrap();
    let catalog = HandlerCatalog::from_trace_file(&args.input, dispatcher)?;
    let handler = catalog.handlers.get(idx).ok_or_else(|| {
        midas::UnpackError::DumpError(format!(
            "handler index {} out of range (have {})",
            idx,
            catalog.handlers.len()
        ))
    })?;

    println!(
        "== lifting handler #{}  sig=0x{:016x}  entry=0x{:x}  len={}  fires={} ==",
        idx, handler.signature, handler.entry_rip, handler.length, handler.fire_count
    );

    let take = handler.exemplar.len().min(args.lift_limit);
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut unsupported_mnemonic: HashMap<String, usize> = HashMap::new();
    let mut unsupported_reason: HashMap<&'static str, usize> = HashMap::new();
    let mut formatter = IntelFormatter::new();
    let mut disasm = String::new();

    for (rip, bytes) in handler.exemplar.iter().take(take) {
        let mut dec = Decoder::with_ip(64, bytes, *rip, DecoderOptions::NONE);
        let insn: Instruction = dec.decode();
        disasm.clear();
        formatter.format(&insn, &mut disasm);

        match lift_instruction(&insn) {
            Ok(effects) => {
                ok += 1;
                println!("  OK  0x{:x}  {:<40} -> {} effect(s)", rip, disasm, effects.len());
            }
            Err(LiftError::Unsupported(reason)) => {
                fail += 1;
                *unsupported_reason.entry(reason).or_insert(0) += 1;
                let m = format!("{:?}", insn.mnemonic());
                *unsupported_mnemonic.entry(m).or_insert(0) += 1;
                println!("  NS  0x{:x}  {:<40} -> unsupported: {}", rip, disasm, reason);
            }
            Err(LiftError::BadOperand(reason)) => {
                fail += 1;
                println!("  ER  0x{:x}  {:<40} -> bad-operand: {}", rip, disasm, reason);
            }
        }
    }

    println!();
    println!("== summary ==");
    println!("lifted ok:      {}/{}", ok, ok + fail);
    println!("unsupported:    {}", fail);
    if !unsupported_reason.is_empty() {
        println!("reasons:");
        let mut rs: Vec<_> = unsupported_reason.iter().collect();
        rs.sort_by(|a, b| b.1.cmp(a.1));
        for (r, c) in rs {
            println!("  {:<30} {}", r, c);
        }
    }
    if !unsupported_mnemonic.is_empty() {
        println!("unsupported mnemonics (top 15):");
        let mut ms: Vec<_> = unsupported_mnemonic.iter().collect();
        ms.sort_by(|a, b| b.1.cmp(a.1));
        for (m, c) in ms.into_iter().take(15) {
            println!("  {:<30} {}", m, c);
        }
    }

    Ok(())
}

fn run_dispatcher_candidates(args: &Args) -> midas::Result<()> {
    let analysis = TraceAnalysis::from_trace_file(&args.input)?;

    println!("== trace summary ==");
    println!("file:          {:?}", args.input);
    println!("total events:  {}", analysis.total_events);
    println!("unique rips:   {}", analysis.unique_rips());
    if let Some(oep) = analysis.oep_rip {
        println!("oep (armed):   0x{:x}", oep);
    }

    println!();
    println!("== top {} dispatcher candidates (rip, fan_out, exec_count) ==", args.top);
    let cands = analysis.dispatcher_candidates(args.top);
    if cands.is_empty() {
        println!("  (no addresses with fan-out ≥ 2 — trace is probably a straight line)");
        return Ok(());
    }
    for (i, c) in cands.iter().enumerate() {
        println!(
            "{:>3}. 0x{:x}   fan_out={:<4} exec_count={}",
            i + 1,
            c.rip,
            c.fan_out,
            c.exec_count
        );
        let take = c.successors.len().min(args.successors_per_candidate);
        for s in &c.successors[..take] {
            println!("       -> 0x{:x}", s);
        }
        if c.successors.len() > take {
            println!("       ... ({} more)", c.successors.len() - take);
        }
    }

    Ok(())
}

fn run_extract_handlers(args: &Args) -> midas::Result<()> {
    let dispatcher = args.dispatcher.ok_or_else(|| {
        midas::UnpackError::DumpError(
            "--dispatcher <RIP> is required with --extract-handlers".into(),
        )
    })?;
    let catalog = HandlerCatalog::from_trace_file(&args.input, dispatcher)?;

    println!("== handler catalog (dispatcher 0x{:x}) ==", catalog.dispatcher_rip);
    println!("total invocations: {}", catalog.total_invocations);
    println!("unique handlers:   {}", catalog.unique_count());
    if catalog.handlers.is_empty() {
        println!("  (no handler invocations segmented — is the dispatcher RIP correct?)");
        return Ok(());
    }

    println!();
    let take = catalog.handlers.len().min(args.handlers_to_print);
    println!("== top {} handlers by fire_count ==", take);
    for (i, h) in catalog.handlers.iter().take(take).enumerate() {
        println!(
            "{:>3}. sig=0x{:016x}  entry=0x{:x}  len={:<4} fires={}",
            i + 1,
            h.signature,
            h.entry_rip,
            h.length,
            h.fire_count
        );
        for r in &h.first_rips {
            println!("       . 0x{:x}", r);
        }
        if h.length > h.first_rips.len() {
            println!("       . ... ({} more)", h.length - h.first_rips.len());
        }
    }
    if catalog.handlers.len() > take {
        println!("... ({} more unique handlers not shown)", catalog.handlers.len() - take);
    }

    Ok(())
}
