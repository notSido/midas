//! Offline trace analyzer — reads a `--devirt-trace` JSONL file and prints
//! per-address stats plus the top dispatcher candidates (M1).
//!
//! Separate binary (not a subcommand) so it can run without Unicorn / the
//! emulator being usable — useful on laptops where the Docker build is
//! elsewhere but the trace file is local.

use clap::Parser;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use midas::devirt::{
    detect_vm, group_into_contexts, lift_instruction, resolve_vm_addresses, HandlerCatalog,
    LiftError, RegSnapshot, TraceAnalysis,
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
            Event::RegsAtRip { rip, regs, .. } => {
                reg_captures.entry(rip).or_insert(regs);
            }
            Event::OepReached { .. } => {}
        }
    }

    let mut descriptors = detect_vm(&instructions);
    resolve_vm_addresses(&mut descriptors, &reg_captures);
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
            Some(a) => println!("  vm_pc_addr:           0x{:x}", a),
            None => println!("  vm_pc_addr:           (no capture / unresolved)"),
        }
        match d.handler_table_addr {
            Some(a) => println!("  handler_table_addr:   0x{:x}", a),
            None => println!("  handler_table_addr:   (no capture / unresolved)"),
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
