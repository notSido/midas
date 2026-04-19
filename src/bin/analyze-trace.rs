//! Offline trace analyzer — reads a `--devirt-trace` JSONL file and prints
//! per-address stats plus the top dispatcher candidates (M1).
//!
//! Separate binary (not a subcommand) so it can run without Unicorn / the
//! emulator being usable — useful on laptops where the Docker build is
//! elsewhere but the trace file is local.

use clap::Parser;
use midas::devirt::{HandlerCatalog, TraceAnalysis};
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
    if args.extract_handlers {
        return run_extract_handlers(&args);
    }
    run_dispatcher_candidates(&args)
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
