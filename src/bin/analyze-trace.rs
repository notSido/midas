//! Offline trace analyzer — reads a `--devirt-trace` JSONL file and prints
//! per-address stats plus the top dispatcher candidates (M1).
//!
//! Separate binary (not a subcommand) so it can run without Unicorn / the
//! emulator being usable — useful on laptops where the Docker build is
//! elsewhere but the trace file is local.

use clap::Parser;
use midas::devirt::TraceAnalysis;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "analyze-trace")]
#[command(about = "Analyze a midas devirt-trace JSONL file", long_about = None)]
struct Args {
    /// Path to a JSONL trace produced by `midas --devirt-trace`.
    #[arg(short, long)]
    input: PathBuf,

    /// Number of dispatcher candidates to print.
    #[arg(long, default_value = "10")]
    top: usize,

    /// Also print up to N successors per candidate (handler entries).
    #[arg(long, default_value = "16")]
    successors_per_candidate: usize,
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
