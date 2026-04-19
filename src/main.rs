use clap::Parser;
use midas::*;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "midas")]
#[command(about = "Midas - Themida 3.x unpacker for Linux", long_about = None)]
struct Args {
    /// Input PE file (Themida-protected). Positional argument: the
    /// *only* thing midas requires on the happy path. See
    /// `project_1_0_binary_contract` in auto-memory.
    #[arg(value_name = "PATH")]
    input: PathBuf,
    
    /// Output file for unpacked PE
    #[arg(short, long)]
    output: Option<PathBuf>,
    
    /// Maximum instructions to emulate (default: 500 million — well above
    /// what current Themida 3.x samples need to reach OEP; pass a smaller
    /// value explicitly if you want a faster fail)
    #[arg(short, long, default_value = "500000000")]
    max_instructions: u64,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Quiet mode - only print errors
    #[arg(short, long)]
    quiet: bool,
    
    /// Detect Themida version only (no unpacking)
    #[arg(long)]
    detect_only: bool,
    
    /// Output results in JSON format
    #[arg(long)]
    json: bool,
    
    /// Timeout in seconds (0 = no timeout)
    #[arg(long, default_value = "0")]
    timeout: u64,
    
    /// Show progress during emulation
    #[arg(long)]
    progress: bool,
    
    /// Workspace base address for allocations
    #[arg(long, default_value = "0x20000000")]
    workspace: String,

    /// Override the default devirt trace path (JSONL, post-OEP
    /// per-instruction). By default the trace is always produced at
    /// `<output>.trace.jsonl` — pass this only to customize. See
    /// also `--no-devirt-trace` to opt out entirely.
    #[arg(long)]
    devirt_trace: Option<PathBuf>,

    /// Opt out of producing a devirt trace. Default is on (the
    /// trace is the input to offline VM analysis). Useful for
    /// pure-unpack runs that don't need devirt; small perf win from
    /// skipping the post-OEP instruction recording.
    #[arg(long)]
    no_devirt_trace: bool,

    /// Cap on the number of post-OEP instructions recorded. Default
    /// is 10M — enough to expose the VM dispatcher on both current
    /// samples. Disarmed recorder has near-zero overhead, so leaving
    /// this alone is the right default.
    #[arg(long, default_value = "10000000")]
    devirt_trace_limit: u64,

    /// (Testing back-door — not the primary path.) Emit a one-shot
    /// register snapshot the first time this RIP fires post-OEP.
    /// Repeatable. The primary capture path is automatic: the
    /// unpacker already snapshots regs on the first firing of every
    /// indirect `jmp r<reg>` post-OEP without any flag — this exists
    /// only for targeted debugging of specific non-dispatcher RIPs.
    #[arg(long, value_parser = parse_rip, hide = true)]
    devirt_capture_regs_at: Vec<u64>,
}

fn parse_rip(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (radix, body) = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, rest)
    } else {
        (10, s)
    };
    u64::from_str_radix(body, radix).map_err(|e| format!("bad RIP {:?}: {}", s, e))
}

fn main() {
    let exit_code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {}", e);
            1
        }
    };
    process::exit(exit_code);
}

fn run() -> Result<()> {
    let args = Args::parse();
    
    // Setup logging
    let log_level = if args.quiet {
        "error"
    } else if args.verbose {
        "debug"
    } else {
        "info"
    };
    
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(None)
        .target(env_logger::Target::Stderr) // Send logs to stderr
        .init();
    
    if !args.json && !args.quiet {
        log::info!("Midas v{} - Themida Unpacker", env!("CARGO_PKG_VERSION"));
        log::info!("Input: {:?}", args.input);
    }
    
    // Load PE
    if !args.quiet && !args.json {
        log::info!("Loading PE file...");
    }
    
    let pe = match pe::PeFile::load(&args.input) {
        Ok(p) => p,
        Err(e) => {
            if e.to_string().contains("exception_rva") {
                log::warn!("PE has malformed exception data (common with Themida) - trying to continue anyway");
            }
            return Err(e);
        }
    };
    
    // Detect Themida version
    let version = themida::detect_themida(&pe)?;
    
    // If detect-only mode, just print version and exit
    if args.detect_only {
        if args.json {
            println!("{{\"themida_version\": \"{:?}\"}}", version);
        } else {
            println!("{:?}", version);
        }
        return Ok(());
    }
    
    // Determine output path
    let output_path = args.output.unwrap_or_else(|| {
        let mut path = args.input.clone();
        let stem = path.file_stem().unwrap().to_str().unwrap();
        path.set_file_name(format!("{}_unpacked.exe", stem));
        path
    });
    
    if !args.quiet && !args.json {
        log::info!("Output will be written to: {:?}", output_path);
    }
    
    // Create unpacker and run
    let start_time = Instant::now();
    let mut unpacker = unpacker::Unpacker::new(pe, args.max_instructions, args.verbose);
    // Devirt trace is produced by default — zero-config UX (see
    // `feedback_zero_config_ux` in auto-memory). The user doesn't
    // have to know it exists; downstream tools consume it to
    // build the VM descriptor + walker. If `--devirt-trace` was
    // passed, use that path; otherwise derive a deterministic
    // sibling of the output PE. `--no-devirt-trace` opts out for
    // pure-unpack runs that don't need devirt analysis.
    let trace_path = args.devirt_trace.clone().unwrap_or_else(|| {
        let mut p = output_path.clone();
        let stem = p.file_stem().unwrap().to_str().unwrap().to_string();
        p.set_file_name(format!("{}.trace.jsonl", stem));
        p
    });
    if !args.no_devirt_trace {
        unpacker.set_devirt_trace(trace_path.clone(), args.devirt_trace_limit);
        if !args.devirt_capture_regs_at.is_empty() {
            unpacker.set_devirt_capture_regs_at(args.devirt_capture_regs_at.clone());
        }
        if !args.quiet && !args.json {
            log::info!("Devirt trace will be written to: {:?}", trace_path);
        }
    } else if !args.devirt_capture_regs_at.is_empty() {
        log::warn!(
            "--devirt-capture-regs-at ignored because --no-devirt-trace was set"
        );
    }
    
    let unpack_result = unpacker.unpack(&output_path);
    let elapsed = start_time.elapsed();
    
    match unpack_result {
        Ok(()) => {
            if args.json {
                let result = UnpackResult::success(
                    None, // OEP not tracked yet
                    format!("{:?}", version),
                    args.max_instructions, // TODO: track actual instructions
                    output_path.clone(),
                );
                println!("{}", result.to_json().unwrap_or_else(|_| 
                    format!("{{\"success\": true, \"output\": \"{}\"}}", output_path.display())
                ));
            } else if !args.quiet {
                // Success message to stdout
                println!("Unpacking completed successfully in {:.2}s", elapsed.as_secs_f64());
                println!("Output: {:?}", output_path);
            }
            Ok(())
        }
        Err(e) => {
            if args.json {
                let result = UnpackResult::failure(
                    e.to_string(),
                    Some(format!("{:?}", version)),
                );
                println!("{}", result.to_json().unwrap_or_else(|_| 
                    format!("{{\"success\": false, \"error\": \"{}\"}}", e)
                ));
            }
            Err(e)
        }
    }
}

