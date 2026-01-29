use clap::Parser;
use midas::*;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "midas")]
#[command(about = "Midas - Themida 3.x unpacker for Linux", long_about = None)]
struct Args {
    /// Input PE file (Themida-protected)
    #[arg(short, long)]
    input: PathBuf,
    
    /// Output file for unpacked PE
    #[arg(short, long)]
    output: Option<PathBuf>,
    
    /// Maximum instructions to emulate (default: 10 million)
    #[arg(short, long, default_value = "10000000")]
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

