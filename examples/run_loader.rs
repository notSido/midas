use std::{env, fs, process};

use midas::{
    emu::Emu,
    pe::PeImage,
    win64::{read_import_by_name, run_with_import_trap, TrapStop, Win64Env},
};

const DEFAULT_PER_RUN_CAP: u64 = 60_000_000;
const DEFAULT_MAX_CALLS: usize = 200;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "run_loader".to_owned());
    let path = args.next().ok_or_else(|| usage(&program))?;
    let per_run_cap = parse_arg(args.next(), DEFAULT_PER_RUN_CAP, "per_run_cap")?;
    let max_calls = parse_arg(args.next(), DEFAULT_MAX_CALLS, "max_calls")?;
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let bytes = fs::read(&path).map_err(|error| format!("failed to read {path:?}: {error}"))?;
    let image =
        PeImage::parse(&bytes).map_err(|error| format!("failed to parse {path:?}: {error}"))?;

    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;

    let mut env = Win64Env::new(image.image_base);
    let result = run_with_import_trap(
        &mut env,
        &mut emu,
        &image,
        image.entry_point_va(),
        per_run_cap,
        max_calls,
    )
    .map_err(|error| format!("failed to run loader: {error}"))?;

    println!("handled APIs:");
    for (index, name) in result.handled.iter().enumerate() {
        println!("  {:03}: {name}", index + 1);
    }

    println!("stop: {}", format_stop(&emu, &image, &result.stop));
    Ok(())
}

fn usage(program: &str) -> String {
    format!("usage: {program} <pe> [per_run_cap] [max_calls]")
}

fn parse_arg<T>(value: Option<String>, default: T, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match value {
        Some(value) => value
            .parse::<T>()
            .map_err(|error| format!("invalid {name} {value:?}: {error}")),
        None => Ok(default),
    }
}

fn format_stop(emu: &Emu, image: &PeImage, stop: &TrapStop) -> String {
    match stop {
        TrapStop::UnhandledApi { name, rva } => {
            let resolved = read_import_by_name(emu, image.image_base, image.size_of_image, *rva)
                .map_or_else(
                    || "unresolved import-by-name".to_owned(),
                    |resolved| format!("import-by-name={resolved}"),
                );
            format!("unhandled API {name} at rva=0x{rva:08x} ({resolved})")
        }
        TrapStop::UnexpectedFault { address } => {
            format!("unexpected fetch fault at 0x{address:016x}")
        }
        TrapStop::InstructionCap => "instruction cap reached".to_owned(),
        TrapStop::Other(value) => value.clone(),
    }
}
