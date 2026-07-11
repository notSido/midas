use std::{env, fs, process};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use midas::{
    emu::{Emu, IndirectTransferKind, IndirectTransferObservation},
    oep::{OepCandidate, OepCriterion, TransferKind, TransferObservation},
    pe::PeImage,
    win64::{run_with_cooperative_scheduler, TrapStop, Win64Env},
};

const DEFAULT_PER_RUN_CAP: u64 = 250_000_000;
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

    let oep_criterion = match OepCriterion::new(&image, image.image_base) {
        Ok(criterion) => {
            let layout = criterion.layout();
            let source_ranges =
                section_va_ranges(layout.mapped_base, &layout.loader_executable_sections)?;
            let target_ranges =
                section_va_ranges(layout.mapped_base, &layout.original_executable_sections)?;
            emu.configure_indirect_transfer_watch(&source_ranges, &target_ranges, false)
                .map_err(|error| format!("failed to arm OEP transfer observation: {error}"))?;
            println!(
                "OEP criterion armed: protector_boundary_rva=0x{:08x} loader_sections={:?} original_executable_sections={:?}",
                layout.protector_boundary_rva,
                layout
                    .loader_executable_sections
                    .iter()
                    .map(|region| region.section_index)
                    .collect::<Vec<_>>(),
                layout
                    .original_executable_sections
                    .iter()
                    .map(|region| region.section_index)
                    .collect::<Vec<_>>(),
            );
            Some(criterion)
        }
        Err(error) => {
            println!("OEP criterion unavailable: {error}");
            None
        }
    };

    let mut env = Win64Env::new(image.image_base);
    let result = run_with_cooperative_scheduler(
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

    println!("cooperative yields:");
    for (index, yielded) in result.cooperative_yields.iter().enumerate() {
        println!(
            "  {:03}: thread={} stack=0x{:016x}+0x{:x} teb=0x{:016x} instructions={} stop={:?}",
            index + 1,
            yielded.thread_id,
            yielded.stack_base,
            yielded.stack_size,
            yielded.teb_base,
            yielded.instructions_executed,
            yielded.stop,
        );
        println!("       handled={:?}", yielded.handled);
    }
    println!(
        "main instructions after first yield: {}",
        result.main_instructions_after_first_yield
    );

    match (
        oep_criterion.as_ref(),
        emu.indirect_transfer_observation(),
        emu.indirect_transfer_capture_failure(),
    ) {
        (Some(criterion), Some(observation), None) => {
            let transfer = transfer_observation(&observation);
            let candidate = criterion.evaluate(transfer).ok_or_else(|| {
                "latched indirect transfer did not satisfy the armed OEP criterion".to_owned()
            })?;
            print_oep_candidate(&candidate, &observation);
        }
        (Some(_), None, Some(failure)) => println!(
            "OEP criterion: potential edge capture failed; no candidate emitted: {failure}"
        ),
        (Some(_), None, None) => println!("OEP criterion: did not fire"),
        (Some(_), Some(_), Some(_)) => {
            return Err("OEP watch retained both an observation and a capture failure".to_owned());
        }
        (None, _, _) => println!("OEP criterion: not armed"),
    }

    println!("stop: {}", format_stop(&image, &result.stop));
    Ok(())
}

fn section_va_ranges(
    mapped_base: u64,
    sections: &[midas::oep::SectionRegion],
) -> Result<Vec<(u64, u64)>, String> {
    sections
        .iter()
        .map(|section| {
            let start = mapped_base
                .checked_add(u64::from(section.start_rva))
                .ok_or_else(|| "OEP source/target section start overflows".to_owned())?;
            let end = mapped_base
                .checked_add(u64::from(section.end_rva))
                .ok_or_else(|| "OEP source/target section end overflows".to_owned())?;
            Ok((start, end))
        })
        .collect()
}

fn transfer_observation(observation: &IndirectTransferObservation) -> TransferObservation {
    let kind = match observation.kind {
        IndirectTransferKind::Branch => TransferKind::IndirectBranch,
        IndirectTransferKind::Call => TransferKind::IndirectCall,
        IndirectTransferKind::Return => TransferKind::Return,
    };
    TransferObservation {
        source_rip: observation.source_rip,
        target_rip: observation.target_rip,
        kind,
        // The emulator watch latches only the first entry to an exact target
        // RIP and tracks target coverage from the first guest instruction.
        target_previously_executed: false,
    }
}

fn print_oep_candidate(candidate: &OepCandidate, observation: &IndirectTransferObservation) {
    println!("OEP criterion: fired (candidate pending reproducibility and disassembly review)");
    println!("OEP candidate RIP: 0x{:016x}", candidate.rip);
    println!(
        "  global instruction: {}",
        observation.global_instruction_index
    );
    println!(
        "  source: 0x{:016x} section={} kind={:?} bytes={}",
        candidate.source_rip,
        candidate.source_section_index,
        candidate.kind,
        hex_bytes(&observation.source_bytes),
    );
    println!(
        "  target section: {} runtime_bytes={}",
        candidate.target_section_index,
        hex_bytes(&observation.target_bytes),
    );
    println!("  target disassembly:");
    let mut decoder = Decoder::with_ip(
        64,
        &observation.target_bytes,
        candidate.rip,
        DecoderOptions::NONE,
    );
    let mut formatter = NasmFormatter::new();
    for _ in 0..8 {
        if !decoder.can_decode() {
            break;
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            println!("    0x{:016x}: <invalid>", instruction.ip());
            break;
        }
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        println!("    0x{:016x}: {text}", instruction.ip());
    }
    println!("  captured registers:");
    for (register, value) in &observation.registers {
        println!("    {register:?}=0x{value:016x}");
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
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

fn format_stop(_image: &PeImage, stop: &TrapStop) -> String {
    match stop {
        TrapStop::UnhandledApi { name, rva } => {
            format!("unhandled API {name} at export-stub or import rva=0x{rva:08x}")
        }
        TrapStop::UnexpectedFault { address } => {
            format!("unexpected fetch fault at 0x{address:016x}")
        }
        TrapStop::InstructionCap => "instruction cap reached".to_owned(),
        TrapStop::IndirectTransferObserved => "OEP indirect transfer observed".to_owned(),
        TrapStop::NullControlTransfer => "null control transfer".to_owned(),
        TrapStop::Other(value) => value.clone(),
    }
}
