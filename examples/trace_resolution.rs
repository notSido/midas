use std::{env, fs, process};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use midas::{
    emu::{Emu, FaultKind, RunReport, StopReason, TraceEvent},
    pe::PeImage,
};

const DEFAULT_WINDOW: u64 = 4_000;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "trace_resolution".to_owned());
    let path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <path-to-pe> <fault-count> [trace-window]"))?;
    let fault_count = args
        .next()
        .ok_or_else(|| format!("usage: {program} <path-to-pe> <fault-count> [trace-window]"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid fault count: {error}"))?;
    let window = match args.next() {
        Some(value) => value
            .parse::<u64>()
            .map_err(|error| format!("invalid trace window: {error}"))?,
        None => DEFAULT_WINDOW,
    };
    if args.next().is_some() {
        return Err(format!(
            "usage: {program} <path-to-pe> <fault-count> [trace-window]"
        ));
    }

    let bytes = fs::read(&path).map_err(|error| format!("failed to read {path:?}: {error}"))?;
    let image =
        PeImage::parse(&bytes).map_err(|error| format!("failed to parse {path:?}: {error}"))?;

    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;

    let entry = image.entry_point_va();
    let (report, trace_events) = emu
        .run_traced(entry, fault_count, window)
        .map_err(|error| format!("failed to run traced emulator: {error}"))?;

    print_report(&image, entry, fault_count, window, &report);
    print_trace(&emu, &image, &trace_events);
    Ok(())
}

fn print_report(image: &PeImage, entry: u64, fault_count: u64, window: u64, report: &RunReport) {
    println!("image_base:  0x{:016x}", image.image_base);
    println!("entry_va:    0x{entry:016x}");
    println!("fault_count: {fault_count}");
    println!("window:      {window}");
    println!("stop:        {}", format_stop_reason(&report.stop_reason));
    println!("final_rip:   0x{:016x}", report.final_rip);
    println!("instrs:      {}", report.instructions_executed);
}

fn print_trace(emu: &Emu, image: &PeImage, trace_events: &[TraceEvent]) {
    println!("trace:");
    for event in trace_events {
        match event {
            TraceEvent::Insn { address } => print_instruction(emu, image, *address),
            TraceEvent::MemRead {
                address,
                size,
                value,
            } => println!("  R 0x{address:016x} ({size}) = 0x{value:x}"),
            TraceEvent::MemWrite {
                address,
                size,
                value,
            } => println!("  W 0x{address:016x} ({size}) = 0x{value:x}"),
        }
    }
}

fn print_instruction(emu: &Emu, image: &PeImage, address: u64) {
    let instruction = match emu.read_mem(address, 16) {
        Ok(bytes) => format_instruction(address, &bytes),
        Err(_) => "<unreadable>".to_owned(),
    };
    let section = format_section_annotation(image, address)
        .map(|annotation| format!(" ; {annotation}"))
        .unwrap_or_default();
    println!("  I 0x{address:016x}: {instruction}{section}");
}

fn format_instruction(address: u64, bytes: &[u8]) -> String {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(&instruction, &mut output);
    output
}

fn format_stop_reason(reason: &StopReason) -> String {
    match reason {
        StopReason::ReachedInstructionCap => "instruction cap reached".to_owned(),
        StopReason::ReachedUntil => "until address reached".to_owned(),
        StopReason::IndirectTransferObserved => "indirect transfer observed".to_owned(),
        StopReason::IndirectTransferCaptureFailed => {
            "indirect-transfer proof capture failed".to_owned()
        }
        StopReason::IndirectTransferStopFailed => "indirect-transfer hook stop failed".to_owned(),
        StopReason::MemoryFault(fault) => format!(
            "memory fault kind={} address=0x{:016x}",
            format_fault_kind(fault.kind),
            fault.address
        ),
        StopReason::InvalidInstruction => "invalid instruction".to_owned(),
        StopReason::Other(value) => format!("other: {value}"),
    }
}

fn format_fault_kind(kind: FaultKind) -> &'static str {
    match kind {
        FaultKind::ReadUnmapped => "read-unmapped",
        FaultKind::WriteUnmapped => "write-unmapped",
        FaultKind::FetchUnmapped => "fetch-unmapped",
        FaultKind::ReadProt => "read-prot",
        FaultKind::WriteProt => "write-prot",
        FaultKind::FetchProt => "fetch-prot",
        FaultKind::Other => "other",
    }
}

fn format_section_annotation(image: &PeImage, address: u64) -> Option<String> {
    let rva = address
        .checked_sub(image.image_base)
        .and_then(|value| u32::try_from(value).ok())?;

    image
        .section_containing_rva(rva)
        .map(|section| format!("{}+0x{rva:08x}", section.name))
}
