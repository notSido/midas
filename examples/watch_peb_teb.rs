use std::{env, fs, process};

use midas::{
    emu::{
        Emu, FaultKind, RunReport, StopReason, WatchHit, PEB_BASE, PEB_SIZE, TEB_BASE, TEB_SIZE,
    },
    pe::PeImage,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "watch_peb_teb".to_owned());
    let path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <pe> <instr_cap>"))?;
    let instr_cap = args
        .next()
        .ok_or_else(|| format!("usage: {program} <pe> <instr_cap>"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid instruction cap: {error}"))?;
    if args.next().is_some() {
        return Err(format!("usage: {program} <pe> <instr_cap>"));
    }

    let bytes = fs::read(&path).map_err(|error| format!("failed to read {path:?}: {error}"))?;
    let image =
        PeImage::parse(&bytes).map_err(|error| format!("failed to parse {path:?}: {error}"))?;

    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;

    let entry_va = image.entry_point_va();
    let ranges = [
        (TEB_BASE, TEB_BASE + TEB_SIZE),
        (PEB_BASE, PEB_BASE + PEB_SIZE),
    ];
    let (report, watch_hits) = emu
        .run_watching(entry_va, instr_cap, &ranges, 256)
        .map_err(|error| format!("failed to run watched emulator: {error}"))?;

    print_report(&report);
    print_hits(&image, instr_cap, &watch_hits);
    Ok(())
}

fn print_report(report: &RunReport) {
    println!("stop:      {}", format_stop_reason(&report.stop_reason));
    println!("final_rip: 0x{:016x}", report.final_rip);
    println!("instrs:    {}", report.instructions_executed);
}

fn print_hits(image: &PeImage, instr_cap: u64, watch_hits: &[WatchHit]) {
    println!("PEB/TEB accesses:");
    if watch_hits.is_empty() {
        println!("  no PEB/TEB accesses observed in {instr_cap} instructions");
        return;
    }

    for hit in watch_hits {
        let op = if hit.is_write { "W" } else { "R" };
        let annotation = format_section_annotation(image, hit.rip)
            .map(|value| format!(" {value}"))
            .unwrap_or_default();
        println!(
            "  [{}] {op} {:#x} ({}) rip={:#x}{annotation}",
            hit.instruction_index, hit.address, hit.size, hit.rip
        );
    }
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
