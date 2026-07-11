use std::{env, fs, process};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use midas::{
    emu::{Emu, FaultKind, RegisterX86, RunReport, StopReason},
    pe::PeImage,
};

const DEFAULT_CAP: u64 = 50_000_000;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "probe_sample".to_owned());
    let path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <path-to-pe> [instruction-cap]"))?;
    let cap = match args.next() {
        Some(value) => value
            .parse::<u64>()
            .map_err(|error| format!("invalid instruction cap {value:?}: {error}"))?,
        None => DEFAULT_CAP,
    };
    if args.next().is_some() {
        return Err(format!("usage: {program} <path-to-pe> [instruction-cap]"));
    }

    let bytes = fs::read(&path).map_err(|error| format!("failed to read {path:?}: {error}"))?;
    let image =
        PeImage::parse(&bytes).map_err(|error| format!("failed to parse {path:?}: {error}"))?;

    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;

    let entry = image.entry_point_va();
    let report = emu
        .run_observed(entry, cap)
        .map_err(|error| format!("failed to run emulator: {error}"))?;

    print_report(&emu, &image, entry, cap, &report);
    Ok(())
}

fn print_report(emu: &Emu, image: &PeImage, entry: u64, cap: u64, report: &RunReport) {
    println!("image_base: 0x{:016x}", image.image_base);
    println!("entry_va:   0x{entry:016x}");
    println!("cap:        {cap}");
    println!("stop:       {}", format_stop_reason(&report.stop_reason));
    println!("final_rip:  0x{:016x}", report.final_rip);
    println!("instrs:     {}", report.instructions_executed);

    if let Some(rva) = report
        .final_rip
        .checked_sub(image.image_base)
        .and_then(|value| u32::try_from(value).ok())
    {
        if let Some(section) = image.section_containing_rva(rva) {
            println!("rip_rva:    0x{rva:08x}");
            println!("rip_section: {}", section.name);
        }
    }

    println!("recent_rips:");
    let start = report.recent_rips.len().saturating_sub(16);
    for rip in &report.recent_rips[start..] {
        println!("  {}", format_address_with_section(image, *rip));
    }

    println!("registers:");
    for (reg, value) in &report.registers {
        println!("  {} = 0x{value:016x}", register_name(*reg));
    }

    print_recent_disassembly(emu, image, report);
    print_memory_dumps(emu, &report.stop_reason);
}

fn format_stop_reason(reason: &StopReason) -> String {
    match reason {
        StopReason::ReachedInstructionCap => "instruction cap reached".to_owned(),
        StopReason::ReachedUntil => "until address reached".to_owned(),
        StopReason::IndirectTransferObserved => "indirect transfer observed".to_owned(),
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

fn print_recent_disassembly(emu: &Emu, image: &PeImage, report: &RunReport) {
    println!("disassembly of recent instructions:");
    let start = report.recent_rips.len().saturating_sub(24);
    for address in &report.recent_rips[start..] {
        match emu.read_mem(*address, 16) {
            Ok(bytes) => {
                let instruction = format_instruction(*address, &bytes);
                let section = format_section_annotation(image, *address)
                    .map(|annotation| format!(" ; {annotation}"))
                    .unwrap_or_default();
                println!("  0x{address:016x}: {instruction}{section}");
            }
            Err(_) => println!("  0x{address:016x}: <unreadable>"),
        }
    }
}

fn format_instruction(address: u64, bytes: &[u8]) -> String {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(&instruction, &mut output);
    output
}

fn print_memory_dumps(emu: &Emu, stop_reason: &StopReason) {
    println!("memory dumps:");
    let StopReason::MemoryFault(fault) = stop_reason else {
        println!("  not available (stop reason was not a memory fault)");
        return;
    };

    println!(
        "  fault: kind={} address=0x{:016x}",
        format_fault_kind(fault.kind),
        fault.address
    );

    match emu.read_reg(RegisterX86::RSP) {
        Ok(rsp) => match emu.read_mem(rsp, 32) {
            Ok(bytes) => {
                println!("  [RSP] 0x{rsp:016x}: {}", format_hex_bytes(&bytes));
                if let Some(value) = read_le_u64(&bytes) {
                    println!("  possible return address if this was a RET: 0x{value:016x}");
                }
            }
            Err(_) => println!("  [RSP] 0x{rsp:016x}: <unreadable>"),
        },
        Err(error) => println!("  RSP: <unreadable register: {error}>"),
    }

    for reg in [
        RegisterX86::RAX,
        RegisterX86::RBX,
        RegisterX86::RCX,
        RegisterX86::RDX,
        RegisterX86::RSI,
        RegisterX86::RDI,
        RegisterX86::RBP,
    ] {
        match emu.read_reg(reg) {
            Ok(address) => match emu.read_mem(address, 32) {
                Ok(bytes) => println!(
                    "  {} -> 0x{address:016x}: {}",
                    register_name(reg),
                    format_hex_bytes(&bytes)
                ),
                Err(_) => println!("  {}=0x{address:016x} -> unmapped", register_name(reg)),
            },
            Err(error) => println!("  {}: <unreadable register: {error}>", register_name(reg)),
        }
    }
}

fn read_le_u64(bytes: &[u8]) -> Option<u64> {
    let value = bytes.get(..8)?;
    Some(u64::from_le_bytes(value.try_into().ok()?))
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_address_with_section(image: &PeImage, address: u64) -> String {
    match format_section_annotation(image, address) {
        Some(annotation) => format!("0x{address:016x} {annotation}"),
        None => format!("0x{address:016x}"),
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

fn register_name(reg: RegisterX86) -> &'static str {
    match reg {
        RegisterX86::RAX => "RAX",
        RegisterX86::RBX => "RBX",
        RegisterX86::RCX => "RCX",
        RegisterX86::RDX => "RDX",
        RegisterX86::RSI => "RSI",
        RegisterX86::RDI => "RDI",
        RegisterX86::RBP => "RBP",
        RegisterX86::RSP => "RSP",
        RegisterX86::R8 => "R8",
        RegisterX86::R9 => "R9",
        RegisterX86::R10 => "R10",
        RegisterX86::R11 => "R11",
        RegisterX86::R12 => "R12",
        RegisterX86::R13 => "R13",
        RegisterX86::R14 => "R14",
        RegisterX86::R15 => "R15",
        RegisterX86::RIP => "RIP",
        RegisterX86::EFLAGS => "RFLAGS",
        _ => "UNKNOWN",
    }
}
