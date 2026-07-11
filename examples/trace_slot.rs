use std::{env, fs, process};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use midas::{
    emu::{Emu, PersistentWatchHit, RegisterX86},
    pe::PeImage,
    win64::{run_with_import_trap, TrapStop, Win64Env},
};

const DEFAULT_HIT_CAP: usize = 4096;
/// Each hit owns 18 register/value pairs, so keep retained diagnostics and output bounded.
const MAX_HIT_CAP: usize = 16_384;
const DEFAULT_PER_RUN_CAP: u64 = 60_000_000;
const DEFAULT_MAX_CALLS: usize = 200;
const DEFAULT_RANGE_SIZE: u64 = 8;
/// Limit the final byte dump to one page even when the watched range is much larger.
const MAX_FINAL_DUMP_BYTES: u64 = 4096;
const DISASM_BYTES: usize = 16;
const HEX_ROW: usize = 16;

const DISPLAY_REGISTERS: [(RegisterX86, &str); 18] = [
    (RegisterX86::RAX, "rax"),
    (RegisterX86::RBX, "rbx"),
    (RegisterX86::RCX, "rcx"),
    (RegisterX86::RDX, "rdx"),
    (RegisterX86::RSI, "rsi"),
    (RegisterX86::RDI, "rdi"),
    (RegisterX86::RBP, "rbp"),
    (RegisterX86::RSP, "rsp"),
    (RegisterX86::R8, "r8"),
    (RegisterX86::R9, "r9"),
    (RegisterX86::R10, "r10"),
    (RegisterX86::R11, "r11"),
    (RegisterX86::R12, "r12"),
    (RegisterX86::R13, "r13"),
    (RegisterX86::R14, "r14"),
    (RegisterX86::R15, "r15"),
    (RegisterX86::RIP, "rip"),
    (RegisterX86::EFLAGS, "rflags"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FinalDumpPlan {
    total_len: u64,
    read_len: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = match args.next() {
        Some(value) => value,
        None => "trace_slot".to_owned(),
    };
    let path = args.next().ok_or_else(|| usage(&program))?;
    let start = parse_hex_arg(args.next().ok_or_else(|| usage(&program))?, "hex-start")?;
    let end = match args.next() {
        Some(value) => parse_hex_arg(value, "hex-end")?,
        None => start.checked_add(DEFAULT_RANGE_SIZE).ok_or_else(|| {
            format!(
                "default watched range overflows: start=0x{start:016x}, size={DEFAULT_RANGE_SIZE:#x}"
            )
        })?,
    };
    if end <= start {
        return Err(format!(
            "hex-end must be greater than hex-start: start=0x{start:016x}, end=0x{end:016x}"
        ));
    }
    let hit_cap = validate_hit_cap(parse_optional_dec(args.next(), DEFAULT_HIT_CAP, "hit-cap")?)?;
    let per_run_cap = parse_optional_dec(args.next(), DEFAULT_PER_RUN_CAP, "per-run-cap")?;
    let max_calls = parse_optional_dec(args.next(), DEFAULT_MAX_CALLS, "max-calls")?;
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let bytes = fs::read(&path).map_err(|error| format!("failed to read {path:?}: {error}"))?;
    let image =
        PeImage::parse(&bytes).map_err(|error| format!("failed to parse {path:?}: {error}"))?;

    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;
    emu.configure_persistent_watch(&[(start, end)], hit_cap)
        .map_err(|error| format!("failed to configure persistent watch: {error}"))?;

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

    print_run_summary(&image, start, end, hit_cap, per_run_cap, max_calls, &result);
    print_hits(&emu, &image, &emu.persistent_watch_hits());
    print_final_bytes(&emu, start, end)?;
    Ok(())
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} <pe> <hex-start> [hex-end] [hit-cap] [per-run-cap] [max-calls]\n\
         hit-cap defaults to {DEFAULT_HIT_CAP} and must not exceed {MAX_HIT_CAP}; each hit stores 18 registers\n\
         final byte output is limited to the first {MAX_FINAL_DUMP_BYTES} watched bytes"
    )
}

fn parse_hex_arg(value: String, name: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(&value);
    u64::from_str_radix(digits, 16).map_err(|error| format!("invalid {name} {value:?}: {error}"))
}

fn parse_optional_dec<T>(value: Option<String>, default: T, name: &str) -> Result<T, String>
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

fn validate_hit_cap(hit_cap: usize) -> Result<usize, String> {
    if hit_cap > MAX_HIT_CAP {
        return Err(format!(
            "hit-cap {hit_cap} exceeds maximum {MAX_HIT_CAP}; each hit owns an 18-register snapshot"
        ));
    }
    Ok(hit_cap)
}

fn print_run_summary(
    image: &PeImage,
    start: u64,
    end: u64,
    hit_cap: usize,
    per_run_cap: u64,
    max_calls: usize,
    result: &midas::win64::TrapRun,
) {
    println!("image_base:   0x{:016x}", image.image_base);
    println!("entry_va:     0x{:016x}", image.entry_point_va());
    println!("watch:        0x{start:016x}..0x{end:016x}");
    println!("hit_cap:      {hit_cap}");
    println!("per_run_cap:  {per_run_cap}");
    println!("max_calls:    {max_calls}");

    println!("handled APIs:");
    if result.handled.is_empty() {
        println!("  <none>");
    } else {
        for (index, name) in result.handled.iter().enumerate() {
            println!("  {:03}: {name}", index + 1);
        }
    }
    println!("stop:         {}", format_stop(&result.stop));
}

fn print_hits(emu: &Emu, image: &PeImage, hits: &[PersistentWatchHit]) {
    println!("watch hits:");
    if hits.is_empty() {
        println!("  <none>");
        return;
    }

    for hit in hits {
        let op = if hit.is_write { "W" } else { "R" };
        println!(
            "  [{:>12}] {op} addr=0x{:016x}{} size={} value={} rip=0x{:016x}{}",
            hit.global_instruction_index,
            hit.address,
            format_image_annotation(image, hit.address, "addr_rva"),
            hit.size,
            format_optional_value(hit.value),
            hit.rip,
            format_image_annotation(image, hit.rip, "rip_rva"),
        );
        println!("      insn: {}", format_instruction(emu, hit.rip));
        println!("      regs: {}", format_registers(&hit.registers));
    }
}

fn print_final_bytes(emu: &Emu, start: u64, end: u64) -> Result<(), String> {
    println!("final bytes:");
    let plan = plan_final_dump(start, end)?;
    if let Some(message) = format_dump_limit(plan) {
        println!("{message}");
    }
    let len = usize::try_from(plan.read_len).map_err(|error| {
        format!(
            "bounded final dump length does not fit usize ({:#x} bytes): {error}",
            plan.read_len
        )
    })?;
    match emu.read_mem(start, len) {
        Ok(bytes) => print_hex_dump(start, &bytes),
        Err(error) => println!("  <unreadable: {error}>"),
    }
    Ok(())
}

fn plan_final_dump(start: u64, end: u64) -> Result<FinalDumpPlan, String> {
    let total_len = end.checked_sub(start).ok_or_else(|| {
        format!("watched range underflows: start=0x{start:016x}, end=0x{end:016x}")
    })?;
    Ok(FinalDumpPlan {
        total_len,
        read_len: total_len.min(MAX_FINAL_DUMP_BYTES),
    })
}

fn format_dump_limit(plan: FinalDumpPlan) -> Option<String> {
    (plan.read_len < plan.total_len).then(|| {
        format!(
            "  <truncated: watched range is {} bytes; dumping first {} bytes>",
            plan.total_len, plan.read_len
        )
    })
}

fn print_hex_dump(base: u64, bytes: &[u8]) {
    if bytes.is_empty() {
        println!("  <empty>");
        return;
    }

    for (row, chunk) in bytes.chunks(HEX_ROW).enumerate() {
        let Some(row_offset) = u64::try_from(row)
            .ok()
            .and_then(|row| row.checked_mul(HEX_ROW as u64))
        else {
            println!("  <offset overflow>");
            return;
        };
        let Some(address) = base.checked_add(row_offset) else {
            println!("  <address overflow>");
            return;
        };
        println!("  0x{address:016x}: {}", format_hex_bytes(chunk));
    }
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn format_stop(stop: &TrapStop) -> String {
    match stop {
        TrapStop::UnhandledApi { name, rva } => {
            format!("unhandled API {name} at export-stub or import rva=0x{rva:08x}")
        }
        TrapStop::UnexpectedFault { address } => {
            format!("unexpected fetch fault at 0x{address:016x}")
        }
        TrapStop::InstructionCap => "instruction cap reached".to_owned(),
        TrapStop::NullControlTransfer => "null control transfer".to_owned(),
        TrapStop::Other(value) => value.clone(),
    }
}

fn format_optional_value(value: Option<u64>) -> String {
    match value {
        Some(value) => format!("Some(0x{value:x})"),
        None => "None".to_owned(),
    }
}

fn format_instruction(emu: &Emu, address: u64) -> String {
    let bytes = match emu.read_mem(address, DISASM_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return format!("<unreadable: {error}>"),
    };

    let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(&instruction, &mut output);
    output
}

fn format_image_annotation(image: &PeImage, address: u64, label: &str) -> String {
    let Some(rva) = image_rva(image, address) else {
        return String::new();
    };
    let section = image
        .section_containing_rva(rva)
        .map(|section| format!(" {}", section.name))
        .unwrap_or_default();
    format!(" {label}=0x{rva:08x}{section}")
}

fn image_rva(image: &PeImage, address: u64) -> Option<u32> {
    let rva = address
        .checked_sub(image.image_base)
        .and_then(|value| u32::try_from(value).ok())?;
    (rva < image.size_of_image).then_some(rva)
}

fn format_registers(registers: &[(RegisterX86, u64)]) -> String {
    DISPLAY_REGISTERS
        .iter()
        .map(|(reg, name)| match register_value(registers, *reg) {
            Some(value) => format!("{name}=0x{value:016x}"),
            None => format!("{name}=<missing>"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn register_value(registers: &[(RegisterX86, u64)], reg: RegisterX86) -> Option<u64> {
    registers
        .iter()
        .find_map(|(candidate, value)| (*candidate == reg).then_some(*value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_cap_validation_preserves_default_and_enforces_maximum() {
        assert_eq!(validate_hit_cap(DEFAULT_HIT_CAP), Ok(DEFAULT_HIT_CAP));
        assert_eq!(validate_hit_cap(MAX_HIT_CAP), Ok(MAX_HIT_CAP));

        let too_large = MAX_HIT_CAP.checked_add(1).unwrap();
        assert_eq!(
            validate_hit_cap(too_large),
            Err(format!(
                "hit-cap {too_large} exceeds maximum {MAX_HIT_CAP}; each hit owns an 18-register snapshot"
            ))
        );
    }

    #[test]
    fn final_dump_plan_is_checked_bounded_and_explicit() {
        let bounded = plan_final_dump(0x1000, 0x1008).unwrap();
        assert_eq!(
            bounded,
            FinalDumpPlan {
                total_len: 8,
                read_len: 8,
            }
        );
        assert_eq!(format_dump_limit(bounded), None);

        let large_end = 0x1000_u64
            .checked_add(MAX_FINAL_DUMP_BYTES)
            .and_then(|value| value.checked_add(1))
            .unwrap();
        let truncated = plan_final_dump(0x1000, large_end).unwrap();
        assert_eq!(truncated.read_len, MAX_FINAL_DUMP_BYTES);
        assert_eq!(truncated.total_len, MAX_FINAL_DUMP_BYTES + 1);
        assert_eq!(
            format_dump_limit(truncated),
            Some(format!(
                "  <truncated: watched range is {} bytes; dumping first {} bytes>",
                MAX_FINAL_DUMP_BYTES + 1,
                MAX_FINAL_DUMP_BYTES
            ))
        );

        assert!(plan_final_dump(u64::MAX, 0).is_err());
    }

    #[test]
    fn register_format_covers_the_complete_snapshot() {
        let registers = DISPLAY_REGISTERS
            .iter()
            .enumerate()
            .map(|(index, (register, _name))| (*register, index as u64))
            .collect::<Vec<_>>();
        let formatted = format_registers(&registers);

        for (index, (_register, name)) in DISPLAY_REGISTERS.iter().enumerate() {
            assert!(
                formatted.contains(&format!("{name}=0x{index:016x}")),
                "missing {name} from {formatted}"
            );
        }
        assert_eq!(formatted.split_whitespace().count(), 18);
    }
}
