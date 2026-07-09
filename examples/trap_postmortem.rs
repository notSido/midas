// Post-mortem for the import/API trap loop. Runs `run_with_import_trap` to
// whatever wall the sample hits, then dumps the stop reason, a register snapshot,
// the disassembled tail of executed instructions, and the stack top (including the
// value a trailing `ret` would have consumed). Sample-dependent; not a committed
// test. Used to characterise the post-GetProcAddress control transfer to address 0
// (see docs/FINDINGS-M3-import-wall.md).
use std::{env, fs, process};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use midas::{
    emu::{Emu, RegisterX86},
    pe::PeImage,
    win64::{run_with_import_trap, Win64Env},
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
    let path = env::args()
        .nth(1)
        .ok_or("usage: trap_postmortem <pe> [per_run_cap] [max_calls]")?;
    let per_run_cap = env::args()
        .nth(2)
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(|e| format!("invalid per_run_cap: {e}"))?
        .unwrap_or(DEFAULT_PER_RUN_CAP);
    let max_calls = env::args()
        .nth(3)
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid max_calls: {e}"))?
        .unwrap_or(DEFAULT_MAX_CALLS);

    let bytes = fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
    let image = PeImage::parse(&bytes).map_err(|e| format!("parse: {e}"))?;

    let mut emu = Emu::new().map_err(|e| format!("emu: {e}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|e| format!("map: {e}"))?;
    let mut env = Win64Env::new(image.image_base);

    let result = run_with_import_trap(
        &mut env,
        &mut emu,
        &image,
        image.entry_point_va(),
        per_run_cap,
        max_calls,
    )
    .map_err(|e| format!("trap: {e}"))?;

    println!("handled: {:?}", result.handled);
    println!("stop:    {:?}", result.stop);

    println!("\nregisters:");
    for reg in REGS {
        if let Ok(v) = emu.read_reg(reg) {
            println!("  {reg:?} = 0x{v:016x}");
        }
    }

    println!("\nlast executed instructions:");
    let rips = emu.recent_rips();
    let start = rips.len().saturating_sub(24);
    for &addr in &rips[start..] {
        match emu.read_mem(addr, 16) {
            Ok(b) => {
                let mut dec = Decoder::with_ip(64, &b, addr, DecoderOptions::NONE);
                let insn = dec.decode();
                let mut out = String::new();
                NasmFormatter::new().format(&insn, &mut out);
                let ann = addr
                    .checked_sub(image.image_base)
                    .and_then(|rva| u32::try_from(rva).ok())
                    .and_then(|rva| image.section_containing_rva(rva).map(|s| (s, rva)))
                    .map(|(s, rva)| format!("  ; {}+0x{rva:08x}", s.name))
                    .unwrap_or_default();
                println!("  0x{addr:016x}: {out}{ann}");
            }
            Err(_) => println!("  0x{addr:016x}: <unreadable>"),
        }
    }

    println!("\n[RSP] window:");
    if let Ok(rsp) = emu.read_reg(RegisterX86::RSP) {
        for i in -1i64..8 {
            let a = (rsp as i64 + i * 8) as u64;
            match emu.read_mem(a, 8) {
                Ok(b) => {
                    let v = u64::from_le_bytes(b.as_slice().try_into().unwrap());
                    let note = if i == -1 { "  <- value a trailing `ret` consumed" } else { "" };
                    println!("  [rsp{:+#05x}] 0x{a:016x} = 0x{v:016x}{note}", i * 8);
                }
                Err(_) => println!("  [rsp{:+#05x}] 0x{a:016x} = <unreadable>", i * 8),
            }
        }
    }

    Ok(())
}

const REGS: [RegisterX86; 17] = [
    RegisterX86::RAX,
    RegisterX86::RBX,
    RegisterX86::RCX,
    RegisterX86::RDX,
    RegisterX86::RSI,
    RegisterX86::RDI,
    RegisterX86::RBP,
    RegisterX86::RSP,
    RegisterX86::R8,
    RegisterX86::R9,
    RegisterX86::R10,
    RegisterX86::R11,
    RegisterX86::R12,
    RegisterX86::R13,
    RegisterX86::R14,
    RegisterX86::R15,
    RegisterX86::RIP,
];
