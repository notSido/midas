//! Disassemble the Themida hot loop to understand what it's waiting for

use std::fs;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pe_file>", args[0]);
        std::process::exit(1);
    }
    
    let data = fs::read(&args[1])?;
    
    // Hot addresses from execution trace
    let image_base = 0x140000000u64;
    let hot_addrs = vec![
        0x14038d07e,
        0x14038d089,
        0x14038d080,
        0x14038d1a5,
        0x14038d079,
        0x14038d0fb,
        0x14038d108,
        0x14038d0fd,
        0x14038d106,
        0x14038d113,
    ];
    
    println!("Disassembling Themida hot loop addresses...\n");
    
    // .boot section: VirtAddr 0x38d000, RawAddr 0x4ac00
    let boot_virt_addr = 0x38d000u64;
    let boot_raw_addr = 0x4ac00usize;
    
    for &va in &hot_addrs {
        let rva = va - image_base;
        
        // Calculate file offset from RVA
        let offset = if rva >= boot_virt_addr {
            boot_raw_addr + ((rva - boot_virt_addr) as usize)
        } else {
            rva as usize
        };
        
        if offset >= data.len() {
            println!("0x{:x}: OUT OF BOUNDS (offset 0x{:x})", va, offset);
            continue;
        }
        
        // Disassemble 32 bytes from this address
        let code = &data[offset..std::cmp::min(offset + 32, data.len())];
        
        let mut decoder = Decoder::with_ip(64, code, va, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        
        println!("0x{:x} (RVA 0x{:x}, offset 0x{:x}):", va, rva, offset);
        
        let mut instruction = Instruction::default();
        let mut count = 0;
        while decoder.can_decode() && count < 5 {
            decoder.decode_out(&mut instruction);
            
            let mut output = String::new();
            formatter.format(&instruction, &mut output);
            
            println!("  {:016X}  {}", instruction.ip(), output);
            count += 1;
        }
        println!();
    }
    
    println!("\nAnalysis:");
    println!("- These 10 addresses account for most of the 10M instructions");
    println!("- Loop is only ~199 unique addresses total");
    println!("- Themida is stuck waiting for something");
    
    Ok(())
}
