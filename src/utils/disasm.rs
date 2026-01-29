//! Disassembly utilities using iced-x86

use iced_x86::{Decoder, DecoderOptions, Instruction};

/// Disassemble a single instruction at address
pub fn disassemble_at(code: &[u8], rip: u64) -> Option<(Instruction, usize)> {
    let mut decoder = Decoder::with_ip(64, code, rip, DecoderOptions::NONE);
    
    if decoder.can_decode() {
        let instr = decoder.decode();
        let len = instr.len();
        Some((instr, len))
    } else {
        None
    }
}

/// Disassemble multiple instructions
pub fn disassemble_block(code: &[u8], rip: u64, count: usize) -> Vec<(Instruction, usize)> {
    let mut decoder = Decoder::with_ip(64, code, rip, DecoderOptions::NONE);
    let mut result = Vec::new();
    
    for _ in 0..count {
        if !decoder.can_decode() {
            break;
        }
        
        let instr = decoder.decode();
        let len = instr.len();
        result.push((instr, len));
    }
    
    result
}

/// Format instruction as string
pub fn format_instruction(instr: &Instruction) -> String {
    use iced_x86::{Formatter, IntelFormatter};
    
    let mut output = String::new();
    let mut formatter = IntelFormatter::new();
    
    formatter.format(instr, &mut output);
    output
}
