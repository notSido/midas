//! PE loader for Unicorn emulation

use crate::pe::PeFile;
use crate::{Result, UnpackError};
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Prot, Arch, Mode};

/// PE loader that maps sections into Unicorn memory
pub struct PeLoader {
    pe: PeFile,
}

impl PeLoader {
    pub fn new(pe: PeFile) -> Self {
        Self { pe }
    }
    
    /// Load PE into Unicorn emulator
    pub fn load_into_unicorn(&self, emu: &mut Unicorn<'_, ()>) -> Result<u64> {
        log::info!("Loading PE into emulator at base: 0x{:x}", self.pe.image_base);
        
        // Map the entire image
        let aligned_size = align_up(self.pe.size_of_image, 0x1000);
        emu.mem_map(self.pe.image_base, aligned_size, Prot::ALL)
            .map_err(|e| UnpackError::MemoryError(format!("Failed to map image: {:?}", e)))?;
        
        // Write PE headers
        let header_size = self.pe.size_of_headers as usize;
        
        emu.mem_write(self.pe.image_base, &self.pe.data[..header_size])
            .map_err(|e| UnpackError::MemoryError(format!("Failed to write headers: {:?}", e)))?;
        
        // Load sections
        for section in self.pe.sections() {
            let section_name = String::from_utf8_lossy(&section.name);
            log::debug!("Loading section: {}", section_name);
            
            let virtual_addr = self.pe.image_base + section.virtual_address as u64;
            let raw_ptr = section.pointer_to_raw_data as usize;
            let raw_size = section.size_of_raw_data as usize;
            
            if raw_size > 0 && raw_ptr + raw_size <= self.pe.data.len() {
                let section_data = &self.pe.data[raw_ptr..raw_ptr + raw_size];
                emu.mem_write(virtual_addr, section_data)
                    .map_err(|e| UnpackError::MemoryError(
                        format!("Failed to write section {}: {:?}", section_name, e)
                    ))?;
            }
        }
        
        // Allocate stack
        let stack_base = 0x00100000u64;
        let stack_size = 0x00100000u64; // 1MB stack
        emu.mem_map(stack_base, stack_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackError::MemoryError(format!("Failed to map stack: {:?}", e)))?;
        
        let stack_pointer = stack_base + (stack_size as u64) - 0x1000;
        
        log::info!("Stack allocated at 0x{:x}, RSP: 0x{:x}", stack_base, stack_pointer);
        
        Ok(stack_pointer)
    }
    
    /// Get image base
    pub fn image_base(&self) -> u64 {
        self.pe.image_base
    }
    
    /// Get entry point address
    pub fn entry_point(&self) -> u64 {
        self.pe.image_base + self.pe.entry_point
    }
    
    /// Get PE file reference
    pub fn pe(&self) -> &PeFile {
        &self.pe
    }
}

/// Align value up to alignment
fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}
