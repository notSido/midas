//! PE64 file parser

use crate::{Result, UnpackError};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Represents a parsed PE64 file
pub struct PeFile {
    /// Raw file data
    pub data: Vec<u8>,
    /// Parsed PE structure
    pub pe: PE,
    /// Image base address
    pub image_base: u64,
    /// Entry point RVA
    pub entry_point: u64,
    /// Size of image
    pub size_of_image: u64,
}

impl PeFile {
    /// Load and parse a PE file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = fs::read(path)?;
        Self::from_bytes(data)
    }
    
    /// Parse PE from bytes
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let pe = PE::parse(&data)
            .map_err(|e| UnpackError::PeError(e.to_string()))?;
        
        // Verify it's 64-bit
        if !pe.is_64 {
            return Err(UnpackError::Not64Bit);
        }
        
        let image_base = pe.image_base as u64;
        let entry_point = pe.entry as u64;
        let size_of_image = pe.header.optional_header
            .ok_or(UnpackError::PeError("No optional header".into()))?
            .windows_fields
            .size_of_image as u64;
        
        Ok(PeFile {
            data,
            pe,
            image_base,
            entry_point,
            size_of_image,
        })
    }
    
    /// Get section data by name
    pub fn get_section_data(&self, name: &str) -> Option<&[u8]> {
        for section in &self.pe.sections {
            let section_name = String::from_utf8_lossy(&section.name);
            if section_name.trim_end_matches('\0') == name {
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                return Some(&self.data[start..start + size]);
            }
        }
        None
    }
    
    /// Get the .text section boundaries (code section)
    pub fn get_text_section_bounds(&self) -> Option<(u64, u64)> {
        for section in &self.pe.sections {
            let section_name = String::from_utf8_lossy(&section.name);
            if section_name.starts_with(".text") {
                let start = self.image_base + section.virtual_address as u64;
                let end = start + section.virtual_size as u64;
                return Some((start, end));
            }
        }
        None
    }
    
    /// Check if address is in code section
    pub fn is_code_address(&self, addr: u64) -> bool {
        if let Some((start, end)) = self.get_text_section_bounds() {
            addr >= start && addr < end
        } else {
            false
        }
    }
    
    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        for section in &self.pe.sections {
            let section_start = section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;
            
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some(section.pointer_to_raw_data as u64 + offset_in_section);
            }
        }
        None
    }
    
    /// Get imports
    pub fn get_imports(&self) -> Vec<(String, Vec<String>)> {
        let mut result = Vec::new();
        
        if let Some(imports) = &self.pe.imports {
            for import in imports {
                let dll_name = import.name.clone();
                let functions: Vec<String> = import.import_lookup_table
                    .iter()
                    .filter_map(|entry| entry.name.clone())
                    .collect();
                result.push((dll_name, functions));
            }
        }
        
        result
    }
}
