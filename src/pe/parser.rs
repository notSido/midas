//! PE64 file parser

use crate::{Result, UnpackError};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Represents a parsed PE64 file
pub struct PeFile {
    /// Raw file data
    pub data: Vec<u8>,
    /// Image base address
    pub image_base: u64,
    /// Entry point RVA
    pub entry_point: u64,
    /// Size of image
    pub size_of_image: u64,
    /// Size of headers
    pub size_of_headers: u32,
    /// Section headers (cached)
    sections: Vec<goblin::pe::section_table::SectionTable>,
    /// Import data (cached)
    imports: Vec<(String, Vec<String>)>,
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
            .map_err(|e| {
                // Themida often has malformed exception data, ignore that specific error
                let err_str = e.to_string();
                if err_str.contains("exception_rva") {
                    log::warn!("Ignoring malformed exception data (common with packers)");
                }
                UnpackError::PeError(err_str)
            })?;
        
        // Verify it's 64-bit
        if !pe.is_64 {
            return Err(UnpackError::Not64Bit);
        }
        
        let image_base = pe.image_base as u64;
        let entry_point = pe.entry as u64;
        let opt_header = pe.header.optional_header
            .ok_or(UnpackError::PeError("No optional header".into()))?;
        let size_of_image = opt_header.windows_fields.size_of_image as u64;
        let size_of_headers = opt_header.windows_fields.size_of_headers;
        
        // Cache sections
        let sections = pe.sections.clone();
        
        // Cache imports - TODO: properly parse import table from goblin 0.8
        let imports = Vec::new();
        
        Ok(PeFile {
            data,
            image_base,
            entry_point,
            size_of_image,
            size_of_headers,
            sections,
            imports,
        })
    }
    
    /// Get section data by name
    pub fn get_section_data(&self, name: &str) -> Option<&[u8]> {
        for section in &self.sections {
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
        for section in &self.sections {
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
        for section in &self.sections {
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
    pub fn get_imports(&self) -> &[(String, Vec<String>)] {
        &self.imports
    }
    
    /// Get sections
    pub fn sections(&self) -> &[goblin::pe::section_table::SectionTable] {
        &self.sections
    }
}
