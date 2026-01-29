//! PE64 file parser

use crate::{Result, UnpackError};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Represents a parsed PE64 file
#[derive(Clone)]
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
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;
        use goblin::pe::header::DosHeader;
        use goblin::pe::section_table::SectionTable;
        
        // Parse DOS header
        let dos_header = DosHeader::parse(&data)
            .map_err(|e| UnpackError::PeError(format!("Failed to parse DOS header: {}", e)))?;
        
        let pe_offset = dos_header.pe_pointer as usize;
        
        // Verify PE signature
        if pe_offset + 4 > data.len() {
            return Err(UnpackError::PeError("File too small for PE signature".into()));
        }
        
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(UnpackError::PeError("Invalid PE signature".into()));
        }
        
        let mut cursor = Cursor::new(&data[pe_offset + 4..]);
        
        // Parse COFF header (20 bytes)
        let machine = cursor.read_u16::<LittleEndian>()?;
        let number_of_sections = cursor.read_u16::<LittleEndian>()?;
        cursor.read_u32::<LittleEndian>()?; // time_date_stamp
        cursor.read_u32::<LittleEndian>()?; // pointer_to_symbol_table
        cursor.read_u32::<LittleEndian>()?; // number_of_symbols
        let size_of_optional_header = cursor.read_u16::<LittleEndian>()?;
        cursor.read_u16::<LittleEndian>()?; // characteristics
        
        // Parse optional header
        let magic = cursor.read_u16::<LittleEndian>()?;
        let is_64 = magic == 0x20b; // PE32+
        
        if !is_64 {
            return Err(UnpackError::Not64Bit);
        }
        
        cursor.read_u8()?; // major_linker_version
        cursor.read_u8()?; // minor_linker_version
        cursor.read_u32::<LittleEndian>()?; // size_of_code
        cursor.read_u32::<LittleEndian>()?; // size_of_initialized_data
        cursor.read_u32::<LittleEndian>()?; // size_of_uninitialized_data
        let entry_point = cursor.read_u32::<LittleEndian>()? as u64;
        cursor.read_u32::<LittleEndian>()?; // base_of_code
        
        // PE32+ specific
        let image_base = cursor.read_u64::<LittleEndian>()?;
        cursor.read_u32::<LittleEndian>()?; // section_alignment
        cursor.read_u32::<LittleEndian>()?; // file_alignment
        cursor.read_u16::<LittleEndian>()?; // major_os_version
        cursor.read_u16::<LittleEndian>()?; // minor_os_version
        cursor.read_u16::<LittleEndian>()?; // major_image_version
        cursor.read_u16::<LittleEndian>()?; // minor_image_version
        cursor.read_u16::<LittleEndian>()?; // major_subsystem_version
        cursor.read_u16::<LittleEndian>()?; // minor_subsystem_version
        cursor.read_u32::<LittleEndian>()?; // win32_version_value
        let size_of_image = cursor.read_u32::<LittleEndian>()? as u64;
        let size_of_headers = cursor.read_u32::<LittleEndian>()?;
        
        log::info!("Parsed PE headers: image_base=0x{:x}, entry=0x{:x}, sections={}", 
            image_base, entry_point, number_of_sections);
        
        // Skip to sections (need to skip rest of optional header + data directories)
        let section_offset = pe_offset + 4 + 20 + size_of_optional_header as usize;
        let mut sections = Vec::new();
        
        for i in 0..number_of_sections {
            let offset = section_offset + (i as usize * 40); // Each section is 40 bytes
            if offset + 40 > data.len() {
                log::warn!("Section table extends beyond file");
                break;
            }
            
            // Parse section manually
            let name = data[offset..offset + 8].to_vec();
            let mut sec_cursor = Cursor::new(&data[offset + 8..offset + 40]);
            let virtual_size = sec_cursor.read_u32::<LittleEndian>()?;
            let virtual_address = sec_cursor.read_u32::<LittleEndian>()?;
            let size_of_raw_data = sec_cursor.read_u32::<LittleEndian>()?;
            let pointer_to_raw_data = sec_cursor.read_u32::<LittleEndian>()?;
            let pointer_to_relocations = sec_cursor.read_u32::<LittleEndian>()?;
            let pointer_to_linenumbers = sec_cursor.read_u32::<LittleEndian>()?;
            let number_of_relocations = sec_cursor.read_u16::<LittleEndian>()?;
            let number_of_linenumbers = sec_cursor.read_u16::<LittleEndian>()?;
            let characteristics = sec_cursor.read_u32::<LittleEndian>()?;
            
            let section = SectionTable {
                name: name.try_into().unwrap(),
                real_name: None,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            };
            
            sections.push(section);
        }
        
        log::info!("Successfully parsed {} sections", sections.len());
        
        Ok(PeFile {
            data,
            image_base,
            entry_point,
            size_of_image,
            size_of_headers,
            sections,
            imports: Vec::new(),
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
