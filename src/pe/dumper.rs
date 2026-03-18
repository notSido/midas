//! PE dumper for creating unpacked binaries

use crate::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// PE dumper that creates a valid PE from memory
pub struct PeDumper {
    image_base: u64,
    oep: u64,
    memory_snapshot: Vec<u8>,
}

impl PeDumper {
    pub fn new(image_base: u64, oep: u64, memory_snapshot: Vec<u8>) -> Self {
        Self {
            image_base,
            oep,
            memory_snapshot,
        }
    }

    /// Dump the unpacked PE to a file, patching the entry point to the OEP
    pub fn dump<P: AsRef<Path>>(&self, output_path: P) -> Result<()> {
        log::info!("Dumping unpacked PE to: {:?}", output_path.as_ref());
        log::info!("  Image base: 0x{:x}", self.image_base);
        log::info!("  OEP: 0x{:x}", self.oep);

        let mut pe_data = self.memory_snapshot.clone();

        // Patch the entry point RVA in the PE header to point to the OEP
        if let Some(ep_offset) = self.find_entry_point_offset(&pe_data) {
            let oep_rva = self.oep.wrapping_sub(self.image_base) as u32;
            log::info!("  Patching AddressOfEntryPoint at file offset 0x{:x} to RVA 0x{:x}", ep_offset, oep_rva);
            if ep_offset + 4 <= pe_data.len() {
                pe_data[ep_offset..ep_offset + 4].copy_from_slice(&oep_rva.to_le_bytes());
            }
        } else {
            log::warn!("Could not locate AddressOfEntryPoint in PE header — output will have original entry point");
        }

        // Align sections: set each section's raw size = virtual size and raw pointer = virtual address
        // so the file layout mirrors the in-memory layout (common for unpacked dumps)
        self.fixup_section_headers(&mut pe_data);

        let mut file = File::create(output_path)?;
        file.write_all(&pe_data)?;

        log::info!("Dump completed successfully");

        Ok(())
    }

    /// Locate the file offset of AddressOfEntryPoint in the optional header
    fn find_entry_point_offset(&self, data: &[u8]) -> Option<usize> {
        // DOS header: e_lfanew at offset 0x3C
        if data.len() < 0x40 {
            return None;
        }
        let pe_offset = u32::from_le_bytes([
            data[0x3C], data[0x3D], data[0x3E], data[0x3F],
        ]) as usize;

        // PE signature (4 bytes) + COFF header (20 bytes) + Optional header starts
        // Optional header: magic (2) + linker version (2) + SizeOfCode (4) +
        //   SizeOfInitializedData (4) + SizeOfUninitializedData (4) + AddressOfEntryPoint (4)
        // So AddressOfEntryPoint is at optional_header_start + 16
        let optional_header_start = pe_offset + 4 + 20;
        let ep_offset = optional_header_start + 16;

        if ep_offset + 4 <= data.len() {
            // Verify PE signature
            if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                return Some(ep_offset);
            }
        }
        None
    }

    /// Fix up section headers so raw pointers/sizes match virtual layout
    /// This makes the dumped file loadable by analysis tools
    fn fixup_section_headers(&self, data: &mut [u8]) {
        if data.len() < 0x40 {
            return;
        }
        let pe_offset = u32::from_le_bytes([
            data[0x3C], data[0x3D], data[0x3E], data[0x3F],
        ]) as usize;

        if pe_offset + 4 + 20 > data.len() {
            return;
        }

        // Read number of sections and size of optional header from COFF header
        let num_sections = u16::from_le_bytes([
            data[pe_offset + 4 + 2], data[pe_offset + 4 + 3],
        ]) as usize;
        let size_of_optional_header = u16::from_le_bytes([
            data[pe_offset + 4 + 16], data[pe_offset + 4 + 17],
        ]) as usize;

        let section_table_start = pe_offset + 4 + 20 + size_of_optional_header;

        for i in 0..num_sections {
            let sec_offset = section_table_start + i * 40;
            if sec_offset + 40 > data.len() {
                break;
            }

            // Read VirtualSize (offset 8) and VirtualAddress (offset 12)
            let virtual_size = u32::from_le_bytes([
                data[sec_offset + 8], data[sec_offset + 9],
                data[sec_offset + 10], data[sec_offset + 11],
            ]);
            let virtual_address = u32::from_le_bytes([
                data[sec_offset + 12], data[sec_offset + 13],
                data[sec_offset + 14], data[sec_offset + 15],
            ]);

            // Set SizeOfRawData = VirtualSize (offset 16)
            data[sec_offset + 16..sec_offset + 20].copy_from_slice(&virtual_size.to_le_bytes());
            // Set PointerToRawData = VirtualAddress (offset 20)
            data[sec_offset + 20..sec_offset + 24].copy_from_slice(&virtual_address.to_le_bytes());

            let name = String::from_utf8_lossy(&data[sec_offset..sec_offset + 8]);
            log::debug!("Section {}: raw_ptr=0x{:x}, raw_size=0x{:x} (mirrored from VA)",
                name.trim_end_matches('\0'), virtual_address, virtual_size);
        }
    }
}
