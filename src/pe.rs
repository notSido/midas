//! PE64 parse and section model layer using goblin.

use goblin::pe::{
    options::{ParseMode, ParseOptions},
    PE,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeError {
    #[error("failed to parse PE: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("not a 64-bit PE (PE32+ expected)")]
    NotPe64,
    #[error("PE optional header is missing")]
    MissingOptionalHeader,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn contains_rva(&self, rva: u32) -> bool {
        self.virtual_address
            .checked_add(self.virtual_size)
            .is_some_and(|end| self.virtual_address <= rva && rva < end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeImage {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub sections: Vec<Section>,
}

impl PeImage {
    pub fn parse(bytes: &[u8]) -> Result<PeImage, PeError> {
        let pe = PE::parse(bytes).or_else(|strict_error| {
            let options = ParseOptions::default().with_parse_mode(ParseMode::Permissive);
            PE::parse_with_opts(bytes, &options).map_err(|_| strict_error)
        })?;
        if !pe.is_64 {
            return Err(PeError::NotPe64);
        }

        let optional_header = pe
            .header
            .optional_header
            .ok_or(PeError::MissingOptionalHeader)?;
        let windows_fields = optional_header.windows_fields;

        let sections = pe
            .sections
            .iter()
            .map(|section| {
                Ok(Section {
                    name: section.name()?.trim_end_matches('\0').to_owned(),
                    virtual_address: section.virtual_address,
                    virtual_size: section.virtual_size,
                    pointer_to_raw_data: section.pointer_to_raw_data,
                    size_of_raw_data: section.size_of_raw_data,
                    characteristics: section.characteristics,
                })
            })
            .collect::<Result<Vec<_>, goblin::error::Error>>()?;

        Ok(PeImage {
            image_base: windows_fields.image_base,
            entry_point_rva: pe.entry,
            size_of_headers: windows_fields.size_of_headers,
            size_of_image: windows_fields.size_of_image,
            subsystem: windows_fields.subsystem,
            sections,
        })
    }

    pub fn entry_point_va(&self) -> u64 {
        self.image_base
            .saturating_add(u64::from(self.entry_point_rva))
    }

    pub fn section_containing_rva(&self, rva: u32) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.contains_rva(rva))
    }

    /// Map an RVA to a file offset within its section's raw data.
    ///
    /// Returns `None` when the RVA falls in a section's virtual-only tail (where
    /// `virtual_size > size_of_raw_data`, common in protected binaries): such an
    /// RVA has no backing bytes in the file, so no valid file offset exists.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        let section = self.section_containing_rva(rva)?;
        let section_delta = rva.checked_sub(section.virtual_address)?;
        if section_delta >= section.size_of_raw_data {
            return None;
        }
        u64::from(section.pointer_to_raw_data).checked_add(u64::from(section_delta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: u16 = 0xf0;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    struct TestSection {
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        characteristics: u32,
    }

    fn write_section(bytes: &mut [u8], offset: usize, section: &TestSection) {
        bytes[offset..offset + 8].copy_from_slice(&section.name);
        write_u32(bytes, offset + 8, section.virtual_size);
        write_u32(bytes, offset + 12, section.virtual_address);
        write_u32(bytes, offset + 16, section.size_of_raw_data);
        write_u32(bytes, offset + 20, section.pointer_to_raw_data);
        write_u32(bytes, offset + 36, section.characteristics);
    }

    fn minimal_pe64() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x800];

        bytes[0..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, PE_OFFSET as u32);

        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff = PE_OFFSET + 4;
        write_u16(&mut bytes, coff, 0x8664);
        write_u16(&mut bytes, coff + 2, 2);
        write_u16(&mut bytes, coff + 16, OPTIONAL_HEADER_SIZE);
        write_u16(&mut bytes, coff + 18, 0x0002);

        let optional = coff + 20;
        write_u16(&mut bytes, optional, 0x20b);
        bytes[optional + 2] = 14;
        write_u32(&mut bytes, optional + 4, 0x200);
        write_u32(&mut bytes, optional + 8, 0x200);
        write_u32(&mut bytes, optional + 16, 0x1000);
        write_u32(&mut bytes, optional + 20, 0x1000);

        let windows = optional + 24;
        write_u64(&mut bytes, windows, 0x140000000);
        write_u32(&mut bytes, windows + 8, 0x1000);
        write_u32(&mut bytes, windows + 12, 0x200);
        write_u16(&mut bytes, windows + 16, 6);
        write_u16(&mut bytes, windows + 18, 0);
        write_u32(&mut bytes, windows + 32, 0x4000);
        write_u32(&mut bytes, windows + 36, 0x400);
        write_u16(&mut bytes, windows + 44, 3);
        write_u64(&mut bytes, windows + 48, 0x100000);
        write_u64(&mut bytes, windows + 56, 0x1000);
        write_u64(&mut bytes, windows + 64, 0x100000);
        write_u64(&mut bytes, windows + 72, 0x1000);
        write_u32(&mut bytes, windows + 84, 16);

        let section_table = optional + usize::from(OPTIONAL_HEADER_SIZE);
        write_section(
            &mut bytes,
            section_table,
            &TestSection {
                name: *b".text\0\0\0",
                virtual_size: 0x200,
                virtual_address: 0x1000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x400,
                characteristics: 0x60000020,
            },
        );
        write_section(
            &mut bytes,
            section_table + 40,
            &TestSection {
                name: *b".data\0\0\0",
                virtual_size: 0x100,
                virtual_address: 0x2000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x600,
                characteristics: 0xc0000040,
            },
        );

        bytes
    }

    #[test]
    fn parse_minimal_pe64_asserts_known_fields() {
        let image = PeImage::parse(&minimal_pe64()).expect("minimal PE64 should parse");

        assert_eq!(image.image_base, 0x140000000);
        assert_eq!(image.entry_point_rva, 0x1000);
        assert_eq!(image.entry_point_va(), 0x140001000);
        assert_eq!(image.size_of_headers, 0x400);
        assert_eq!(image.size_of_image, 0x4000);
        assert_eq!(image.subsystem, 3);
        assert_eq!(image.sections.len(), 2);

        assert_eq!(
            image.sections[0],
            Section {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x200,
                pointer_to_raw_data: 0x400,
                size_of_raw_data: 0x200,
                characteristics: 0x60000020,
            }
        );
        assert_eq!(
            image.sections[1],
            Section {
                name: ".data".to_owned(),
                virtual_address: 0x2000,
                virtual_size: 0x100,
                pointer_to_raw_data: 0x600,
                size_of_raw_data: 0x200,
                characteristics: 0xc0000040,
            }
        );

        assert_eq!(
            image
                .section_containing_rva(0x1100)
                .map(|section| section.name.as_str()),
            Some(".text")
        );
        assert_eq!(image.rva_to_file_offset(0x1100), Some(0x500));
    }

    #[test]
    fn rva_to_file_offset_none_in_virtual_only_tail() {
        // A section whose virtual_size (0x2000) exceeds size_of_raw_data (0x200):
        // RVAs in [va + size_of_raw_data, va + virtual_size) are backed by no
        // file bytes and must map to None; RVAs within the raw range still map.
        let image = PeImage {
            image_base: 0x140000000,
            entry_point_rva: 0x1000,
            size_of_headers: 0x400,
            size_of_image: 0x10000,
            subsystem: 3,
            sections: vec![Section {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x2000,
                pointer_to_raw_data: 0x400,
                size_of_raw_data: 0x200,
                characteristics: 0x60000020,
            }],
        };

        // Inside the raw-backed range.
        assert_eq!(image.rva_to_file_offset(0x1000), Some(0x400));
        assert_eq!(image.rva_to_file_offset(0x11ff), Some(0x5ff));
        // First RVA past the raw data but still inside virtual_size: no bytes.
        assert!(image.section_containing_rva(0x1200).is_some());
        assert_eq!(image.rva_to_file_offset(0x1200), None);
        assert_eq!(image.rva_to_file_offset(0x2fff), None);
        // Outside the section entirely.
        assert_eq!(image.rva_to_file_offset(0x3000), None);
    }

    #[test]
    fn serde_round_trip() {
        let image = PeImage::parse(&minimal_pe64()).expect("minimal PE64 should parse");
        let json = serde_json::to_string(&image).expect("image should serialize");
        let round_tripped: PeImage = serde_json::from_str(&json).expect("image should deserialize");

        assert_eq!(round_tripped, image);
    }

    #[test]
    fn parses_real_samples_if_present() {
        // Sample binaries are gitignored and absent in CI; iterate over every
        // *.exe in samples/ so the check is sample-agnostic and covers whatever
        // real samples exist locally. Assert only invariants that hold for ANY
        // valid PE64 — no hardcoded per-sample constants.
        let samples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples");
        let entries = match fs::read_dir(&samples_dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        let mut checked = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("exe") {
                continue;
            }

            let bytes = fs::read(&path).expect("sample should be readable");
            let image = PeImage::parse(&bytes).expect("sample should parse as PE64");

            println!(
                "sample {}: image_base={:#x}, entry_point_rva={:#x}, sections={}",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                image.image_base,
                image.entry_point_rva,
                image.sections.len()
            );

            assert_ne!(image.image_base, 0);
            assert!(!image.sections.is_empty());
            assert!(image.entry_point_rva < image.size_of_image);

            let file_len = bytes.len() as u64;
            for section in &image.sections {
                let raw_end =
                    u64::from(section.pointer_to_raw_data) + u64::from(section.size_of_raw_data);
                assert!(raw_end <= file_len);
            }
            checked += 1;
        }

        println!("parsed {checked} real sample(s)");
    }
}
