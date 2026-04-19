//! Memory reader for midas's OEP-dumped PE files.
//!
//! midas's `PeDumper` (see `src/pe/dumper.rs`) writes unpacked PEs with
//! section raw-offsets aligned to their virtual addresses — i.e. for
//! any section, `raw_pointer == virtual_address` and
//! `raw_size == virtual_size`. That makes virtual-address lookup
//! trivially `file_offset = va - image_base`.
//!
//! This module exposes that lookup. It's the minimum piece needed to
//! follow pointers the VM detector has located: the descriptor gives us
//! the absolute addresses of the VM_PC cell and handler-table pointer
//! cell; `OepDump::read_u64_at_va` reads the actual pointer values
//! from those cells so downstream tooling (e.g. the bytecode walker)
//! has concrete memory to walk.
//!
//! Note: because the dump layout is raw=virtual, "reading past the end
//! of the image" returns `None` rather than silently wrapping — most
//! illegitimate VAs are caught that way.

use std::path::Path;

use crate::{Result, UnpackError};

/// An OEP-dumped PE loaded into memory with VA-based access.
pub struct OepDump {
    data: Vec<u8>,
    image_base: u64,
}

impl OepDump {
    /// Load the PE at `path`, parsing only the minimum needed for
    /// VA → file-offset lookup: DOS e_lfanew → NT magic check →
    /// optional header's `ImageBase` for PE32+.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path.as_ref())?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < 0x40 {
            return Err(UnpackError::PeError("file too small for DOS header".into()));
        }
        let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        // Optional-header ImageBase is at pe_off + 24 (end of COFF header)
        // + 24 (start of 64-bit ImageBase within the optional header).
        // We need at least pe_off + 56 bytes to read ImageBase.
        if pe_off + 56 > data.len() {
            return Err(UnpackError::PeError("file too small for NT header".into()));
        }
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err(UnpackError::PeError("bad PE signature".into()));
        }
        let magic = u16::from_le_bytes(data[pe_off + 24..pe_off + 26].try_into().unwrap());
        if magic != 0x20b {
            return Err(UnpackError::Not64Bit);
        }
        let image_base =
            u64::from_le_bytes(data[pe_off + 48..pe_off + 56].try_into().unwrap());
        Ok(Self { data, image_base })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Read `len` bytes starting at virtual address `va`. Returns
    /// `None` if the range falls outside the loaded image.
    pub fn read_bytes_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let rva = va.checked_sub(self.image_base)?;
        let off = rva as usize;
        let end = off.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(&self.data[off..end])
    }

    /// Read a little-endian 64-bit value at virtual address `va`.
    pub fn read_u64_at_va(&self, va: u64) -> Option<u64> {
        let bytes = self.read_bytes_at_va(va, 8)?;
        Some(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read a little-endian 16-bit value at virtual address `va`.
    pub fn read_u16_at_va(&self, va: u64) -> Option<u16> {
        let bytes = self.read_bytes_at_va(va, 2)?;
        Some(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read a little-endian 32-bit value at virtual address `va`.
    pub fn read_u32_at_va(&self, va: u64) -> Option<u32> {
        let bytes = self.read_bytes_at_va(va, 4)?;
        Some(u32::from_le_bytes(bytes.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid PE32+ header carrying the ImageBase we check for.
    /// Not a loadable PE — just enough for `from_bytes` to succeed.
    fn synth_pe64_with_image_base(image_base: u64) -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        // DOS e_lfanew → 0x80
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // NT headers at 0x80: "PE\0\0" + COFF (20 bytes) + optional header
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        // Optional magic at 0x80 + 24 = 0x98
        v[0x98..0x9A].copy_from_slice(&0x20bu16.to_le_bytes());
        // ImageBase at 0x80 + 48 = 0xB0
        v[0xB0..0xB8].copy_from_slice(&image_base.to_le_bytes());
        v
    }

    #[test]
    fn image_base_parsed() {
        let bytes = synth_pe64_with_image_base(0x140000000);
        let dump = OepDump::from_bytes(bytes).unwrap();
        assert_eq!(dump.image_base(), 0x140000000);
    }

    #[test]
    fn read_bytes_at_va_range_check() {
        let mut bytes = synth_pe64_with_image_base(0x140000000);
        // Plant a known u64 at file offset 0x100 → VA 0x140000100
        bytes[0x100..0x108].copy_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes());
        let dump = OepDump::from_bytes(bytes).unwrap();
        assert_eq!(dump.read_u64_at_va(0x140000100), Some(0xdead_beef_cafe_f00d));
        // Below image base
        assert_eq!(dump.read_u64_at_va(0x13fffffff), None);
        // Past end
        assert_eq!(dump.read_u64_at_va(0x140001000), None);
    }
}
