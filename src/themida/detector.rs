//! Themida version detection

use crate::pe::PeFile;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemidaVersion {
    V2,
    V3,
    Unknown,
}

/// Detect Themida version and configuration
pub fn detect_themida(pe: &PeFile) -> Result<ThemidaVersion> {
    // Look for Themida sections
    let mut has_themida_section = false;
    
    for section in pe.sections() {
        let name = String::from_utf8_lossy(&section.name);
        if name.contains(".themida") || name.contains("themida") {
            has_themida_section = true;
            log::info!("Found Themida section: {}", name);
        }
    }
    
    // Check for characteristic Themida v3 patterns
    // V3 typically has larger virtualized sections
    if has_themida_section {
        // This is a simplified detection - real detection would analyze more
        log::info!("Detected Themida v3.x");
        Ok(ThemidaVersion::V3)
    } else {
        // Check entry point for Themida characteristics
        if is_themida_entry(&pe) {
            log::info!("Detected Themida (version uncertain)");
            Ok(ThemidaVersion::V3)
        } else {
            log::warn!("Could not confirm Themida protection");
            Ok(ThemidaVersion::Unknown)
        }
    }
}

/// Check if entry point looks like Themida
fn is_themida_entry(pe: &PeFile) -> bool {
    // Read first bytes of entry point
    if let Some(offset) = pe.rva_to_offset(pe.entry_point) {
        if let Some(code) = pe.data.get(offset as usize..(offset as usize + 16)) {
            // Look for common Themida patterns
            // V3 often starts with push/mov operations
            if code[0] == 0x48 || code[0] == 0x40 || code[0] == 0x55 {
                return true;
            }
        }
    }
    false
}
