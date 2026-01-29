//! OEP (Original Entry Point) detection

use crate::Result;

/// OEP detector tracks execution to find the original entry point
pub struct OepDetector {
    /// Code section boundaries
    pub code_start: u64,
    pub code_end: u64,
    /// Themida section boundaries (if known)
    pub themida_start: Option<u64>,
    pub themida_end: Option<u64>,
    /// Detected OEP
    pub oep: Option<u64>,
    /// Track if we've left Themida section
    pub left_themida: bool,
}

impl OepDetector {
    pub fn new(code_start: u64, code_end: u64) -> Self {
        Self {
            code_start,
            code_end,
            themida_start: None,
            themida_end: None,
            oep: None,
            left_themida: false,
        }
    }
    
    /// Set Themida section boundaries
    pub fn set_themida_bounds(&mut self, start: u64, end: u64) {
        self.themida_start = Some(start);
        self.themida_end = Some(end);
        log::debug!("Themida bounds set: 0x{:x} - 0x{:x}", start, end);
    }
    
    /// Check if address is in Themida section
    pub fn is_in_themida(&self, addr: u64) -> bool {
        if let (Some(start), Some(end)) = (self.themida_start, self.themida_end) {
            addr >= start && addr < end
        } else {
            false
        }
    }
    
    /// Check if address is in code section
    pub fn is_in_code(&self, addr: u64) -> bool {
        addr >= self.code_start && addr < self.code_end
    }
    
    /// Process execution at an address
    /// Returns true if OEP was detected
    pub fn on_execute(&mut self, addr: u64) -> bool {
        // If we're in code section but not in Themida section, this might be OEP
        if self.is_in_code(addr) && !self.is_in_themida(addr) {
            if self.oep.is_none() {
                log::info!("Potential OEP detected at: 0x{:x}", addr);
                self.oep = Some(addr);
                return true;
            }
        }
        
        // Track if we left Themida
        if !self.is_in_themida(addr) && !self.left_themida {
            self.left_themida = true;
            log::debug!("Left Themida section at: 0x{:x}", addr);
        }
        
        false
    }
    
    /// Get detected OEP
    pub fn get_oep(&self) -> Option<u64> {
        self.oep
    }
}
