//! Emulation state tracking

use std::collections::HashMap;

/// Tracks the state of the emulation
pub struct EmulationState {
    /// Instruction count
    pub instruction_count: u64,
    /// API calls made
    pub api_calls: Vec<ApiCall>,
    /// Memory writes to code section
    pub code_writes: Vec<(u64, Vec<u8>)>,
    /// Detected OEP (if found)
    pub oep: Option<u64>,
    /// Whether we've reached the OEP
    pub oep_reached: bool,
    /// IAT entries discovered
    pub iat_entries: HashMap<u64, String>,
}

/// Represents an API call
#[derive(Debug, Clone)]
pub struct ApiCall {
    pub address: u64,
    pub dll: String,
    pub function: String,
    pub args: Vec<u64>,
}

impl EmulationState {
    pub fn new() -> Self {
        Self {
            instruction_count: 0,
            api_calls: Vec::new(),
            code_writes: Vec::new(),
            oep: None,
            oep_reached: false,
            iat_entries: HashMap::new(),
        }
    }
    
    /// Record an API call
    pub fn add_api_call(&mut self, call: ApiCall) {
        log::debug!("API call: {}!{} at 0x{:x}", call.dll, call.function, call.address);
        self.api_calls.push(call);
    }
    
    /// Record a write to code section
    pub fn add_code_write(&mut self, addr: u64, data: Vec<u8>) {
        log::trace!("Code write at 0x{:x}: {} bytes", addr, data.len());
        self.code_writes.push((addr, data));
    }
    
    /// Set the OEP
    pub fn set_oep(&mut self, oep: u64) {
        log::info!("OEP detected at 0x{:x}", oep);
        self.oep = Some(oep);
    }
    
    /// Mark OEP as reached
    pub fn mark_oep_reached(&mut self) {
        self.oep_reached = true;
        log::info!("OEP reached!");
    }
    
    /// Add IAT entry
    pub fn add_iat_entry(&mut self, addr: u64, name: String) {
        self.iat_entries.insert(addr, name);
    }
    
    /// Get statistics
    pub fn stats(&self) -> String {
        format!(
            "Instructions: {}, API calls: {}, Code writes: {}, IAT entries: {}",
            self.instruction_count,
            self.api_calls.len(),
            self.code_writes.len(),
            self.iat_entries.len()
        )
    }
}

impl Default for EmulationState {
    fn default() -> Self {
        Self::new()
    }
}
