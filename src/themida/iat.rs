//! IAT (Import Address Table) reconstruction

use std::collections::HashMap;

/// IAT reconstructor
pub struct IatReconstructor {
    /// Traced API calls: address -> (dll, function)
    pub api_calls: HashMap<u64, (String, String)>,
    /// IAT base address (detected)
    pub iat_base: Option<u64>,
}

impl IatReconstructor {
    pub fn new() -> Self {
        Self {
            api_calls: HashMap::new(),
            iat_base: None,
        }
    }
    
    /// Record an API call
    pub fn record_api_call(&mut self, addr: u64, dll: String, function: String) {
        log::trace!("API call: {}!{} at 0x{:x}", dll, function, addr);
        self.api_calls.insert(addr, (dll, function));
    }
    
    /// Get number of discovered APIs
    pub fn api_count(&self) -> usize {
        self.api_calls.len()
    }
    
    /// Get all APIs
    pub fn get_apis(&self) -> &HashMap<u64, (String, String)> {
        &self.api_calls
    }
}

impl Default for IatReconstructor {
    fn default() -> Self {
        Self::new()
    }
}
