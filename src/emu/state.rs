//! Emulation state tracking

/// Tracks the state of the emulation
pub struct EmulationState {
    /// Instruction count
    pub instruction_count: u64,
    /// Whether we've reached the OEP
    pub oep_reached: bool,
}

impl EmulationState {
    pub fn new() -> Self {
        Self {
            instruction_count: 0,
            oep_reached: false,
        }
    }

    /// Mark OEP as reached
    pub fn mark_oep_reached(&mut self) {
        self.oep_reached = true;
        log::info!("OEP reached!");
    }

    /// Get statistics
    pub fn stats(&self) -> String {
        format!(
            "Instructions: {}, OEP reached: {}",
            self.instruction_count,
            self.oep_reached,
        )
    }
}

impl Default for EmulationState {
    fn default() -> Self {
        Self::new()
    }
}
