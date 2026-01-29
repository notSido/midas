//! LDR (Loader) data structures

/// PEB_LDR_DATA address
pub const LDR_BASE: u64 = 0x7FFF_D000;

/// PEB_LDR_DATA structure (simplified)
#[repr(C)]
pub struct PebLdrData {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: u64,
    pub in_load_order_module_list_flink: u64,
    pub in_load_order_module_list_blink: u64,
}

impl PebLdrData {
    pub fn new() -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            initialized: 1,
            ss_handle: 0,
            in_load_order_module_list_flink: 0,
            in_load_order_module_list_blink: 0,
        }
    }
    
    pub fn as_bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = self as *const Self as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec()
        }
    }
}

impl Default for PebLdrData {
    fn default() -> Self {
        Self::new()
    }
}

/// Setup LDR data in emulator memory
pub fn setup_ldr(emu: &mut unicorn_engine::Unicorn<()>) -> crate::Result<()> {
    use unicorn_engine::unicorn_const::Prot;
    
    emu.mem_map(LDR_BASE, 0x1000, Prot::READ | Prot::WRITE)
        .map_err(|e| crate::UnpackError::MemoryError(format!("Failed to map LDR: {:?}", e)))?;
    
    let ldr = PebLdrData::new();
    emu.mem_write(LDR_BASE, &ldr.as_bytes())
        .map_err(|e| crate::UnpackError::MemoryError(format!("Failed to write LDR: {:?}", e)))?;
    
    log::debug!("LDR data initialized at 0x{:x}", LDR_BASE);
    
    Ok(())
}
