//! Windows PEB (Process Environment Block) structures for x64

use crate::Result;

/// PEB address for emulation (fake but consistent)
pub const PEB_BASE: u64 = 0x7FFF_F000;
/// TEB address
pub const TEB_BASE: u64 = 0x7FFF_E000;

/// Process Environment Block (simplified for x64)
#[repr(C)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,  // We set this to 0
    pub bit_field: u8,
    pub _padding1: [u8; 4],
    pub mutant: u64,
    pub image_base_address: u64,
    pub ldr: u64,  // Pointer to PEB_LDR_DATA
    pub process_parameters: u64,
    pub sub_system_data: u64,
    pub process_heap: u64,
}

impl Peb {
    pub fn new(image_base: u64, ldr_address: u64) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,  // Important: not being debugged
            bit_field: 0,
            _padding1: [0; 4],
            mutant: 0xFFFF_FFFF_FFFF_FFFF,
            image_base_address: image_base,
            ldr: ldr_address,
            process_parameters: 0,
            sub_system_data: 0,
            process_heap: 0,
        }
    }
    
    /// Convert to bytes for writing to memory
    pub fn as_bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = self as *const Self as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec()
        }
    }
}

/// Thread Environment Block (simplified)
#[repr(C)]
pub struct Teb {
    pub nt_tib: NtTib,
    pub _padding: [u8; 0x30],
    pub process_environment_block: u64,  // Pointer to PEB
}

#[repr(C)]
pub struct NtTib {
    pub exception_list: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub sub_system_tib: u64,
    pub fiber_data: u64,
    pub arbitrary_user_pointer: u64,
    pub _self: u64,
}

impl Teb {
    pub fn new(peb_address: u64, stack_base: u64) -> Self {
        Self {
            nt_tib: NtTib {
                exception_list: 0xFFFF_FFFF_FFFF_FFFF,
                stack_base,
                stack_limit: stack_base - 0x100000, // 1MB below
                sub_system_tib: 0,
                fiber_data: 0,
                arbitrary_user_pointer: 0,
                _self: TEB_BASE,
            },
            _padding: [0; 0x30],
            process_environment_block: peb_address,
        }
    }
    
    pub fn as_bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = self as *const Self as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec()
        }
    }
}

/// Setup PEB and TEB in emulator memory
pub fn setup_peb_teb(
    emu: &mut unicorn_engine::Unicorn<()>,
    image_base: u64,
    ldr_address: u64,
    stack_base: u64,
) -> Result<()> {
    use unicorn_engine::unicorn_const::Prot;
    
    // Map PEB memory
    emu.mem_map(PEB_BASE, 0x1000, Prot::READ | Prot::WRITE)
        .map_err(|e| crate::UnpackError::MemoryError(format!("Failed to map PEB: {:?}", e)))?;
    
    // Map TEB memory
    emu.mem_map(TEB_BASE, 0x1000, Prot::READ | Prot::WRITE)
        .map_err(|e| crate::UnpackError::MemoryError(format!("Failed to map TEB: {:?}", e)))?;
    
    // Create and write PEB
    let peb = Peb::new(image_base, ldr_address);
    emu.mem_write(PEB_BASE, &peb.as_bytes())
        .map_err(|e| crate::UnpackError::MemoryError(format!("Failed to write PEB: {:?}", e)))?;
    
    // Create and write TEB
    let teb = Teb::new(PEB_BASE, stack_base);
    emu.mem_write(TEB_BASE, &teb.as_bytes())
        .map_err(|e| crate::UnpackError::MemoryError(format!("Failed to write TEB: {:?}", e)))?;
    
    // Setup GS segment to point to TEB (x64 uses GS for TEB)
    // Note: Unicorn doesn't fully support segment registers, but we try
    use unicorn_engine::RegisterX86;
    let _ = emu.reg_write(RegisterX86::GS_BASE, TEB_BASE);
    
    log::info!("PEB/TEB structures initialized");
    log::debug!("  PEB at: 0x{:x}", PEB_BASE);
    log::debug!("  TEB at: 0x{:x}", TEB_BASE);
    
    Ok(())
}
