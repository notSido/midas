//! Emulation engine wrapper around Unicorn

use crate::{Result, UnpackError};
use unicorn_engine::{Unicorn, RegisterX86};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

/// Emulation engine managing the Unicorn instance
pub struct EmulationEngine {
    emu: Unicorn<'static, ()>,
    pub image_base: u64,
    pub instruction_count: u64,
}

impl EmulationEngine {
    /// Create a new 64-bit x86 emulation engine
    pub fn new(image_base: u64) -> Result<Self> {
        let emu = Unicorn::new(Arch::X86, Mode::MODE_64)
            .map_err(|e| UnpackError::EmulationError(format!("Failed to create emulator: {:?}", e)))?;
        
        Ok(Self {
            emu,
            image_base,
            instruction_count: 0,
        })
    }
    
    /// Get mutable reference to Unicorn instance
    pub fn emu_mut(&mut self) -> &mut Unicorn<'static, ()> {
        &mut self.emu
    }
    
    /// Get reference to Unicorn instance
    pub fn emu(&self) -> &Unicorn<'static, ()> {
        &self.emu
    }
    
    /// Setup initial registers
    pub fn setup_registers(&mut self, rsp: u64, rip: u64) -> Result<()> {
        self.emu.reg_write(RegisterX86::RSP, rsp)?;
        self.emu.reg_write(RegisterX86::RBP, rsp)?;
        self.emu.reg_write(RegisterX86::RIP, rip)?;
        
        // Set some reasonable defaults for other registers
        self.emu.reg_write(RegisterX86::RAX, 0)?;
        self.emu.reg_write(RegisterX86::RBX, 0)?;
        self.emu.reg_write(RegisterX86::RCX, 0)?;
        self.emu.reg_write(RegisterX86::RDX, 0)?;
        self.emu.reg_write(RegisterX86::RSI, 0)?;
        self.emu.reg_write(RegisterX86::RDI, 0)?;
        self.emu.reg_write(RegisterX86::R8, 0)?;
        self.emu.reg_write(RegisterX86::R9, 0)?;
        
        // Set flags
        self.emu.reg_write(RegisterX86::EFLAGS, 0x202)?; // IF flag set
        
        Ok(())
    }
    
    /// Read register value
    pub fn read_reg(&self, reg: RegisterX86) -> Result<u64> {
        self.emu.reg_read(reg)
            .map_err(|e| UnpackError::EmulationError(format!("Failed to read register: {:?}", e)))
    }
    
    /// Write register value
    pub fn write_reg(&mut self, reg: RegisterX86, value: u64) -> Result<()> {
        self.emu.reg_write(reg, value)
            .map_err(|e| UnpackError::EmulationError(format!("Failed to write register: {:?}", e)))
    }
    
    /// Read memory
    pub fn read_mem(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        self.emu.mem_read_as_vec(addr, size)
            .map_err(|e| UnpackError::MemoryError(format!("Failed to read memory at 0x{:x}: {:?}", addr, e)))
    }
    
    /// Write memory
    pub fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.emu.mem_write(addr, data)
            .map_err(|e| UnpackError::MemoryError(format!("Failed to write memory at 0x{:x}: {:?}", addr, e)))
    }
    
    /// Map memory region
    pub fn map_memory(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        self.emu.mem_map(addr, size, perms)
            .map_err(|e| UnpackError::MemoryError(format!("Failed to map memory at 0x{:x}: {:?}", addr, e)))
    }
    
    /// Start emulation
    pub fn start(&mut self, begin: u64, until: u64) -> Result<()> {
        log::debug!("Starting emulation from 0x{:x} until 0x{:x}", begin, until);
        
        self.emu.emu_start(begin, until, 0, 0)
            .map_err(|e| UnpackError::EmulationError(format!("Emulation failed: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Stop emulation
    pub fn stop(&mut self) -> Result<()> {
        self.emu.emu_stop()
            .map_err(|e| UnpackError::EmulationError(format!("Failed to stop: {:?}", e)))
    }
    
    /// Get current instruction pointer
    pub fn get_rip(&self) -> Result<u64> {
        self.read_reg(RegisterX86::RIP)
    }
    
    /// Dump memory region
    pub fn dump_memory(&self, start: u64, size: usize) -> Result<Vec<u8>> {
        self.read_mem(start, size)
    }
}
