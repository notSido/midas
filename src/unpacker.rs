//! Main unpacker orchestrator

use crate::{Result, UnpackError};
use crate::pe::{PeFile, PeLoader, PeDumper};
use crate::emu::{EmulationEngine, EmulationState};
use crate::themida::{OepDetector, detect_themida};
use crate::win64::{peb, ldr};
use crate::win64::api;
use unicorn_engine::{RegisterX86, Unicorn};
use unicorn_engine::unicorn_const::HookType;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// API hook range
const API_HOOK_BASE: u64 = 0xFEED_0000;
const API_HOOK_END: u64 = 0xFEEF_0000;

/// Workspace for allocations
const WORKSPACE_BASE: u64 = 0x20000000;

/// Main unpacker that coordinates all components
pub struct Unpacker {
    pe: PeFile,
    max_instructions: u64,
    verbose: bool,
}

impl Unpacker {
    /// Create a new unpacker
    pub fn new(pe: PeFile, max_instructions: u64, verbose: bool) -> Self {
        Self {
            pe,
            max_instructions,
            verbose,
        }
    }
    
    /// Run the unpacking process
    pub fn unpack<P: AsRef<Path>>(&mut self, output_path: P) -> Result<()> {
        log::info!("Starting unpacking process");
        
        // Detect Themida version
        let version = detect_themida(&self.pe)?;
        log::info!("Detected Themida version: {:?}", version);
        
        // Setup emulation
        log::info!("Setting up emulation environment");
        let mut engine = EmulationEngine::new(self.pe.image_base)?;
        let loader = PeLoader::new(self.pe.clone());
        
        // Load PE into emulator
        let stack_pointer = loader.load_into_unicorn(engine.emu_mut())?;
        let entry_point = loader.entry_point();
        log::info!("Entry point: 0x{:x}", entry_point);
        
        // Setup Windows structures
        self.setup_windows_env(&mut engine, stack_pointer)?;
        
        // Setup initial registers
        engine.setup_registers(stack_pointer, entry_point)?;
        
        // Setup hooks and state
        let mut state = EmulationState::new();
        let mut workspace = WORKSPACE_BASE;
        
        // Determine code section bounds for OEP detection
        let (code_start, code_end) = self.get_code_section_bounds();
        let mut oep_detector = OepDetector::new(code_start, code_end);
        
        // Try to detect Themida section
        if let Some((themida_start, themida_end)) = self.find_themida_section() {
            oep_detector.set_themida_bounds(themida_start, themida_end);
        }
        
        log::info!("Starting emulation (max {} instructions)", self.max_instructions);
        
        // Run emulation with hooks
        self.run_emulation(
            &mut engine,
            &mut state,
            &mut workspace,
            &mut oep_detector,
            entry_point,
        )?;
        
        // Check if OEP was found
        let oep = oep_detector.get_oep().ok_or(UnpackError::OepNotFound)?;
        log::info!("OEP found at: 0x{:x}", oep);
        
        // Dump the unpacked PE
        log::info!("Dumping unpacked PE");
        let image_size = self.pe.size_of_image as usize;
        let memory_snapshot = engine.dump_memory(self.pe.image_base, image_size)?;
        
        let dumper = PeDumper::new(self.pe.image_base, oep, memory_snapshot);
        dumper.dump(output_path)?;
        
        // Print statistics
        log::info!("Unpacking complete!");
        log::info!("Statistics: {}", state.stats());
        
        Ok(())
    }
    
    /// Setup Windows environment (PEB, TEB, LDR)
    fn setup_windows_env(&self, engine: &mut EmulationEngine, stack_base: u64) -> Result<()> {
        log::info!("Setting up Windows environment structures");
        
        // Setup LDR_DATA
        let ldr_address = ldr::LDR_DATA_BASE;
        ldr::setup_ldr_data(engine.emu_mut(), self.pe.image_base)?;
        
        // Setup PEB and TEB
        peb::setup_peb_teb(engine.emu_mut(), self.pe.image_base, ldr_address, stack_base)?;
        
        Ok(())
    }
    
    /// Run emulation with hooks
    fn run_emulation(
        &self,
        engine: &mut EmulationEngine,
        state: &mut EmulationState,
        workspace: &mut u64,
        oep_detector: &mut OepDetector,
        entry_point: u64,
    ) -> Result<()> {
        // Shared state for hooks
        let instruction_count = Arc::new(Mutex::new(0u64));
        let max_instructions = self.max_instructions;
        let oep_found = Arc::new(Mutex::new(false));
        let code_start = oep_detector.code_start;
        let code_end = oep_detector.code_end;
        
        // Clone Arcs for hook closures
        let instr_count_clone = instruction_count.clone();
        let oep_found_clone = oep_found.clone();
        
        // Add instruction hook
        let _code_hook = engine.emu_mut().add_code_hook(0, u64::MAX, move |emu, addr, _size| {
            let mut count = instr_count_clone.lock().unwrap();
            *count += 1;
            
            // Check instruction limit
            if *count >= max_instructions {
                log::warn!("Reached maximum instruction count");
                let _ = emu.emu_stop();
                return;
            }
            
            // Log execution periodically
            if *count % 100000 == 0 {
                log::debug!("Executed {} instructions, current: 0x{:x}", *count, addr);
            }
            
            // Check for OEP
            if addr >= code_start && addr < code_end {
                // Potential OEP
                let mut oep = oep_found_clone.lock().unwrap();
                if !*oep {
                    log::info!("Potential OEP reached at: 0x{:x}", addr);
                    *oep = true;
                    // Continue for a bit more to ensure unpacking is complete
                }
            }
            
            // Check for API calls in hook range
            if addr >= API_HOOK_BASE && addr < API_HOOK_END {
                log::debug!("API hook hit at: 0x{:x}", addr);
                // Handle API call
                let _ = Self::handle_api_call(emu, addr);
            }
        }).map_err(|e| UnpackError::EmulationError(format!("Failed to add code hook: {:?}", e)))?;
        
        // Save workspace value
        let workspace_val = *workspace;
        
        // Add memory write hook to track code modifications
        let write_count = Arc::new(Mutex::new(0u64));
        let write_count_clone = write_count.clone();
        
        let _mem_hook = engine.emu_mut().add_mem_hook(
            HookType::MEM_WRITE,
            code_start,
            code_end,
            move |_emu, _mem_type, addr, size, value| {
                let mut count = write_count_clone.lock().unwrap();
                *count += 1;
                
                if *count <= 10 || *count % 100 == 0 {
                    log::debug!("Code write at 0x{:x}, size: {}, value: 0x{:x}", addr, size, value);
                }
                
                true
            }
        ).map_err(|e| UnpackError::EmulationError(format!("Failed to add mem hook: {:?}", e)))?;
        
        // Start emulation
        log::info!("Starting emulation from 0x{:x}", entry_point);
        
        // Emulate until we hit an error or reach max instructions
        let result = engine.emu_mut().emu_start(
            entry_point,
            0,  // Run until stopped
            0,  // No timeout
            0   // No count (we handle this in hook)
        );
        
        // Update state
        let final_count = *instruction_count.lock().unwrap();
        state.instruction_count = final_count;
        
        let oep_reached = *oep_found.lock().unwrap();
        if oep_reached {
            state.mark_oep_reached();
            // Set OEP in detector
            let rip = engine.get_rip()?;
            if rip >= code_start && rip < code_end {
                oep_detector.on_execute(rip);
            }
        }
        
        log::info!("Emulation stopped after {} instructions", final_count);
        
        // It's normal for emulation to error out - we just need to reach OEP
        if let Err(e) = result {
            log::debug!("Emulation error (expected): {:?}", e);
        }
        
        *workspace = workspace_val;
        
        Ok(())
    }
    
    /// Handle API call
    fn handle_api_call(emu: &mut Unicorn<()>, addr: u64) -> Result<()> {
        // Determine which API based on address
        // This is a simplified version - real implementation would have a map
        
        let api_offset = addr - API_HOOK_BASE;
        
        match api_offset {
            0x1000 => {
                api::kernel32::virtual_alloc(emu, &mut WORKSPACE_BASE.clone())?;
            }
            0x1100 => {
                api::kernel32::virtual_protect(emu)?;
            }
            0x1200 => {
                api::kernel32::load_library_a(emu)?;
            }
            0x1300 => {
                api::kernel32::get_proc_address(emu)?;
            }
            0x1400 => {
                api::kernel32::get_tick_count(emu)?;
            }
            0x1500 => {
                api::kernel32::query_performance_counter(emu)?;
            }
            _ => {
                log::debug!("Unknown API at offset 0x{:x}", api_offset);
                // Return success by default
                let _ = emu.reg_write(RegisterX86::RAX, 0);
            }
        }
        
        // Simulate return by popping return address and jumping to it
        let rsp = emu.reg_read(RegisterX86::RSP)?;
        let ret_addr_bytes = emu.mem_read_as_vec(rsp, 8)
            .map_err(|e| UnpackError::MemoryError(format!("Failed to read return address: {:?}", e)))?;
        let ret_addr = u64::from_le_bytes([
            ret_addr_bytes[0], ret_addr_bytes[1], ret_addr_bytes[2], ret_addr_bytes[3],
            ret_addr_bytes[4], ret_addr_bytes[5], ret_addr_bytes[6], ret_addr_bytes[7],
        ]);
        
        // Update RSP and RIP
        emu.reg_write(RegisterX86::RSP, rsp + 8)?;
        emu.reg_write(RegisterX86::RIP, ret_addr)?;
        
        Ok(())
    }
    
    /// Get code section boundaries
    fn get_code_section_bounds(&self) -> (u64, u64) {
        // Find .text or first executable section
        for section in self.pe.sections() {
            let name = String::from_utf8_lossy(&section.name);
            if name.starts_with(".text") || (section.characteristics & 0x20000000) != 0 {
                let start = self.pe.image_base + section.virtual_address as u64;
                let end = start + section.virtual_size as u64;
                log::info!("Code section: {} (0x{:x} - 0x{:x})", name.trim_end_matches('\0'), start, end);
                return (start, end);
            }
        }
        
        // Fallback
        log::warn!("Could not find code section, using image bounds");
        (self.pe.image_base, self.pe.image_base + self.pe.size_of_image)
    }
    
    /// Find Themida section (usually has high entropy or specific characteristics)
    fn find_themida_section(&self) -> Option<(u64, u64)> {
        // Look for section with Themida characteristics
        for section in self.pe.sections() {
            let name = String::from_utf8_lossy(&section.name);
            let name_clean = name.trim_end_matches('\0');
            
            // Themida often uses sections like .themida, or packed sections
            if name_clean.contains("themida") 
                || name_clean.starts_with(".")
                && section.size_of_raw_data > 0
                && section.virtual_size > section.size_of_raw_data * 2 {
                
                let start = self.pe.image_base + section.virtual_address as u64;
                let end = start + section.virtual_size as u64;
                log::info!("Potential Themida section: {} (0x{:x} - 0x{:x})", name_clean, start, end);
                return Some((start, end));
            }
        }
        
        None
    }
}
