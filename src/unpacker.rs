//! Main unpacker orchestrator

use crate::{Result, UnpackError};
use crate::pe::{PeFile, PeLoader, PeDumper};
use crate::emu::{EmulationEngine, EmulationState};
use crate::themida::{OepDetector, detect_themida};
use crate::win64::{peb, ldr};
use crate::win64::{api::ApiRegistry, syscall};
use crate::cpu_features::{self, CpuState};
use crate::tracer::ExecutionTracer;
use crate::devirt::{RegSnapshot, TraceBuilder};
use unicorn_engine::{RegisterX86, Unicorn};
use unicorn_engine::unicorn_const::HookType;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// API hook range
const API_HOOK_BASE: u64 = 0xFEED_0000;

/// Workspace for allocations
const WORKSPACE_BASE: u64 = 0x20000000;

/// Optional devirt-trace recording configuration. When present, the
/// unpacker will continue past the OEP breakout point and write a JSONL
/// trace for downstream VM analysis (M1+).
pub struct DevirtTraceConfig {
    pub path: PathBuf,
    pub limit: u64,
    /// RIPs at which the unpacker should emit a one-shot register
    /// snapshot the first time each fires post-OEP. Populated by
    /// `set_devirt_capture_regs_at`. Empty by default.
    pub capture_regs_at: Vec<u64>,
}

/// Main unpacker that coordinates all components
pub struct Unpacker {
    pe: PeFile,
    max_instructions: u64,
    #[allow(dead_code)]
    verbose: bool,
    devirt_trace: Option<DevirtTraceConfig>,
}

impl Unpacker {
    /// Create a new unpacker
    pub fn new(pe: PeFile, max_instructions: u64, verbose: bool) -> Self {
        Self {
            pe,
            max_instructions,
            verbose,
            devirt_trace: None,
        }
    }

    /// Enable post-OEP per-instruction trace recording for
    /// devirtualization. Without this, the unpacker stops at OEP as
    /// before — the trace recording path is strictly additive.
    pub fn set_devirt_trace<P: Into<PathBuf>>(&mut self, path: P, limit: u64) {
        self.devirt_trace = Some(DevirtTraceConfig {
            path: path.into(),
            limit,
            capture_regs_at: Vec::new(),
        });
    }

    /// Register one or more RIPs at which the unpacker should emit a
    /// one-shot register snapshot the first time each fires post-OEP.
    /// Requires `set_devirt_trace` to have been called first.
    pub fn set_devirt_capture_regs_at(&mut self, rips: Vec<u64>) {
        if let Some(cfg) = &mut self.devirt_trace {
            cfg.capture_regs_at = rips;
        } else if !rips.is_empty() {
            log::warn!(
                "set_devirt_capture_regs_at ignored — devirt trace not configured"
            );
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
        // Create API registry
        let api_registry = ApiRegistry::new(API_HOOK_BASE, *workspace);
        
        // Create CPU state for RDTSC/CPUID
        let cpu_state = Arc::new(Mutex::new(CpuState::new()));
        
        // Create execution tracer
        let tracer = Arc::new(Mutex::new(ExecutionTracer::new()));
        let last_unique_count = Arc::new(Mutex::new(0usize));

        // Shared state for hooks
        let instruction_count = Arc::new(Mutex::new(0u64));
        let max_instructions = self.max_instructions;
        let oep_found = Arc::new(Mutex::new(false));
        let oep_candidate: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let code_start = oep_detector.code_start;
        let code_end = oep_detector.code_end;
        let api_registry_shared = Arc::new(Mutex::new(api_registry));

        // Devirt trace recorder — present only when --devirt-trace was set.
        // Shared with the code hook behind an Arc<Mutex<_>>; armed at
        // breakout, written to per-instruction until the configured limit.
        let devirt_trace: Option<Arc<Mutex<TraceBuilder>>> = match &self.devirt_trace {
            Some(cfg) => {
                let mut tb = TraceBuilder::new(&cfg.path, cfg.limit)?;
                for rip in &cfg.capture_regs_at {
                    tb.add_capture_rip(*rip);
                }
                if !cfg.capture_regs_at.is_empty() {
                    log::info!(
                        "Devirt trace registered {} capture-regs-at RIPs",
                        cfg.capture_regs_at.len()
                    );
                }
                Some(Arc::new(Mutex::new(tb)))
            }
            None => None,
        };

        // Clone Arcs for hook closures
        let instr_count_clone = instruction_count.clone();
        let oep_found_clone = oep_found.clone();
        let oep_candidate_clone = oep_candidate.clone();
        let api_registry_clone = api_registry_shared.clone();
        let cpu_state_clone = cpu_state.clone();
        let tracer_clone = tracer.clone();
        let last_unique_clone = last_unique_count.clone();
        let devirt_trace_clone = devirt_trace.clone();
        
        // Shared workspace for syscall handler
        let workspace_shared = Arc::new(Mutex::new(*workspace));
        let workspace_clone_for_hook = workspace_shared.clone();
        
        // Add instruction hook
        let _code_hook = engine.emu_mut().add_code_hook(0, u64::MAX, move |emu, addr, size| {
            let mut count = instr_count_clone.lock().unwrap();
            *count += 1;
            
            // Track execution and check limits
            {
                let mut trace = tracer_clone.lock().unwrap();
                trace.record(addr);

                // Check instruction limit (inside same lock scope to avoid deadlock)
                if *count >= max_instructions {
                    log::warn!("Reached maximum instruction count");
                    log::warn!("Final stats: {}", trace.stats());
                    let _ = emu.emu_stop();
                    return;
                }

                // Check for loops and log stats periodically
                if *count % 1000000 == 0 {
                    let current_unique = trace.unique_count();
                    log::info!("Execution stats: {}", trace.stats());

                    // Check for breakout (OEP transition). Skip once we
                    // already fired — otherwise the post-OEP stream keeps
                    // re-tripping the heuristic every million insns.
                    let already_oep = *oep_found_clone.lock().unwrap();
                    let mut last_count = last_unique_clone.lock().unwrap();
                    if !already_oep && trace.detect_breakout(*last_count) {
                        log::info!("BREAKOUT DETECTED! Unique addresses jumped from {} to {} at RIP 0x{:x}", *last_count, current_unique, addr);

                        // Capture current RIP as OEP candidate — this is the
                        // first instruction past the decompression loop.
                        *oep_candidate_clone.lock().unwrap() = Some(addr);
                        *oep_found_clone.lock().unwrap() = true;

                        match &devirt_trace_clone {
                            Some(tb) => {
                                // Devirt mode: arm the recorder and keep
                                // running so we capture the VM execution.
                                // Capture a full GPR snapshot at the arm instant so the
                                // bytecode walker can resolve [rbp + X]-style VM state
                                // pointers without a second emulation pass.
                                let regs = match snapshot_gprs(emu) {
                                    Ok(s) => Some(s),
                                    Err(e) => {
                                        log::warn!("Failed to snapshot GPRs at OEP: {}", e);
                                        None
                                    }
                                };
                                if let Err(e) = tb.lock().unwrap().arm(addr, regs) {
                                    log::error!("Failed to arm devirt trace: {}", e);
                                    let _ = emu.emu_stop();
                                    return;
                                }
                                *last_count = current_unique;
                            }
                            None => {
                                // No devirt: stop at OEP as before.
                                let _ = emu.emu_stop();
                                return;
                            }
                        }
                    } else {
                        *last_count = current_unique;
                    }

                    if trace.is_looping() {
                        log::warn!("Detected execution loop!");
                    }
                }
            }

            // Devirt trace: record this instruction if the recorder is
            // armed. Cheap no-op while disarmed (before OEP) — one lock +
            // boolean check. Past the limit, stop emulation cleanly.
            if let Some(tb) = &devirt_trace_clone {
                let mut tb = tb.lock().unwrap();
                if tb.is_armed() {
                    let read_size = (size as usize).min(15);
                    let bytes = emu.mem_read_as_vec(addr, read_size).unwrap_or_default();
                    // Automatic one-shot register capture on every
                    // indirect `jmp r<reg>` the first time each RIP
                    // fires post-OEP. No flag required — the offline
                    // VM-pattern detector uses the resulting
                    // `RegsAtRip` events to recover dispatcher-entry
                    // register state (RBP in particular) for every
                    // candidate dispatcher.
                    if tb.should_auto_capture_indirect_jmp(addr, &bytes) {
                        match snapshot_gprs(emu) {
                            Ok(regs) => {
                                if let Err(e) = tb.record_auto_captured_regs(addr, regs) {
                                    log::warn!(
                                        "auto regs-at-rip record failed at 0x{:x}: {}",
                                        addr, e
                                    );
                                }
                            }
                            Err(e) => log::warn!(
                                "auto regs snapshot failed at 0x{:x}: {}",
                                addr, e
                            ),
                        }
                    }
                    // Manual one-shot capture (testing back-door;
                    // primary path is the auto-capture above).
                    if tb.should_capture_regs(addr) {
                        match snapshot_gprs(emu) {
                            Ok(regs) => {
                                if let Err(e) = tb.record_regs_at_rip(addr, regs) {
                                    log::warn!(
                                        "regs-at-rip record failed at 0x{:x}: {}",
                                        addr, e
                                    );
                                }
                            }
                            Err(e) => log::warn!(
                                "regs snapshot failed at 0x{:x}: {}",
                                addr, e
                            ),
                        }
                    }
                    match tb.record_exec(addr, &bytes) {
                        Ok(true) => {}
                        Ok(false) => {
                            log::info!("Devirt trace limit reached at tick {}, stopping emulation", tb.tick());
                            let _ = emu.emu_stop();
                            return;
                        }
                        Err(e) => {
                            log::error!("Devirt trace write error: {}", e);
                            let _ = emu.emu_stop();
                            return;
                        }
                    }
                }
            }
            
            // Log execution periodically
            if *count % 100000 == 0 {
                log::debug!("Executed {} instructions, current: 0x{:x}", *count, addr);
            }
            
            // Log more frequently in verbose mode for debugging
            if *count % 10000 == 0 {
                log::trace!("At 0x{:x} after {} instructions", addr, *count);
            }
            
            // Check for special instructions (0x0F prefix)
            if size >= 2 {
                if let Ok(bytes) = emu.mem_read_as_vec(addr, 2) {
                    if bytes[0] == 0x0F {
                        match bytes[1] {
                            // Syscall (0x0F 0x05)
                            0x05 => {
                                let mut ws = workspace_clone_for_hook.lock().unwrap();
                                match syscall::handle_syscall(emu, &mut *ws) {
                                    Ok(_) => {},
                                    Err(e) => {
                                        log::error!("Syscall handler error: {}", e);
                                    }
                                }
                                return; // Syscall handler already advanced RIP
                            }
                            // CPUID (0x0F 0xA2)
                            0xA2 => {
                                log::debug!("CPUID at 0x{:x}", addr);
                                match cpu_features::handle_cpuid(emu) {
                                    Ok(_) => {},
                                    Err(e) => {
                                        log::error!("CPUID handler error: {}", e);
                                    }
                                }
                                // CPUID is 2 bytes, Unicorn will auto-advance
                                return;
                            }
                            // RDTSC (0x0F 0x31)
                            0x31 => {
                                let mut cpu = cpu_state_clone.lock().unwrap();
                                match cpu_features::handle_rdtsc(emu, &mut *cpu) {
                                    Ok(_) => {
                                        log::trace!("RDTSC at 0x{:x} -> 0x{:x}", addr, cpu.rdtsc_counter);
                                    }
                                    Err(e) => {
                                        log::error!("RDTSC handler error: {}", e);
                                    }
                                }
                                // RDTSC is 2 bytes, Unicorn will auto-advance
                                return;
                            }
                            _ => {} // Other 0x0F instructions, continue normally
                        }
                    }
                }
            }
            
            // Check for API calls using registry
            let mut registry = api_registry_clone.lock().unwrap();
            if registry.is_api_hook(addr) {
                match registry.dispatch(addr, emu) {
                    Ok(true) => {
                        // API handled successfully, simulate return
                        match Self::simulate_api_return(emu) {
                            Ok(_) => {},
                            Err(e) => {
                                log::error!("Failed to simulate API return: {}", e);
                            }
                        }
                    }
                    Ok(false) => {
                        log::warn!("Unknown API at 0x{:x}", addr);
                    }
                    Err(e) => {
                        log::error!("API dispatch error at 0x{:x}: {}", addr, e);
                    }
                }
            }
        }).map_err(|e| UnpackError::EmulationError(format!("Failed to add code hook: {:?}", e)))?;
        
        // Add memory write hook to track code modifications
        let write_count = Arc::new(Mutex::new(0u64));
        let write_count_clone = write_count.clone();
        
        let _mem_write_hook = engine.emu_mut().add_mem_hook(
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
        
        // Mirror-sync hook: when code writes to image_base+RVA, replicate
        // the write to low_mem+RVA. The low-memory mirror is populated at
        // PE load with raw file bytes; later runtime writes to image_base
        // (e.g. Themida's decompression output) would otherwise leave the
        // mirror stale, and any subsequent bare-RVA jump/read would hit
        // out-of-date data. This hook is defensive hygiene — it is NOT
        // what fixes the observed INSN_INVALID crashes on either sample
        // (those are caused by fake-import pointers resolving into the
        // PE's own import-name strings, which is a separate and larger
        // fix; see task #10 and docs/DEVIRT.md).
        let image_base = self.pe.image_base;
        let image_end = image_base + self.pe.size_of_image;
        let low_mem_end = std::cmp::max(
            (self.pe.size_of_image + 0xFFF) & !0xFFF,
            0x1000000u64,
        );
        let mirror_write_count = Arc::new(Mutex::new(0u64));
        let mirror_count_clone = mirror_write_count.clone();
        let _mirror_hook = engine.emu_mut().add_mem_hook(
            HookType::MEM_WRITE,
            image_base,
            image_end,
            move |emu, _mem_type, addr, size, value| {
                let rva = addr - image_base;
                if rva >= low_mem_end {
                    return true;
                }
                let n = size.min(8);
                // Unicorn delivers value as i64 for writes up to 8 bytes;
                // for rare larger writes we take the low 8 bytes (good
                // enough in practice for Themida's decompression, which
                // uses byte/word/dword/qword stores).
                let le = value.to_le_bytes();
                if emu.mem_write(rva, &le[..n]).is_ok() {
                    *mirror_count_clone.lock().unwrap() += 1;
                }
                true
            },
        ).map_err(|e| UnpackError::EmulationError(format!("Failed to add mirror hook: {:?}", e)))?;

        // Add unmapped memory read/fetch hooks for debugging
        let _mem_read_unmapped = engine.emu_mut().add_mem_hook(
            HookType::MEM_READ_UNMAPPED,
            0,
            u64::MAX,
            move |_emu, _mem_type, addr, size, _value| {
                log::error!("READ_UNMAPPED at 0x{:x} (size: {})", addr, size);
                false // Stop on unmapped reads
            }
        ).map_err(|e| UnpackError::EmulationError(format!("Failed to add read unmapped hook: {:?}", e)))?;
        
        let _mem_fetch_unmapped = engine.emu_mut().add_mem_hook(
            HookType::MEM_FETCH_UNMAPPED,
            0,
            u64::MAX,
            move |_emu, _mem_type, addr, size, _value| {
                log::error!("FETCH_UNMAPPED at 0x{:x} (size: {})", addr, size);
                log::error!("This address should be mapped if decompression worked correctly");
                false // Stop on unmapped fetch
            }
        ).map_err(|e| UnpackError::EmulationError(format!("Failed to add fetch unmapped hook: {:?}", e)))?;
        
        // Start emulation
        log::info!("Starting emulation from 0x{:x}", entry_point);
        
        // Log initial register state for debugging
        if let Ok(rsi) = engine.read_reg(RegisterX86::RSI) {
            log::debug!("Initial RSI: 0x{:x}", rsi);
        }
        if let Ok(rdi) = engine.read_reg(RegisterX86::RDI) {
            log::debug!("Initial RDI: 0x{:x}", rdi);
        }
        
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
            // Prefer the RIP captured at breakout; fall back to current RIP.
            let oep = oep_candidate.lock().unwrap().unwrap_or(engine.get_rip()?);
            log::info!("OEP captured at: 0x{:x}", oep);
            oep_detector.oep = Some(oep);
        }
        
        log::info!("Emulation stopped after {} instructions", final_count);
        log::info!(
            "Mirror-sync writes propagated: {}",
            *mirror_write_count.lock().unwrap()
        );

        // Diagnostic: if emulation halted in low-mem, compare the bytes
        // at the crash RIP to the matching image_base+RVA address. This
        // tells us whether the section was decrypted at all.
        if let Err(ref _e) = result {
            if let Ok(crash_rip) = engine.get_rip() {
                let image_base = self.pe.image_base;
                let image_top = image_base + self.pe.size_of_image;
                let low_mem_end = std::cmp::max(
                    (self.pe.size_of_image + 0xFFF) & !0xFFF,
                    0x1000000u64,
                );
                if crash_rip < low_mem_end {
                    let rva = crash_rip;
                    let mirror_bytes = engine.emu_mut()
                        .mem_read_as_vec(rva, 16)
                        .unwrap_or_default();
                    let image_addr = image_base + rva;
                    let image_bytes = if image_addr < image_top {
                        engine.emu_mut().mem_read_as_vec(image_addr, 16).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    log::warn!(
                        "Crash-site bytes at RVA 0x{:x}: mirror={:02x?} image={:02x?}",
                        rva, mirror_bytes, image_bytes
                    );
                }
            }
        }
        
        // Check emulation result
        if let Err(e) = result {
            log::warn!("Emulation error: {:?}", e);
            log::info!("This is often expected - emulation hit an edge case");
            
            // Get final RIP to see where it crashed
            if let Ok(rip) = engine.get_rip() {
                log::info!("Stopped at RIP: 0x{:x}", rip);
            }
        }
        
        // Update workspace from both registry and syscall handler
        let registry = api_registry_shared.lock().unwrap();
        let syscall_workspace = workspace_shared.lock().unwrap();
        *workspace = std::cmp::max(registry.workspace, *syscall_workspace);

        // Flush the devirt trace (if any). We can't consume the builder
        // here — the Unicorn hook closure keeps a strong `Arc` alive for
        // the engine's lifetime — so just flush through the lock. The
        // file closes when the engine (and its hooks) eventually drop.
        if let Some(arc) = &devirt_trace {
            let mut builder = arc.lock().map_err(|e| {
                UnpackError::EmulationError(format!("devirt trace mutex poisoned: {:?}", e))
            })?;
            let events = builder.flush()?;
            log::info!("Devirt trace finalized: {} events", events);
        }

        Ok(())
    }
    
    /// Simulate API return by popping return address and jumping to it
    fn simulate_api_return(emu: &mut Unicorn<()>) -> Result<()> {
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

/// Read all 16 GPRs + RIP out of the Unicorn emulator into a
/// `RegSnapshot`. Used to capture register state at OEP-arm time
/// so the devirt trace carries RBP (and friends) forward to the
/// offline bytecode walker.
fn snapshot_gprs(emu: &Unicorn<()>) -> Result<RegSnapshot> {
    Ok(RegSnapshot {
        rax: emu.reg_read(RegisterX86::RAX)?,
        rbx: emu.reg_read(RegisterX86::RBX)?,
        rcx: emu.reg_read(RegisterX86::RCX)?,
        rdx: emu.reg_read(RegisterX86::RDX)?,
        rsi: emu.reg_read(RegisterX86::RSI)?,
        rdi: emu.reg_read(RegisterX86::RDI)?,
        rbp: emu.reg_read(RegisterX86::RBP)?,
        rsp: emu.reg_read(RegisterX86::RSP)?,
        r8: emu.reg_read(RegisterX86::R8)?,
        r9: emu.reg_read(RegisterX86::R9)?,
        r10: emu.reg_read(RegisterX86::R10)?,
        r11: emu.reg_read(RegisterX86::R11)?,
        r12: emu.reg_read(RegisterX86::R12)?,
        r13: emu.reg_read(RegisterX86::R13)?,
        r14: emu.reg_read(RegisterX86::R14)?,
        r15: emu.reg_read(RegisterX86::R15)?,
        rip: emu.reg_read(RegisterX86::RIP)?,
    })
}
