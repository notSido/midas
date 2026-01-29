use crate::{Result, UnpackError};
use unicorn_engine::{Unicorn, RegisterX86};

/// CPU state for tracking time-based counters
pub struct CpuState {
    /// RDTSC counter value
    pub rdtsc_counter: u64,
    /// Random increment range for RDTSC to simulate realistic timing
    rdtsc_increment_min: u64,
    rdtsc_increment_max: u64,
}

impl CpuState {
    /// Create a new CPU state with realistic initial values
    pub fn new() -> Self {
        Self {
            rdtsc_counter: 0x1000000000, // Start with a realistic base value
            rdtsc_increment_min: 10000,
            rdtsc_increment_max: 50000,
        }
    }

    /// Get next RDTSC value with realistic increment
    fn next_rdtsc(&mut self) -> u64 {
        // Simulate realistic CPU cycles between RDTSC calls
        let increment = self.rdtsc_increment_min 
            + (self.rdtsc_counter % (self.rdtsc_increment_max - self.rdtsc_increment_min));
        self.rdtsc_counter = self.rdtsc_counter.wrapping_add(increment);
        self.rdtsc_counter
    }
}

impl Default for CpuState {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle CPUID instruction emulation
/// Returns realistic Intel CPU features to bypass anti-emulation checks
pub fn handle_cpuid(emu: &mut Unicorn<'_, ()>) -> Result<()> {
    let eax = emu.reg_read(RegisterX86::EAX)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to read EAX: {}", e)))?;
    
    let ecx = emu.reg_read(RegisterX86::ECX)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to read ECX: {}", e)))?;

    match eax as u32 {
        // Leaf 0: Get vendor ID and maximum supported leaf
        0x00000000 => {
            // Maximum basic CPUID leaf supported
            emu.reg_write(RegisterX86::EAX, 0x16)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            
            // Vendor ID: "GenuineIntel" (stored in EBX, EDX, ECX)
            // "Genu" in EBX
            emu.reg_write(RegisterX86::EBX, 0x756e6547)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            
            // "ineI" in EDX
            emu.reg_write(RegisterX86::EDX, 0x49656e69)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
            
            // "ntel" in ECX
            emu.reg_write(RegisterX86::ECX, 0x6c65746e)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
        }

        // Leaf 1: Processor info and feature bits
        0x00000001 => {
            // EAX: Version Information
            // Family 6, Model 158 (0x9E), Stepping 9 - Intel Core i7-8700K
            // Format: Extended Family (4 bits) | Extended Model (4 bits) | Reserved (2 bits) | 
            //         Processor Type (2 bits) | Family (4 bits) | Model (4 bits) | Stepping (4 bits)
            let stepping = 0x9;
            let model = 0xE; // Lower 4 bits of model
            let family = 0x6;
            let processor_type = 0x0; // Original OEM Processor
            let extended_model = 0x9; // Upper 4 bits of model (0x9E = 158)
            let extended_family = 0x0;
            
            let version_info = stepping 
                | (model << 4) 
                | (family << 8) 
                | (processor_type << 12)
                | (extended_model << 16)
                | (extended_family << 20);
            
            emu.reg_write(RegisterX86::EAX, version_info as u64)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;

            // EBX: Brand Index, CLFLUSH line size, Max APIC IDs, Initial APIC ID
            let brand_index = 0x0;
            let clflush_line_size = 0x8; // 8 * 8 = 64 bytes
            let max_apic_ids = 0xC; // 12 logical processors
            let initial_apic_id = 0x0;
            
            let ebx_value = brand_index 
                | (clflush_line_size << 8) 
                | (max_apic_ids << 16)
                | (initial_apic_id << 24);
            
            emu.reg_write(RegisterX86::EBX, ebx_value as u64)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;

            // ECX: Feature flags
            // CRITICAL: Bit 31 must be 0 (not running in hypervisor)
            let mut features_ecx: u32 = 0;
            features_ecx |= 1 << 0;  // SSE3
            features_ecx |= 1 << 1;  // PCLMULQDQ
            features_ecx |= 1 << 3;  // MONITOR
            features_ecx |= 1 << 9;  // SSSE3
            features_ecx |= 1 << 12; // FMA
            features_ecx |= 1 << 13; // CMPXCHG16B
            features_ecx |= 1 << 19; // SSE4.1
            features_ecx |= 1 << 20; // SSE4.2
            features_ecx |= 1 << 22; // MOVBE
            features_ecx |= 1 << 23; // POPCNT
            features_ecx |= 1 << 25; // AES
            features_ecx |= 1 << 26; // XSAVE
            features_ecx |= 1 << 27; // OSXSAVE
            features_ecx |= 1 << 28; // AVX
            features_ecx |= 1 << 29; // F16C
            features_ecx |= 1 << 30; // RDRAND
            // Bit 31 (hypervisor) = 0 - CRITICAL FOR ANTI-VM BYPASS
            
            emu.reg_write(RegisterX86::ECX, features_ecx as u64)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;

            // EDX: Feature flags
            let mut features_edx: u32 = 0;
            features_edx |= 1 << 0;  // FPU
            features_edx |= 1 << 1;  // VME
            features_edx |= 1 << 2;  // DE
            features_edx |= 1 << 3;  // PSE
            features_edx |= 1 << 4;  // TSC
            features_edx |= 1 << 5;  // MSR
            features_edx |= 1 << 6;  // PAE
            features_edx |= 1 << 7;  // MCE
            features_edx |= 1 << 8;  // CX8
            features_edx |= 1 << 9;  // APIC
            features_edx |= 1 << 11; // SEP
            features_edx |= 1 << 12; // MTRR
            features_edx |= 1 << 13; // PGE
            features_edx |= 1 << 14; // MCA
            features_edx |= 1 << 15; // CMOV
            features_edx |= 1 << 16; // PAT
            features_edx |= 1 << 17; // PSE-36
            features_edx |= 1 << 19; // CLFSH
            features_edx |= 1 << 23; // MMX
            features_edx |= 1 << 24; // FXSR
            features_edx |= 1 << 25; // SSE
            features_edx |= 1 << 26; // SSE2
            features_edx |= 1 << 28; // HTT
            
            emu.reg_write(RegisterX86::EDX, features_edx as u64)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }

        // Leaf 7: Extended Features (with ECX as sub-leaf)
        0x00000007 => {
            if ecx == 0 {
                // EAX: Maximum sub-leaf
                emu.reg_write(RegisterX86::EAX, 0x0)
                    .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;

                // EBX: Extended feature flags
                let mut features_ebx: u32 = 0;
                features_ebx |= 1 << 0;  // FSGSBASE
                features_ebx |= 1 << 3;  // BMI1
                features_ebx |= 1 << 5;  // AVX2
                features_ebx |= 1 << 7;  // SMEP
                features_ebx |= 1 << 8;  // BMI2
                features_ebx |= 1 << 9;  // ERMS
                features_ebx |= 1 << 10; // INVPCID
                features_ebx |= 1 << 18; // RDSEED
                features_ebx |= 1 << 19; // ADX
                features_ebx |= 1 << 20; // SMAP
                
                emu.reg_write(RegisterX86::EBX, features_ebx as u64)
                    .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;

                // ECX: Additional features
                emu.reg_write(RegisterX86::ECX, 0x0)
                    .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;

                // EDX: Additional features
                emu.reg_write(RegisterX86::EDX, 0x0)
                    .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
            }
        }

        // Leaf 0x80000000: Get highest extended function supported
        0x80000000 => {
            emu.reg_write(RegisterX86::EAX, 0x80000008)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            
            emu.reg_write(RegisterX86::EBX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            
            emu.reg_write(RegisterX86::ECX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
            
            emu.reg_write(RegisterX86::EDX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }

        // Leaf 0x80000002-0x80000004: Processor Brand String
        // "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz"
        0x80000002 => {
            // "Intel(R) Core(TM) "
            emu.reg_write(RegisterX86::EAX, 0x65746E49) // "Inte"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            emu.reg_write(RegisterX86::EBX, 0x2952286C) // "l(R)"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            emu.reg_write(RegisterX86::ECX, 0x726F4320) // " Cor"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
            emu.reg_write(RegisterX86::EDX, 0x4D542865) // "e(TM"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }

        0x80000003 => {
            // ") i7-8700K CPU "
            emu.reg_write(RegisterX86::EAX, 0x37692029) // ") i7"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            emu.reg_write(RegisterX86::EBX, 0x3030382D) // "-800"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            emu.reg_write(RegisterX86::ECX, 0x5043204B) // "K CP"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
            emu.reg_write(RegisterX86::EDX, 0x20402055) // "U @ "
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }

        0x80000004 => {
            // "3.70GHz\0\0\0\0\0\0\0\0\0"
            emu.reg_write(RegisterX86::EAX, 0x30372E33) // "3.70"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            emu.reg_write(RegisterX86::EBX, 0x007A4847) // "GHz\0"
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            emu.reg_write(RegisterX86::ECX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
            emu.reg_write(RegisterX86::EDX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }

        // Leaf 0x80000008: Virtual and Physical address sizes
        0x80000008 => {
            // EAX bits 7-0: Physical address bits (39)
            // EAX bits 15-8: Linear address bits (48)
            let phys_bits = 39;
            let linear_bits = 48;
            
            emu.reg_write(RegisterX86::EAX, (linear_bits << 8 | phys_bits) as u64)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            
            emu.reg_write(RegisterX86::EBX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            
            emu.reg_write(RegisterX86::ECX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
            
            emu.reg_write(RegisterX86::EDX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }

        // For any other leaf, return zeros
        _ => {
            emu.reg_write(RegisterX86::EAX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX: {}", e)))?;
            emu.reg_write(RegisterX86::EBX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EBX: {}", e)))?;
            emu.reg_write(RegisterX86::ECX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write ECX: {}", e)))?;
            emu.reg_write(RegisterX86::EDX, 0x0)
                .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX: {}", e)))?;
        }
    }

    Ok(())
}

/// Handle RDTSC instruction emulation
/// Returns a realistic timestamp counter value that increments over time
pub fn handle_rdtsc(emu: &mut Unicorn<'_, ()>, state: &mut CpuState) -> Result<()> {
    let tsc = state.next_rdtsc();
    
    // RDTSC returns value in EDX:EAX
    // EDX contains high 32 bits, EAX contains low 32 bits
    let low = (tsc & 0xFFFFFFFF) as u64;
    let high = (tsc >> 32) as u64;
    
    emu.reg_write(RegisterX86::EAX, low)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to write EAX for RDTSC: {}", e)))?;
    
    emu.reg_write(RegisterX86::EDX, high)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to write EDX for RDTSC: {}", e)))?;
    
    Ok(())
}

/// Detect if the bytes at current EIP are a CPUID instruction (0x0F 0xA2)
pub fn is_cpuid_instruction(emu: &Unicorn<'_, ()>) -> Result<bool> {
    let eip = emu.reg_read(RegisterX86::EIP)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to read EIP: {}", e)))?;
    
    let mut code = [0u8; 2];
    emu.mem_read(eip, &mut code)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to read memory at EIP: {}", e)))?;
    
    Ok(code[0] == 0x0F && code[1] == 0xA2)
}

/// Detect if the bytes at current EIP are a RDTSC instruction (0x0F 0x31)
pub fn is_rdtsc_instruction(emu: &Unicorn<'_, ()>) -> Result<bool> {
    let eip = emu.reg_read(RegisterX86::EIP)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to read EIP: {}", e)))?;
    
    let mut code = [0u8; 2];
    emu.mem_read(eip, &mut code)
        .map_err(|e| UnpackError::EmulationError(format!("Failed to read memory at EIP: {}", e)))?;
    
    Ok(code[0] == 0x0F && code[1] == 0x31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_state_rdtsc_increment() {
        let mut state = CpuState::new();
        let initial = state.rdtsc_counter;
        
        let tsc1 = state.next_rdtsc();
        let tsc2 = state.next_rdtsc();
        
        // Ensure counter increments
        assert!(tsc1 > initial);
        assert!(tsc2 > tsc1);
        
        // Ensure realistic increments
        let diff = tsc2 - tsc1;
        assert!(diff >= state.rdtsc_increment_min);
        assert!(diff <= state.rdtsc_increment_max);
    }

    #[test]
    fn test_cpu_state_default() {
        let state = CpuState::default();
        assert_eq!(state.rdtsc_counter, 0x1000000000);
        assert_eq!(state.rdtsc_increment_min, 10000);
        assert_eq!(state.rdtsc_increment_max, 50000);
    }
}
