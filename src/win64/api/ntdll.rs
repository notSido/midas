//! ntdll.dll API emulation

use crate::{Result, UnpackError};
use unicorn_engine::{Unicorn, RegisterX86};



/// NtQuerySystemInformation stub
pub fn nt_query_system_information(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let system_information_class = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("NtQuerySystemInformation: class={}", system_information_class);
    
    // Return STATUS_NOT_IMPLEMENTED
    emu.reg_write(RegisterX86::RAX, 0xC0000002)?;
    
    Ok(())
}

/// NtClose stub
pub fn nt_close(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let handle = emu.reg_read(RegisterX86::RCX)?;
    log::debug!("NtClose: handle=0x{:x}", handle);
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// NtAllocateVirtualMemory stub
pub fn nt_allocate_virtual_memory(emu: &mut Unicorn<'_, ()>, workspace: &mut u64) -> Result<()> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address_ptr = emu.reg_read(RegisterX86::RDX)?;
    let _zero_bits = emu.reg_read(RegisterX86::R8)?;
    let region_size_ptr = emu.reg_read(RegisterX86::R9)?;
    
    // Read size
    let size_bytes = emu.mem_read_as_vec(region_size_ptr, 8)?;
    let size = u64::from_le_bytes([
        size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3],
        size_bytes[4], size_bytes[5], size_bytes[6], size_bytes[7],
    ]);
    
    log::debug!("NtAllocateVirtualMemory: size=0x{:x}", size);
    
    // Allocate at workspace
    let aligned_size = (size + 0xFFF) & !0xFFF;
    let address = *workspace;
    
    emu.mem_map(address, aligned_size, unicorn_engine::unicorn_const::Prot::ALL)
        .map_err(|e| UnpackError::ApiError(format!("NtAllocateVirtualMemory map failed: {:?}", e)))?;
    
    *workspace += aligned_size;
    
    // Write address back
    emu.mem_write(base_address_ptr, &address.to_le_bytes())?;
    emu.mem_write(region_size_ptr, &aligned_size.to_le_bytes())?;
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// RtlGetVersion stub
pub fn rtl_get_version(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let version_info_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("RtlGetVersion: 0x{:x}", version_info_ptr);
    
    // RTL_OSVERSIONINFOEXW structure
    // dwOSVersionInfoSize, dwMajorVersion (10), dwMinorVersion (0), dwBuildNumber, dwPlatformId, szCSDVersion, ...
    let mut buffer = vec![0u8; 0x11C]; // Size of RTL_OSVERSIONINFOEXW
    
    // Write version info (Windows 10)
    buffer[4..8].copy_from_slice(&10u32.to_le_bytes()); // Major version
    buffer[8..12].copy_from_slice(&0u32.to_le_bytes()); // Minor version
    buffer[12..16].copy_from_slice(&19041u32.to_le_bytes()); // Build number
    buffer[16..20].copy_from_slice(&2u32.to_le_bytes()); // Platform ID (VER_PLATFORM_WIN32_NT)
    
    emu.mem_write(version_info_ptr, &buffer)?;
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// RtlAddFunctionTable stub (for exception handling)
pub fn rtl_add_function_table(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let function_table = emu.reg_read(RegisterX86::RCX)?;
    let entry_count = emu.reg_read(RegisterX86::RDX)?;
    let base_address = emu.reg_read(RegisterX86::R8)?;
    
    log::debug!("RtlAddFunctionTable: table=0x{:x}, count={}, base=0x{:x}", 
        function_table, entry_count, base_address);
    
    // Return TRUE (1)
    emu.reg_write(RegisterX86::RAX, 1)?;
    Ok(())
}

/// NtQueryInformationProcess - Anti-debug bypass (workspace version)
pub fn nt_query_information_process(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let process_information_class = emu.reg_read(RegisterX86::RDX)?;
    let process_information = emu.reg_read(RegisterX86::R8)?;
    let _process_information_length = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("NtQueryInformationProcess: class={}", process_information_class);
    
    // ProcessDebugPort = 7, ProcessDebugObjectHandle = 30
    if process_information_class == 7 || process_information_class == 30 {
        log::info!("Anti-debug: NtQueryInformationProcess(ProcessDebugPort/ObjectHandle) - returning 0");
        
        // Write 0 to indicate no debugger
        let zero: u64 = 0;
        emu.mem_write(process_information, &zero.to_le_bytes())?;
        
        // Return STATUS_SUCCESS (0)
        emu.reg_write(RegisterX86::RAX, 0)?;
    } else {
        // Return STATUS_NOT_IMPLEMENTED for other classes
        emu.reg_write(RegisterX86::RAX, 0xC0000002)?;
    }
    
    Ok(())
}
