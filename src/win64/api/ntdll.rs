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

/// RtlUnwindEx - Stack unwinding for exception handling
pub fn rtl_unwind_ex(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let target_frame = emu.reg_read(RegisterX86::RCX)?;
    let target_ip = emu.reg_read(RegisterX86::RDX)?;
    let exception_record = emu.reg_read(RegisterX86::R8)?;
    let return_value = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("RtlUnwindEx: target_frame=0x{:x}, target_ip=0x{:x}, exception_record=0x{:x}, return_value=0x{:x}",
        target_frame, target_ip, exception_record, return_value);
    
    // For now, just return success - Themida typically uses this for SEH
    // In a real implementation, this would unwind the stack and call exception handlers
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// RtlVirtualUnwind - Virtual unwinding for exception handling
pub fn rtl_virtual_unwind(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let handler_type = emu.reg_read(RegisterX86::RCX)?;
    let image_base = emu.reg_read(RegisterX86::RDX)?;
    let control_pc = emu.reg_read(RegisterX86::R8)?;
    let function_entry = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("RtlVirtualUnwind: handler_type={}, image_base=0x{:x}, control_pc=0x{:x}, function_entry=0x{:x}",
        handler_type, image_base, control_pc, function_entry);
    
    // Return NULL to indicate no exception handler found
    // This is fine for Themida - it's just probing the exception handling infrastructure
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// RtlCaptureContext - Capture current execution context
pub fn rtl_capture_context(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let context_record_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("RtlCaptureContext: context_record=0x{:x}", context_record_ptr);
    
    // CONTEXT structure is quite large (around 0x4D0 bytes on x64)
    // We'll populate the basic registers that Themida might check
    
    // CONTEXT.ContextFlags offset 0x30
    let context_flags: u32 = 0x10001F; // CONTEXT_FULL | CONTEXT_AMD64
    emu.mem_write(context_record_ptr + 0x30, &context_flags.to_le_bytes())?;
    
    // Save current register state into CONTEXT structure
    // General purpose registers start at offset 0x78
    let rax = emu.reg_read(RegisterX86::RAX)?;
    let rcx = emu.reg_read(RegisterX86::RCX)?;
    let rdx = emu.reg_read(RegisterX86::RDX)?;
    let rbx = emu.reg_read(RegisterX86::RBX)?;
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let rbp = emu.reg_read(RegisterX86::RBP)?;
    let rsi = emu.reg_read(RegisterX86::RSI)?;
    let rdi = emu.reg_read(RegisterX86::RDI)?;
    let rip = emu.reg_read(RegisterX86::RIP)?;
    
    emu.mem_write(context_record_ptr + 0x78, &rax.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0x80, &rcx.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0x88, &rdx.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0x90, &rbx.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0x98, &rsp.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xA0, &rbp.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xA8, &rsi.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xB0, &rdi.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xF8, &rip.to_le_bytes())?;
    
    // R8-R15 start at offset 0xB8
    let r8 = emu.reg_read(RegisterX86::R8)?;
    let r9 = emu.reg_read(RegisterX86::R9)?;
    let r10 = emu.reg_read(RegisterX86::R10)?;
    let r11 = emu.reg_read(RegisterX86::R11)?;
    
    emu.mem_write(context_record_ptr + 0xB8, &r8.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xC0, &r9.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xC8, &r10.to_le_bytes())?;
    emu.mem_write(context_record_ptr + 0xD0, &r11.to_le_bytes())?;
    
    // No return value for this function (void)
    Ok(())
}

/// RtlLookupFunctionEntry - Find exception handler for an address
pub fn rtl_lookup_function_entry(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let control_pc = emu.reg_read(RegisterX86::RCX)?;
    let image_base_ptr = emu.reg_read(RegisterX86::RDX)?;
    let history_table = emu.reg_read(RegisterX86::R8)?;
    
    log::debug!("RtlLookupFunctionEntry: control_pc=0x{:x}, image_base_ptr=0x{:x}, history_table=0x{:x}",
        control_pc, image_base_ptr, history_table);
    
    // Return NULL to indicate no function entry found
    // This tells Themida there's no exception handler registered for this address
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// NtSetInformationThread - Set thread information (anti-debug bypass)
pub fn nt_set_information_thread(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let thread_handle = emu.reg_read(RegisterX86::RCX)?;
    let thread_information_class = emu.reg_read(RegisterX86::RDX)?;
    let thread_information = emu.reg_read(RegisterX86::R8)?;
    let thread_information_length = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("NtSetInformationThread: handle=0x{:x}, class={}, info=0x{:x}, length={}",
        thread_handle, thread_information_class, thread_information, thread_information_length);
    
    // ThreadHideFromDebugger = 0x11
    if thread_information_class == 0x11 {
        log::info!("Anti-debug: NtSetInformationThread(ThreadHideFromDebugger) - allowing");
    }
    
    // Always return success to let Themida proceed
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// NtProtectVirtualMemory - Change memory protection
pub fn nt_protect_virtual_memory(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address_ptr = emu.reg_read(RegisterX86::RDX)?;
    let region_size_ptr = emu.reg_read(RegisterX86::R8)?;
    let new_protect = emu.reg_read(RegisterX86::R9)?;
    
    // Read the base address and size
    let base_address_bytes = emu.mem_read_as_vec(base_address_ptr, 8)?;
    let base_address = u64::from_le_bytes([
        base_address_bytes[0], base_address_bytes[1], base_address_bytes[2], base_address_bytes[3],
        base_address_bytes[4], base_address_bytes[5], base_address_bytes[6], base_address_bytes[7],
    ]);
    
    let size_bytes = emu.mem_read_as_vec(region_size_ptr, 8)?;
    let size = u64::from_le_bytes([
        size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3],
        size_bytes[4], size_bytes[5], size_bytes[6], size_bytes[7],
    ]);
    
    log::debug!("NtProtectVirtualMemory: process=0x{:x}, base=0x{:x}, size=0x{:x}, protect=0x{:x}",
        process_handle, base_address, size, new_protect);
    
    // Read old protection from stack (5th parameter at [rsp+0x28])
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let old_protect_ptr_bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
    let old_protect_ptr = u64::from_le_bytes([
        old_protect_ptr_bytes[0], old_protect_ptr_bytes[1], old_protect_ptr_bytes[2], old_protect_ptr_bytes[3],
        old_protect_ptr_bytes[4], old_protect_ptr_bytes[5], old_protect_ptr_bytes[6], old_protect_ptr_bytes[7],
    ]);
    
    // Write some reasonable old protection value (PAGE_EXECUTE_READWRITE = 0x40)
    if old_protect_ptr != 0 {
        let old_protect: u32 = 0x40;
        emu.mem_write(old_protect_ptr, &old_protect.to_le_bytes())?;
    }
    
    // Map Windows protection flags to Unicorn protection
    let unicorn_prot = match new_protect {
        0x01 => unicorn_engine::unicorn_const::Prot::NONE,      // PAGE_NOACCESS
        0x02 => unicorn_engine::unicorn_const::Prot::READ,      // PAGE_READONLY
        0x04 => unicorn_engine::unicorn_const::Prot::READ | unicorn_engine::unicorn_const::Prot::WRITE, // PAGE_READWRITE
        0x10 => unicorn_engine::unicorn_const::Prot::EXEC,      // PAGE_EXECUTE
        0x20 => unicorn_engine::unicorn_const::Prot::READ | unicorn_engine::unicorn_const::Prot::EXEC, // PAGE_EXECUTE_READ
        0x40 => unicorn_engine::unicorn_const::Prot::ALL,       // PAGE_EXECUTE_READWRITE
        _ => unicorn_engine::unicorn_const::Prot::ALL,          // Default to all permissions
    };
    
    // Try to change memory protection
    // Note: Unicorn doesn't really support mem_protect well, so we might need to remap
    match emu.mem_protect(base_address, size, unicorn_prot) {
        Ok(_) => {
            log::debug!("Successfully changed memory protection at 0x{:x}", base_address);
        }
        Err(e) => {
            log::warn!("Failed to change memory protection at 0x{:x}: {:?} - continuing anyway", base_address, e);
            // Don't fail - Themida will continue even if this doesn't work perfectly
        }
    }
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}
