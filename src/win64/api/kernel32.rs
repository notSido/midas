//! kernel32.dll API emulation

use crate::{Result, UnpackError};
use unicorn_engine::{Unicorn, RegisterX86};

/// VirtualAlloc implementation
pub fn virtual_alloc(emu: &mut Unicorn<'_, ()>, workspace: &mut u64) -> Result<()> {
    // Read arguments from registers (x64 calling convention)
    let _lpaddress = emu.reg_read(RegisterX86::RCX)?;
    let dwsize = emu.reg_read(RegisterX86::RDX)?;
    let _flallocationtype = emu.reg_read(RegisterX86::R8)?;
    let _flprotect = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("VirtualAlloc: size=0x{:x}", dwsize);
    
    // Allocate memory at workspace address
    let aligned_size = (dwsize + 0xFFF) & !0xFFF;
    let address = *workspace;
    
    emu.mem_map(address, aligned_size, unicorn_engine::unicorn_const::Prot::ALL)
        .map_err(|e| UnpackError::ApiError(format!("VirtualAlloc map failed: {:?}", e)))?;
    
    *workspace += aligned_size as u64;
    
    log::debug!("VirtualAlloc: allocated 0x{:x} bytes at 0x{:x}", aligned_size, address);
    
    // Return address in RAX
    emu.reg_write(RegisterX86::RAX, address)?;
    
    Ok(())
}

/// VirtualProtect implementation
pub fn virtual_protect(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpaddress = emu.reg_read(RegisterX86::RCX)?;
    let dwsize = emu.reg_read(RegisterX86::RDX)?;
    let _flnewprotect = emu.reg_read(RegisterX86::R8)?;
    let _lpfloldprotect = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("VirtualProtect: addr=0x{:x}, size=0x{:x}", lpaddress, dwsize);
    
    // Just return success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}

/// GetProcAddress stub
pub fn get_proc_address(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let hmodule = emu.reg_read(RegisterX86::RCX)?;
    let lpprocname = emu.reg_read(RegisterX86::RDX)?;
    
    // Try to read the function name
    let mut name_bytes = Vec::new();
    for i in 0..256 {
        let byte = emu.mem_read_as_vec(lpprocname + i, 1)
            .unwrap_or(vec![0])[0];
        if byte == 0 {
            break;
        }
        name_bytes.push(byte);
    }
    
    let func_name = String::from_utf8_lossy(&name_bytes);
    log::debug!("GetProcAddress: module=0x{:x}, func={}", hmodule, func_name);
    
    // Return a fake address (we'll hook this later)
    let fake_addr = 0xFEED_0000 + (func_name.len() as u64 * 0x100);
    emu.reg_write(RegisterX86::RAX, fake_addr)?;
    
    Ok(())
}

/// LoadLibraryA stub
pub fn load_library_a(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpfilename = emu.reg_read(RegisterX86::RCX)?;
    
    // Try to read the library name
    let mut name_bytes = Vec::new();
    for i in 0..256 {
        let byte = emu.mem_read_as_vec(lpfilename + i, 1)
            .unwrap_or(vec![0])[0];
        if byte == 0 {
            break;
        }
        name_bytes.push(byte);
    }
    
    let lib_name = String::from_utf8_lossy(&name_bytes);
    log::debug!("LoadLibraryA: {}", lib_name);
    
    // Return a fake module handle
    let fake_handle = 0x7000_0000 + (lib_name.len() as u64 * 0x10000);
    emu.reg_write(RegisterX86::RAX, fake_handle)?;
    
    Ok(())
}

/// GetTickCount stub
pub fn get_tick_count(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    // Return a fake tick count
    emu.reg_write(RegisterX86::RAX, 0x12345678)?;
    Ok(())
}

/// QueryPerformanceCounter stub
pub fn query_performance_counter(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lp_counter = emu.reg_read(RegisterX86::RCX)?;
    
    // Write a fake counter value
    let counter_value: u64 = 0x123456789ABCDEF;
    emu.mem_write(lp_counter, &counter_value.to_le_bytes())?;
    
    // Return success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}

/// VirtualFree stub
pub fn virtual_free(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpaddress = emu.reg_read(RegisterX86::RCX)?;
    let dwsize = emu.reg_read(RegisterX86::RDX)?;
    let _dwfreetype = emu.reg_read(RegisterX86::R8)?;
    
    log::debug!("VirtualFree: addr=0x{:x}, size=0x{:x}", lpaddress, dwsize);
    
    // Return success (we don't actually free in emulation)
    emu.reg_write(RegisterX86::RAX, 1)?;
    Ok(())
}

/// VirtualQuery stub
pub fn virtual_query(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpaddress = emu.reg_read(RegisterX86::RCX)?;
    let _lpbuffer = emu.reg_read(RegisterX86::RDX)?;
    let _dwlength = emu.reg_read(RegisterX86::R8)?;
    
    log::debug!("VirtualQuery: addr=0x{:x}", lpaddress);
    
    // Return 0 (not implemented)
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// LoadLibraryW stub (wide char version)
pub fn load_library_w(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpfilename = emu.reg_read(RegisterX86::RCX)?;
    
    // Read wide string
    let mut name_bytes = Vec::new();
    for i in (0..512).step_by(2) {
        let bytes = emu.mem_read_as_vec(lpfilename + i, 2)
            .unwrap_or(vec![0, 0]);
        if bytes[0] == 0 && bytes[1] == 0 {
            break;
        }
        name_bytes.push(bytes[0]);
        name_bytes.push(bytes[1]);
    }
    
    let lib_name = String::from_utf16_lossy(
        &name_bytes.chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
            .collect::<Vec<u16>>()
    );
    log::debug!("LoadLibraryW: {}", lib_name);
    
    // Return fake handle
    let fake_handle = 0x7000_0000 + (lib_name.len() as u64 * 0x10000);
    emu.reg_write(RegisterX86::RAX, fake_handle)?;
    Ok(())
}

/// GetModuleHandleA stub
pub fn get_module_handle_a(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpmodulename = emu.reg_read(RegisterX86::RCX)?;
    
    if lpmodulename == 0 {
        // NULL = return handle to current process
        emu.reg_write(RegisterX86::RAX, 0x00400000)?;
        return Ok(());
    }
    
    let mut name_bytes = Vec::new();
    for i in 0..256 {
        let byte = emu.mem_read_as_vec(lpmodulename + i, 1)
            .unwrap_or(vec![0])[0];
        if byte == 0 {
            break;
        }
        name_bytes.push(byte);
    }
    
    let module_name = String::from_utf8_lossy(&name_bytes);
    log::debug!("GetModuleHandleA: {}", module_name);
    
    // Return fake handle
    let fake_handle = 0x7000_0000 + (module_name.len() as u64 * 0x10000);
    emu.reg_write(RegisterX86::RAX, fake_handle)?;
    Ok(())
}

/// GetModuleHandleW stub
pub fn get_module_handle_w(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpmodulename = emu.reg_read(RegisterX86::RCX)?;
    
    if lpmodulename == 0 {
        // NULL = return handle to current process
        emu.reg_write(RegisterX86::RAX, 0x00400000)?;
        return Ok(());
    }
    
    log::debug!("GetModuleHandleW: 0x{:x}", lpmodulename);
    
    // Return fake handle
    emu.reg_write(RegisterX86::RAX, 0x70000000)?;
    Ok(())
}

/// GetModuleFileNameA stub
pub fn get_module_filename_a(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let _hmodule = emu.reg_read(RegisterX86::RCX)?;
    let lpfilename = emu.reg_read(RegisterX86::RDX)?;
    let nsize = emu.reg_read(RegisterX86::R8)?;
    
    log::debug!("GetModuleFileNameA: buffer=0x{:x}, size={}", lpfilename, nsize);
    
    // Write fake filename
    let filename = b"C:\\Windows\\System32\\sample.exe\0";
    let len = filename.len().min(nsize as usize);
    emu.mem_write(lpfilename, &filename[..len])?;
    
    // Return length
    emu.reg_write(RegisterX86::RAX, len as u64)?;
    Ok(())
}

/// GetTickCount64 stub
pub fn get_tick_count64(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    emu.reg_write(RegisterX86::RAX, 0x123456789)?;
    Ok(())
}

/// GetSystemTimeAsFileTime stub
pub fn get_system_time_as_file_time(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpsystemtimeasfiletime = emu.reg_read(RegisterX86::RCX)?;
    
    // Write fake FILETIME (8 bytes)
    let filetime: u64 = 0x01d0_0000_0000_0000;
    emu.mem_write(lpsystemtimeasfiletime, &filetime.to_le_bytes())?;
    
    Ok(())
}

/// GetCurrentProcessId stub
pub fn get_current_process_id(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    emu.reg_write(RegisterX86::RAX, 1234)?;
    Ok(())
}

/// GetCurrentThreadId stub
pub fn get_current_thread_id(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    emu.reg_write(RegisterX86::RAX, 5678)?;
    Ok(())
}

/// GetCurrentProcess stub
pub fn get_current_process(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    emu.reg_write(RegisterX86::RAX, 0xFFFFFFFFFFFFFFFF)?; // -1 pseudo handle
    Ok(())
}

/// GetCurrentThread stub
pub fn get_current_thread(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    emu.reg_write(RegisterX86::RAX, 0xFFFFFFFFFFFFFFFE)?; // -2 pseudo handle
    Ok(())
}

/// Sleep stub
pub fn sleep(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let dwmilliseconds = emu.reg_read(RegisterX86::RCX)?;
    log::debug!("Sleep: {}ms (ignored)", dwmilliseconds);
    Ok(())
}

/// ExitProcess stub
pub fn exit_process(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let uexitcode = emu.reg_read(RegisterX86::RCX)?;
    log::info!("ExitProcess: exit code {}", uexitcode);
    
    // Stop emulation
    emu.emu_stop()
        .map_err(|e| UnpackError::EmulationError(format!("Failed to stop: {:?}", e)))?;
    
    Ok(())
}

/// FlushInstructionCache stub
pub fn flush_instruction_cache(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let hprocess = emu.reg_read(RegisterX86::RCX)?;
    let lpbaseaddress = emu.reg_read(RegisterX86::RDX)?;
    let dwsize = emu.reg_read(RegisterX86::R8)?;
    
    log::debug!("FlushInstructionCache: process=0x{:x}, addr=0x{:x}, size=0x{:x}", 
                hprocess, lpbaseaddress, dwsize);
    
    // Return success
    emu.reg_write(RegisterX86::RAX, 1)?;
    Ok(())
}

/// GetLastError stub
pub fn get_last_error(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    log::debug!("GetLastError");
    
    // Return ERROR_SUCCESS (0)
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// SetLastError stub
pub fn set_last_error(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let dwerrcode = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("SetLastError: code=0x{:x}", dwerrcode);
    
    // No return value (void function)
    Ok(())
}

/// GetSystemInfo stub
pub fn get_system_info(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpsysteminfo = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("GetSystemInfo: buffer=0x{:x}", lpsysteminfo);
    
    // SYSTEM_INFO structure (48 bytes on x64)
    let mut system_info = vec![0u8; 48];
    
    // wProcessorArchitecture (WORD) - PROCESSOR_ARCHITECTURE_AMD64 = 9
    system_info[0..2].copy_from_slice(&9u16.to_le_bytes());
    
    // dwPageSize (DWORD) - 4096
    system_info[4..8].copy_from_slice(&4096u32.to_le_bytes());
    
    // lpMinimumApplicationAddress (LPVOID) - 0x10000
    system_info[8..16].copy_from_slice(&0x10000u64.to_le_bytes());
    
    // lpMaximumApplicationAddress (LPVOID) - 0x7FFFFFFFFFFF
    system_info[16..24].copy_from_slice(&0x7FFFFFFFFFFFu64.to_le_bytes());
    
    // dwActiveProcessorMask (DWORD_PTR) - 0xFF (8 cores)
    system_info[24..32].copy_from_slice(&0xFFu64.to_le_bytes());
    
    // dwNumberOfProcessors (DWORD) - 8
    system_info[32..36].copy_from_slice(&8u32.to_le_bytes());
    
    // dwProcessorType (DWORD) - PROCESSOR_AMD_X8664 = 8664
    system_info[36..40].copy_from_slice(&8664u32.to_le_bytes());
    
    // dwAllocationGranularity (DWORD) - 65536
    system_info[40..44].copy_from_slice(&65536u32.to_le_bytes());
    
    // wProcessorLevel (WORD) - 6
    system_info[44..46].copy_from_slice(&6u16.to_le_bytes());
    
    // wProcessorRevision (WORD) - 0
    system_info[46..48].copy_from_slice(&0u16.to_le_bytes());
    
    emu.mem_write(lpsysteminfo, &system_info)?;
    
    // No return value (void function)
    Ok(())
}

/// IsDebuggerPresent - Anti-debug check (always return false)
pub fn is_debugger_present(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    log::debug!("IsDebuggerPresent: returning FALSE");
    
    // Return FALSE (0)
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}

/// CheckRemoteDebuggerPresent - Anti-debug check (always return false)
pub fn check_remote_debugger_present(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let _hprocess = emu.reg_read(RegisterX86::RCX)?;
    let pbdebuggerpresent = emu.reg_read(RegisterX86::RDX)?;
    
    log::debug!("CheckRemoteDebuggerPresent: returning FALSE");
    
    // Write FALSE (0) to output parameter
    emu.mem_write(pbdebuggerpresent, &0u32.to_le_bytes())?;
    
    // Return success (TRUE)
    emu.reg_write(RegisterX86::RAX, 1)?;
    Ok(())
}

/// OutputDebugStringA - Debug output (ignore)
pub fn output_debug_string_a(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let lpoutputstring = emu.reg_read(RegisterX86::RCX)?;
    
    // Try to read the debug string
    let mut string_bytes = Vec::new();
    for i in 0..256 {
        let byte = emu.mem_read_as_vec(lpoutputstring + i, 1)
            .unwrap_or(vec![0])[0];
        if byte == 0 {
            break;
        }
        string_bytes.push(byte);
    }
    
    let debug_string = String::from_utf8_lossy(&string_bytes);
    log::debug!("OutputDebugStringA: {}", debug_string);
    
    // No return value (void function)
    Ok(())
}

/// CloseHandle stub - Handle closing (always succeeds)
pub fn close_handle(emu: &mut Unicorn<'_, ()>, _workspace: &mut u64) -> Result<()> {
    let hobject = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("CloseHandle: handle=0x{:x}", hobject);
    
    // Return TRUE (success)
    emu.reg_write(RegisterX86::RAX, 1)?;
    Ok(())
}
