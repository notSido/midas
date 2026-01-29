//! kernel32.dll API emulation

use crate::{Result, UnpackError};
use unicorn_engine::{Unicorn, RegisterX86};

/// VirtualAlloc implementation
pub fn virtual_alloc(emu: &mut Unicorn<'_, ()>, workspace: &mut u64) -> Result<u64> {
    // Read arguments from registers (x64 calling convention)
    let _lpaddress = emu.reg_read(RegisterX86::RCX)?;
    let dwsize = emu.reg_read(RegisterX86::RDX)?;
    let _flallocationtype = emu.reg_read(RegisterX86::R8)?;
    let _flprotect = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("VirtualAlloc: size=0x{:x}", dwsize);
    
    // Allocate memory at workspace address
    let aligned_size = ((dwsize + 0xFFF) & !0xFFF);
    let address = *workspace;
    
    emu.mem_map(address, aligned_size, unicorn_engine::unicorn_const::Prot::ALL)
        .map_err(|e| UnpackError::ApiError(format!("VirtualAlloc map failed: {:?}", e)))?;
    
    *workspace += aligned_size as u64;
    
    log::debug!("VirtualAlloc: allocated 0x{:x} bytes at 0x{:x}", aligned_size, address);
    
    // Return address in RAX
    emu.reg_write(RegisterX86::RAX, address)?;
    
    Ok(address)
}

/// VirtualProtect implementation
pub fn virtual_protect(emu: &mut Unicorn<'_, ()>) -> Result<()> {
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
pub fn get_proc_address(emu: &mut Unicorn<'_, ()>) -> Result<()> {
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
pub fn load_library_a(emu: &mut Unicorn<'_, ()>) -> Result<()> {
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
pub fn get_tick_count(emu: &mut Unicorn<'_, ()>) -> Result<()> {
    // Return a fake tick count
    emu.reg_write(RegisterX86::RAX, 0x12345678)?;
    Ok(())
}

/// QueryPerformanceCounter stub
pub fn query_performance_counter(emu: &mut Unicorn<'_, ()>) -> Result<()> {
    let lp_counter = emu.reg_read(RegisterX86::RCX)?;
    
    // Write a fake counter value
    let counter_value: u64 = 0x123456789ABCDEF;
    emu.mem_write(lp_counter, &counter_value.to_le_bytes())?;
    
    // Return success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}
