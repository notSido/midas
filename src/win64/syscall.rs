//! Windows NT Syscall handling
//! 
//! Modern packers like Themida use direct syscalls to bypass API hooks.
//! This module intercepts syscall instructions and emulates NT kernel functions.

use crate::{Result, UnpackError};
use unicorn_engine::{Unicorn, RegisterX86};

/// Syscall dispatcher - handles syscall instruction
pub fn handle_syscall(emu: &mut Unicorn<'_, ()>, workspace: &mut u64) -> Result<()> {
    // On x64 Windows, syscall number is in RAX
    let syscall_num = emu.reg_read(RegisterX86::RAX)?;
    
    // Arguments in RCX, RDX, R8, R9, stack...
    let arg1 = emu.reg_read(RegisterX86::RCX)?;
    let arg2 = emu.reg_read(RegisterX86::RDX)?;
    let arg3 = emu.reg_read(RegisterX86::R8)?;
    let arg4 = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("Syscall 0x{:x}: args=(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x})", 
        syscall_num, arg1, arg2, arg3, arg4);
    
    // Dispatch based on syscall number (Windows 10 x64 syscall table)
    let status = match syscall_num {
        0x18 => nt_allocate_virtual_memory(emu, workspace)?,
        0x50 => nt_protect_virtual_memory(emu)?,
        0x19 => nt_query_information_process(emu)?,
        0x0D => nt_query_system_information(emu)?,
        0x0F => nt_close(emu)?,
        0x36 => nt_query_virtual_memory(emu)?,
        0x1E => nt_free_virtual_memory(emu)?,
        0x37 => nt_read_virtual_memory(emu)?,
        0x3A => nt_write_virtual_memory(emu)?,
        0x0C => nt_open_process(emu)?,
        _ => {
            log::warn!("Unimplemented syscall: 0x{:x}", syscall_num);
            0xC0000002 // STATUS_NOT_IMPLEMENTED
        }
    };
    
    // Return status in RAX
    emu.reg_write(RegisterX86::RAX, status)?;
    
    // Advance RIP past syscall instruction (2 bytes: 0x0F 0x05)
    let rip = emu.reg_read(RegisterX86::RIP)?;
    emu.reg_write(RegisterX86::RIP, rip + 2)?;
    
    Ok(())
}

/// NtAllocateVirtualMemory - Syscall 0x18
fn nt_allocate_virtual_memory(emu: &mut Unicorn<'_, ()>, workspace: &mut u64) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address_ptr = emu.reg_read(RegisterX86::RDX)?;
    let _zero_bits = emu.reg_read(RegisterX86::R8)?;
    let region_size_ptr = emu.reg_read(RegisterX86::R9)?;
    
    // Read size from memory
    let size_bytes = emu.mem_read_as_vec(region_size_ptr, 8)?;
    let size = u64::from_le_bytes([
        size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3],
        size_bytes[4], size_bytes[5], size_bytes[6], size_bytes[7],
    ]);
    
    log::debug!("NtAllocateVirtualMemory: size=0x{:x}", size);
    
    // Allocate at workspace
    let aligned_size = (size + 0xFFF) & !0xFFF;
    let address = *workspace;
    
    // Try to map memory
    match emu.mem_map(address, aligned_size, unicorn_engine::unicorn_const::Prot::ALL) {
        Ok(_) => {
            *workspace += aligned_size;
            
            // Write address back
            emu.mem_write(base_address_ptr, &address.to_le_bytes())?;
            emu.mem_write(region_size_ptr, &aligned_size.to_le_bytes())?;
            
            log::debug!("NtAllocateVirtualMemory: allocated 0x{:x} bytes at 0x{:x}", aligned_size, address);
            Ok(0) // STATUS_SUCCESS
        }
        Err(e) => {
            log::error!("NtAllocateVirtualMemory failed: {:?}", e);
            Ok(0xC0000017) // STATUS_NO_MEMORY
        }
    }
}

/// NtProtectVirtualMemory - Syscall 0x50
fn nt_protect_virtual_memory(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address_ptr = emu.reg_read(RegisterX86::RDX)?;
    let region_size_ptr = emu.reg_read(RegisterX86::R8)?;
    let new_protect = emu.reg_read(RegisterX86::R9)?;
    
    // Read from stack for 5th parameter (old protect pointer)
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let old_protect_ptr_bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
    let old_protect_ptr = u64::from_le_bytes([
        old_protect_ptr_bytes[0], old_protect_ptr_bytes[1], old_protect_ptr_bytes[2], old_protect_ptr_bytes[3],
        old_protect_ptr_bytes[4], old_protect_ptr_bytes[5], old_protect_ptr_bytes[6], old_protect_ptr_bytes[7],
    ]);
    
    log::debug!("NtProtectVirtualMemory: new_protect=0x{:x}", new_protect);
    
    // Write old protection (fake it as PAGE_EXECUTE_READWRITE)
    if old_protect_ptr != 0 {
        emu.mem_write(old_protect_ptr, &0x40u32.to_le_bytes())?;
    }
    
    Ok(0) // STATUS_SUCCESS
}

/// NtQueryInformationProcess - Syscall 0x19
fn nt_query_information_process(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let process_information_class = emu.reg_read(RegisterX86::RDX)?;
    let process_information = emu.reg_read(RegisterX86::R8)?;
    let _process_information_length = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("NtQueryInformationProcess: class={}", process_information_class);
    
    // ProcessDebugPort = 7, ProcessDebugObjectHandle = 30
    if process_information_class == 7 || process_information_class == 30 {
        log::info!("Anti-debug: NtQueryInformationProcess(DebugPort/Object) - returning 0");
        
        // Write 0 to indicate no debugger
        let zero: u64 = 0;
        emu.mem_write(process_information, &zero.to_le_bytes())?;
        
        Ok(0) // STATUS_SUCCESS
    } else {
        Ok(0xC0000002) // STATUS_NOT_IMPLEMENTED
    }
}

/// NtQuerySystemInformation - Syscall 0x0D
fn nt_query_system_information(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let system_information_class = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("NtQuerySystemInformation: class={}", system_information_class);
    
    Ok(0xC0000002) // STATUS_NOT_IMPLEMENTED
}

/// NtClose - Syscall 0x0F
fn nt_close(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let handle = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("NtClose: handle=0x{:x}", handle);
    
    Ok(0) // STATUS_SUCCESS
}

/// NtQueryVirtualMemory - Syscall 0x36
fn nt_query_virtual_memory(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address = emu.reg_read(RegisterX86::RDX)?;
    
    log::debug!("NtQueryVirtualMemory: addr=0x{:x}", base_address);
    
    Ok(0xC0000002) // STATUS_NOT_IMPLEMENTED
}

/// NtFreeVirtualMemory - Syscall 0x1E
fn nt_free_virtual_memory(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address_ptr = emu.reg_read(RegisterX86::RDX)?;
    
    // Read address
    let addr_bytes = emu.mem_read_as_vec(base_address_ptr, 8)?;
    let address = u64::from_le_bytes([
        addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
        addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7],
    ]);
    
    log::debug!("NtFreeVirtualMemory: addr=0x{:x}", address);
    
    // Don't actually free in emulation
    Ok(0) // STATUS_SUCCESS
}

/// NtReadVirtualMemory - Syscall 0x37
fn nt_read_virtual_memory(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address = emu.reg_read(RegisterX86::RDX)?;
    let buffer = emu.reg_read(RegisterX86::R8)?;
    let number_of_bytes_to_read = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("NtReadVirtualMemory: addr=0x{:x}, size=0x{:x}", base_address, number_of_bytes_to_read);
    
    // Read from source and write to buffer
    match emu.mem_read_as_vec(base_address, number_of_bytes_to_read as usize) {
        Ok(data) => {
            emu.mem_write(buffer, &data)?;
            Ok(0) // STATUS_SUCCESS
        }
        Err(_) => {
            Ok(0xC0000005) // STATUS_ACCESS_VIOLATION
        }
    }
}

/// NtWriteVirtualMemory - Syscall 0x3A
fn nt_write_virtual_memory(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let _process_handle = emu.reg_read(RegisterX86::RCX)?;
    let base_address = emu.reg_read(RegisterX86::RDX)?;
    let buffer = emu.reg_read(RegisterX86::R8)?;
    let number_of_bytes_to_write = emu.reg_read(RegisterX86::R9)?;
    
    log::debug!("NtWriteVirtualMemory: addr=0x{:x}, size=0x{:x}", base_address, number_of_bytes_to_write);
    
    // Read from buffer and write to destination
    match emu.mem_read_as_vec(buffer, number_of_bytes_to_write as usize) {
        Ok(data) => {
            match emu.mem_write(base_address, &data) {
                Ok(_) => Ok(0), // STATUS_SUCCESS
                Err(_) => Ok(0xC0000005) // STATUS_ACCESS_VIOLATION
            }
        }
        Err(_) => {
            Ok(0xC0000005) // STATUS_ACCESS_VIOLATION
        }
    }
}

/// NtOpenProcess - Syscall 0x0C
fn nt_open_process(emu: &mut Unicorn<'_, ()>) -> Result<u64> {
    let process_handle_ptr = emu.reg_read(RegisterX86::RCX)?;
    let _desired_access = emu.reg_read(RegisterX86::RDX)?;
    
    log::debug!("NtOpenProcess");
    
    // Return fake handle
    let fake_handle: u64 = 0x1234;
    emu.mem_write(process_handle_ptr, &fake_handle.to_le_bytes())?;
    
    Ok(0) // STATUS_SUCCESS
}
