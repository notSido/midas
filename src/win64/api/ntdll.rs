//! ntdll.dll API emulation

use crate::Result;
use unicorn_engine::{Unicorn, RegisterX86};

/// NtQueryInformationProcess - Anti-debug bypass
pub fn nt_query_information_process(emu: &mut Unicorn<()>) -> Result<()> {
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

/// NtSetInformationThread - Anti-debug bypass
pub fn nt_set_information_thread(emu: &mut Unicorn<()>) -> Result<()> {
    let _thread_handle = emu.reg_read(RegisterX86::RCX)?;
    let thread_information_class = emu.reg_read(RegisterX86::RDX)?;
    
    log::debug!("NtSetInformationThread: class={}", thread_information_class);
    
    // ThreadHideFromDebugger = 17
    if thread_information_class == 17 {
        log::info!("Anti-debug: NtSetInformationThread(ThreadHideFromDebugger) - ignoring");
    }
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, 0)?;
    
    Ok(())
}

/// NtQuerySystemInformation stub
pub fn nt_query_system_information(emu: &mut Unicorn<()>) -> Result<()> {
    let system_information_class = emu.reg_read(RegisterX86::RCX)?;
    
    log::debug!("NtQuerySystemInformation: class={}", system_information_class);
    
    // Return STATUS_NOT_IMPLEMENTED
    emu.reg_write(RegisterX86::RAX, 0xC0000002)?;
    
    Ok(())
}
