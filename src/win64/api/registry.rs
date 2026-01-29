//! API registry and dispatcher

use crate::Result;
use unicorn_engine::Unicorn;
use std::collections::HashMap;

/// API function type
pub type ApiFn = fn(&mut Unicorn<()>, &mut u64) -> Result<()>;

/// API registry that maps addresses to API implementations
pub struct ApiRegistry {
    /// Map of hook address -> (dll_name, function_name, implementation)
    apis: HashMap<u64, (String, String, ApiFn)>,
    /// Next available hook address
    next_hook_addr: u64,
    /// Workspace for VirtualAlloc
    pub workspace: u64,
}

impl ApiRegistry {
    pub fn new(base_addr: u64, workspace: u64) -> Self {
        let mut registry = Self {
            apis: HashMap::new(),
            next_hook_addr: base_addr,
            workspace,
        };
        
        // Register all APIs
        registry.register_kernel32_apis();
        registry.register_ntdll_apis();
        
        registry
    }
    
    /// Register an API
    fn register(&mut self, dll: &str, name: &str, func: ApiFn) -> u64 {
        let addr = self.next_hook_addr;
        self.apis.insert(addr, (dll.to_string(), name.to_string(), func));
        self.next_hook_addr += 0x10; // 16 bytes per API
        log::debug!("Registered {}!{} at 0x{:x}", dll, name, addr);
        addr
    }
    
    /// Register kernel32.dll APIs
    fn register_kernel32_apis(&mut self) {
        use super::kernel32::*;
        
        // Memory management
        self.register("kernel32.dll", "VirtualAlloc", virtual_alloc);
        self.register("kernel32.dll", "VirtualProtect", virtual_protect);
        self.register("kernel32.dll", "VirtualFree", virtual_free);
        self.register("kernel32.dll", "VirtualQuery", virtual_query);
        self.register("kernel32.dll", "FlushInstructionCache", flush_instruction_cache);
        
        // Module/Library management
        self.register("kernel32.dll", "LoadLibraryA", load_library_a);
        self.register("kernel32.dll", "LoadLibraryW", load_library_w);
        self.register("kernel32.dll", "GetProcAddress", get_proc_address);
        self.register("kernel32.dll", "GetModuleHandleA", get_module_handle_a);
        self.register("kernel32.dll", "GetModuleHandleW", get_module_handle_w);
        self.register("kernel32.dll", "GetModuleFileNameA", get_module_filename_a);
        
        // Timing
        self.register("kernel32.dll", "GetTickCount", get_tick_count);
        self.register("kernel32.dll", "GetTickCount64", get_tick_count64);
        self.register("kernel32.dll", "QueryPerformanceCounter", query_performance_counter);
        self.register("kernel32.dll", "GetSystemTimeAsFileTime", get_system_time_as_file_time);
        
        // Process/Thread
        self.register("kernel32.dll", "GetCurrentProcessId", get_current_process_id);
        self.register("kernel32.dll", "GetCurrentThreadId", get_current_thread_id);
        self.register("kernel32.dll", "GetCurrentProcess", get_current_process);
        self.register("kernel32.dll", "GetCurrentThread", get_current_thread);
        
        // System info
        self.register("kernel32.dll", "GetSystemInfo", get_system_info);
        
        // Anti-debug
        self.register("kernel32.dll", "IsDebuggerPresent", is_debugger_present);
        self.register("kernel32.dll", "CheckRemoteDebuggerPresent", check_remote_debugger_present);
        
        // Debug output
        self.register("kernel32.dll", "OutputDebugStringA", output_debug_string_a);
        
        // Error handling
        self.register("kernel32.dll", "GetLastError", get_last_error);
        self.register("kernel32.dll", "SetLastError", set_last_error);
        
        // Handles
        self.register("kernel32.dll", "CloseHandle", close_handle);
        
        // Utility
        self.register("kernel32.dll", "Sleep", sleep);
        self.register("kernel32.dll", "ExitProcess", exit_process);
    }
    
    /// Register ntdll.dll APIs
    fn register_ntdll_apis(&mut self) {
        use super::ntdll::*;
        
        // System information
        self.register("ntdll.dll", "RtlGetVersion", rtl_get_version);
        self.register("ntdll.dll", "NtQuerySystemInformation", nt_query_system_information);
        
        // Process/Thread information (anti-debug)
        self.register("ntdll.dll", "NtQueryInformationProcess", nt_query_information_process);
        self.register("ntdll.dll", "NtSetInformationThread", nt_set_information_thread);
        
        // Memory management
        self.register("ntdll.dll", "NtAllocateVirtualMemory", nt_allocate_virtual_memory);
        self.register("ntdll.dll", "NtProtectVirtualMemory", nt_protect_virtual_memory);
        
        // Exception handling (SEH)
        self.register("ntdll.dll", "RtlUnwindEx", rtl_unwind_ex);
        self.register("ntdll.dll", "RtlVirtualUnwind", rtl_virtual_unwind);
        self.register("ntdll.dll", "RtlCaptureContext", rtl_capture_context);
        self.register("ntdll.dll", "RtlLookupFunctionEntry", rtl_lookup_function_entry);
        self.register("ntdll.dll", "RtlAddFunctionTable", rtl_add_function_table);
        
        // Handles
        self.register("ntdll.dll", "NtClose", nt_close);
    }
    
    /// Get API info by address
    pub fn get_api(&self, addr: u64) -> Option<&(String, String, ApiFn)> {
        self.apis.get(&addr)
    }
    
    /// Check if address is a hooked API
    pub fn is_api_hook(&self, addr: u64) -> bool {
        self.apis.contains_key(&addr)
    }
    
    /// Dispatch API call
    pub fn dispatch(&mut self, addr: u64, emu: &mut Unicorn<()>) -> Result<bool> {
        if let Some((dll, name, func)) = self.apis.get(&addr).cloned() {
            log::debug!("API call: {}!{} at 0x{:x}", dll, name, addr);
            func(emu, &mut self.workspace)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Get all registered APIs for IAT setup
    pub fn get_all_apis(&self) -> Vec<(u64, String, String)> {
        self.apis.iter()
            .map(|(addr, (dll, name, _))| (*addr, dll.clone(), name.clone()))
            .collect()
    }
    
    /// Find API by name (case-insensitive)
    pub fn find_api(&self, dll: &str, name: &str) -> Option<u64> {
        let dll_lower = dll.to_lowercase();
        let name_lower = name.to_lowercase();
        
        self.apis.iter()
            .find(|(_, (d, n, _))| {
                d.to_lowercase() == dll_lower && n.to_lowercase() == name_lower
            })
            .map(|(addr, _)| *addr)
    }
}
