//! Minimal Win64 import-call trap and API stubs.

use std::collections::BTreeMap;

use crate::{
    emu::{Emu, EmuError, FaultKind, RegisterX86, StopReason},
    pe,
};

const IMPORT_NAME_CAP: usize = 256;
const SET_CURRENT_DIRECTORY_W_UNIT_CAP: usize = 260;
const WINDOW_CLASS_NAME_BYTE_CAP: usize = 256;
const WNDCLASSEXA_SIZE: usize = 80;
const FAKE_MODULE_BASE_START: u64 = 0x0000_7fff_0000_0000;
const FAKE_MODULE_BASE_STEP: u64 = 0x0010_0000;
const PROC_STUB_BASE: u64 = 0x0000_7ffe_0000_0000;
const PROC_STUB_STRIDE: u64 = 16;
const PAGE_SIZE: u32 = 0x1000;

const HEAP_ARENA_BASE: u64 = 0x0000_000f_4000_0000;
const HEAP_ARENA_SIZE: u64 = 0x1000_0000;
const HEAP_ALIGNMENT: u64 = 16;
const HEAP_NO_SERIALIZE: u32 = 0x1;
const HEAP_ZERO_MEMORY: u32 = 0x8;

/// Emulated-environment policy for the default user UI language: en-US.
const EMULATED_USER_DEFAULT_UI_LANGID: u16 = 0x0409;

/// Deterministic ID for the current thread exposed by the emulated environment.
const EMULATED_CURRENT_THREAD_ID: u32 = 1;

/// Deterministic uptime in milliseconds exposed by `timeGetTime`.
const EMULATED_UPTIME_MS: u32 = 0;

/// First ID in the finite created-thread namespace. The `u64` cursor can also
/// represent one past `u32::MAX`, leaving `u32::MAX` available as a valid ID.
const CREATED_THREAD_ID_BASE: u64 = 2;
const CREATED_THREAD_ID_EXHAUSTED: u64 = u32::MAX as u64 + 1;

/// Host-independent unmanifested Windows 8 compatibility view returned by
/// `GetVersion`: major 6, minor 2, build 9200, with the platform bit clear.
const EMULATED_WINDOWS_VERSION: u32 = 0x23f0_0206;

/// Host-independent current directory exposed by each emulated environment.
const EMULATED_CURRENT_DIRECTORY: [u16; 3] = [0x43, 0x3a, 0x5c];

/// Host-independent executable path exposed by each emulated environment:
/// `C:\guest.exe`, stored without a trailing NUL.
const EMULATED_EXECUTABLE_PATH: [u16; 12] = [
    0x43, 0x3a, 0x5c, 0x67, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x65,
];

/// Opaque process-heap handle in the gap between the fixed PEB and heap arena.
/// The handle remains unmapped and distinct from the allocator backing.
const EMULATED_PROCESS_HEAP_HANDLE: u64 = 0x0000_000f_3000_0000;

/// Start of the finite opaque vectored-exception-handler token namespace. It
/// begins immediately after the fixed PEB mapping and ends at the process-heap
/// handle, which is the exclusive upper bound. Tokens remain unmapped.
const VECTORED_EXCEPTION_HANDLER_TOKEN_BASE: u64 = crate::emu::PEB_BASE + crate::emu::PEB_SIZE;
const VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE: u64 = 0x10;

/// Start of the registry-backed opaque kernel-handle namespace. These values
/// remain unmapped; `HEAP_ARENA_BASE` is the exclusive upper bound.
const KERNEL_HANDLE_BASE: u64 = 0x0000_000f_3000_1000;
const KERNEL_HANDLE_STRIDE: u64 = 0x10;

/// Opaque handle for the sole modeled shared system cursor. It occupies the
/// unmapped gap after the process-heap handle and before the kernel-handle
/// namespace.
const EMULATED_HAND_CURSOR_HANDLE: u64 = 0x0000_000f_3000_0010;

/// `IDC_HAND`, encoded by Win32's `MAKEINTRESOURCE` convention.
const PREDEFINED_HAND_CURSOR_ID: u64 = 32_649;

/// First and one-past-last values in the deterministic local class-atom
/// namespace. The `u32` cursor can represent exhaustion after allocating
/// `0xffff` without wrapping back to zero.
const WINDOW_CLASS_ATOM_BASE: u32 = 0xc000;
const WINDOW_CLASS_ATOM_EXHAUSTED: u32 = 0x1_0000;

/// Pre-Vista THREAD_ALL_ACCESS, including the legacy unnamed 0x4 access bit.
const LEGACY_THREAD_ALL_ACCESS: u32 = 0x001f_03ff;

/// RVA of the synthetic module's IMAGE_EXPORT_DIRECTORY.
pub const SYNTHETIC_EXPORT_DIR_RVA: u32 = 0x200;

/// Byte spacing between synthetic export call targets.
pub const SYNTHETIC_STUB_STRIDE: u32 = 16;

/// Seed kernel32 export names expanded by observation, not a completeness claim.
/// A real kernel32 provider will replace this later.
pub const KERNEL32_EXPORTS: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "GetProcessHeap",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "ExitProcess",
    "GetUserDefaultUILanguage",
    "GetCurrentThreadId",
    "GetCurrentDirectoryW",
    "SetCurrentDirectoryW",
    "GetModuleFileNameW",
    "OpenThread",
    "CreateThread",
    "GetVersion",
    "Sleep",
];

/// Seed ntdll export names observed during the bootstrap export walk; this is
/// not a completeness claim.
const NTDLL_EXPORTS: &[&str] = &[
    "RtlEnterCriticalSection",
    "RtlLeaveCriticalSection",
    "RtlInitializeCriticalSection",
    "RtlAddVectoredExceptionHandler",
    "NtQueryObject",
    "RtlAllocateHeap",
    "RtlReAllocateHeap",
    "RtlFreeHeap",
];

const USER32_EXPORTS: &[&str] = &["LoadCursorA", "RegisterClassExA"];

#[derive(Debug, Clone)]
pub struct SyntheticModule {
    pub base: u64,
    pub image: Vec<u8>,
    stub_region_rva: u32,
    stub_region_size: u32,
    exports: BTreeMap<String, u32>,
    stub_rva_to_name: BTreeMap<u32, String>,
}

impl SyntheticModule {
    fn build(base: u64, module_name: &str, exports: &[&str]) -> Self {
        let mut sorted_exports = exports.to_vec();
        sorted_exports.sort_unstable();

        let export_count = sorted_exports.len();
        let export_dir_rva = SYNTHETIC_EXPORT_DIR_RVA;
        let eat_rva = export_dir_rva + 40;
        let names_rva = eat_rva + export_count as u32 * 4;
        let ords_rva = names_rva + export_count as u32 * 4;
        let strings_rva = ords_rva + export_count as u32 * 2;

        let mut cursor = strings_rva;
        let module_name_rva = cursor;
        cursor += module_name.len() as u32 + 1;

        let mut name_rvas = Vec::with_capacity(export_count);
        for export in &sorted_exports {
            name_rvas.push(cursor);
            cursor += export.len() as u32 + 1;
        }

        let export_area_size = cursor - export_dir_rva;
        let stub_region_rva = align_up_u32(cursor, PAGE_SIZE);
        let stub_region_size = align_up_u32(export_count as u32 * SYNTHETIC_STUB_STRIDE, PAGE_SIZE);
        let image_len = stub_region_rva as usize;
        let size_of_image = stub_region_rva + stub_region_size;
        let mut image = vec![0u8; image_len];

        write_bytes(&mut image, 0, b"MZ");
        write_u32(&mut image, 0x3c, 0x80);

        let pe_offset = 0x80;
        write_bytes(&mut image, pe_offset, b"PE\0\0");
        let coff = pe_offset + 4;
        write_u16(&mut image, coff, 0x8664);
        write_u16(&mut image, coff + 2, 0);
        write_u16(&mut image, coff + 16, 0xf0);
        write_u16(&mut image, coff + 18, 0x2022);

        let opt = coff + 20;
        write_u16(&mut image, opt, 0x20b);
        write_u64(&mut image, opt + 24, base);
        write_u32(&mut image, opt + 56, size_of_image);
        write_u32(&mut image, opt + 108, 16);
        write_u32(&mut image, opt + 112, export_dir_rva);
        write_u32(&mut image, opt + 116, export_area_size);

        let export_dir = export_dir_rva as usize;
        write_u32(&mut image, export_dir + 12, module_name_rva);
        write_u32(&mut image, export_dir + 16, 1);
        write_u32(&mut image, export_dir + 20, export_count as u32);
        write_u32(&mut image, export_dir + 24, export_count as u32);
        write_u32(&mut image, export_dir + 28, eat_rva);
        write_u32(&mut image, export_dir + 32, names_rva);
        write_u32(&mut image, export_dir + 36, ords_rva);

        let mut export_map = BTreeMap::new();
        let mut stub_rva_to_name = BTreeMap::new();
        for ((index, export), name_rva) in sorted_exports.iter().enumerate().zip(name_rvas.iter()) {
            let stub_rva = stub_region_rva + index as u32 * SYNTHETIC_STUB_STRIDE;
            write_u32(&mut image, eat_rva as usize + index * 4, stub_rva);
            write_u32(&mut image, names_rva as usize + index * 4, *name_rva);
            write_u16(&mut image, ords_rva as usize + index * 2, index as u16);
            export_map.insert((*export).to_owned(), stub_rva);
            stub_rva_to_name.insert(stub_rva, (*export).to_owned());
        }

        write_ascii_z(&mut image, module_name_rva as usize, module_name);
        for (name, rva) in sorted_exports.iter().zip(name_rvas) {
            write_ascii_z(&mut image, rva as usize, name);
        }

        Self {
            base,
            image,
            stub_region_rva,
            stub_region_size,
            exports: export_map,
            stub_rva_to_name,
        }
    }

    fn map_into(&self, emu: &mut Emu) -> Result<(), EmuError> {
        emu.map_readonly(self.base, &self.image)?;

        if self.stub_region_size == 0 {
            return Ok(());
        }

        let stub_region_addr = self
            .base
            .checked_add(u64::from(self.stub_region_rva))
            .ok_or(EmuError::AddressRangeOverflow {
                base: self.base,
                size: u64::from(self.stub_region_rva),
            })?;
        let stub_region = vec![0u8; self.stub_region_size as usize];
        emu.map_readonly(stub_region_addr, &stub_region)
    }

    fn stub_name(&self, addr: u64) -> Option<&str> {
        let rva = addr.checked_sub(self.base)?;
        let rva = u32::try_from(rva).ok()?;
        let end = self
            .stub_region_rva
            .checked_add(self.exports.len() as u32 * SYNTHETIC_STUB_STRIDE)?;
        if !(self.stub_region_rva..end).contains(&rva) {
            return None;
        }
        if !(rva - self.stub_region_rva).is_multiple_of(SYNTHETIC_STUB_STRIDE) {
            return None;
        }
        self.stub_rva_to_name.get(&rva).map(String::as_str)
    }

    fn export_stub(&self, name: &str) -> Option<u64> {
        self.base.checked_add(u64::from(*self.exports.get(name)?))
    }
}

pub fn read_import_by_name(
    emu: &Emu,
    image_base: u64,
    image_size: u32,
    rva: u32,
) -> Option<String> {
    let rva_after_hint = u64::from(rva).checked_add(2)?;
    if rva_after_hint >= u64::from(image_size) {
        return None;
    }

    let max_len =
        usize::try_from((u64::from(image_size) - rva_after_hint).min(IMPORT_NAME_CAP as u64))
            .ok()?;
    if max_len == 0 {
        return None;
    }

    let name_address = image_base.checked_add(rva_after_hint)?;
    // Scan one byte at a time rather than reading the whole `max_len` window at
    // once: the image address range is not fully mapped (map_image leaves gaps
    // between sections), so a bulk read of a name that sits near a section's end
    // would cross into unmapped memory and fail, rejecting a valid import. A
    // byte-wise scan resolves the name as long as it and its NUL terminator lie
    // in mapped memory.
    let mut name_bytes = Vec::new();
    for offset in 0..max_len {
        let byte_address = name_address.checked_add(offset as u64)?;
        let byte = match emu.read_mem(byte_address, 1) {
            Ok(bytes) => bytes[0],
            // Ran into unmapped memory before a NUL terminator: not a valid,
            // fully-mapped import-by-name.
            Err(_) => return None,
        };
        if byte == 0 {
            if name_bytes.is_empty() {
                return None;
            }
            return String::from_utf8(name_bytes).ok();
        }
        if !(0x21..=0x7e).contains(&byte) {
            return None;
        }
        name_bytes.push(byte);
    }

    // No NUL terminator within the cap.
    None
}

fn align_up_u32(value: u32, alignment: u32) -> u32 {
    value.div_ceil(alignment) * alignment
}

fn write_bytes(image: &mut [u8], offset: usize, value: &[u8]) {
    let Some(end) = offset.checked_add(value.len()) else {
        return;
    };
    let Some(dst) = image.get_mut(offset..end) else {
        return;
    };
    dst.copy_from_slice(value);
}

fn write_u16(image: &mut [u8], offset: usize, value: u16) {
    write_bytes(image, offset, &value.to_le_bytes());
}

fn write_u32(image: &mut [u8], offset: usize, value: u32) {
    write_bytes(image, offset, &value.to_le_bytes());
}

fn write_u64(image: &mut [u8], offset: usize, value: u64) {
    write_bytes(image, offset, &value.to_le_bytes());
}

fn write_ascii_z(image: &mut [u8], offset: usize, value: &str) {
    let bytes = value.as_bytes();
    write_bytes(image, offset, bytes);
    if let Some(nul) = offset
        .checked_add(bytes.len())
        .and_then(|nul| image.get_mut(nul))
    {
        *nul = 0;
    }
}

fn utf16le_with_nul(units: &[u16]) -> Result<Vec<u8>, EmuError> {
    let byte_len = units
        .len()
        .checked_add(1)
        .and_then(|units| units.checked_mul(std::mem::size_of::<u16>()))
        .ok_or(EmuError::CodeTooLarge)?;
    let mut bytes = Vec::with_capacity(byte_len);
    for unit in units.iter().copied().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapAllocation {
    requested_size: u64,
    mapped_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelObject {
    Thread { thread_id: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelHandle {
    object: KernelObject,
    desired_access: u32,
    inheritable: bool,
}

/// Immutable record created by the bounded `CreateThread` model.
///
/// The record is runnable only in the sense that creation succeeded with
/// supported arguments. Midas does not schedule it, allocate its runtime
/// state, or assign lifecycle meaning to a later control transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnableUnscheduledThread {
    pub start_address: u64,
    pub parameter: u64,
    pub requested_stack_size: u64,
    pub creation_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VectoredExceptionHandlerRegistration {
    token: u64,
    handler: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WndClassExA {
    cb_size: u32,
    style: u32,
    window_procedure: u64,
    class_extra: i32,
    window_extra: i32,
    instance: u64,
    icon: u64,
    cursor: u64,
    background: u64,
    menu_name: u64,
    class_name: u64,
    icon_small: u64,
}

impl WndClassExA {
    fn matches_observed_shape(&self, image_base: u64) -> bool {
        self.style == 3
            && self.window_procedure != 0
            && self.class_extra == 0
            && self.window_extra == 0
            && self.instance == image_base
            && self.icon == 0
            && self.cursor == EMULATED_HAND_CURSOR_HANDLE
            && self.background == 6
            && self.menu_name == 0
            && self.icon_small == 0
    }
}

/// Environment-owned projection of the supported `WNDCLASSEXA` shape. Guest
/// pointers are replaced by owned or scalar values so later lookups cannot
/// observe guest-memory mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredWindowClassA {
    atom: u16,
    cb_size: u32,
    style: u32,
    window_procedure: u64,
    class_extra: i32,
    window_extra: i32,
    instance: u64,
    icon: u64,
    cursor: u64,
    background: u64,
    menu_name: Option<String>,
    class_name: String,
    icon_small: u64,
}

impl RegisteredWindowClassA {
    fn new(atom: u16, raw: WndClassExA, class_name: String) -> Self {
        debug_assert_eq!(raw.menu_name, 0);
        Self {
            atom,
            cb_size: raw.cb_size,
            style: raw.style,
            window_procedure: raw.window_procedure,
            class_extra: raw.class_extra,
            window_extra: raw.window_extra,
            instance: raw.instance,
            icon: raw.icon,
            cursor: raw.cursor,
            background: raw.background,
            menu_name: None,
            class_name,
            icon_small: raw.icon_small,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Win64Env {
    image_base: u64,
    process_heap: u64,
    current_thread_id: u32,
    current_directory: [u16; 3],
    executable_path: [u16; 12],
    next_vectored_exception_handler_token: u64,
    vectored_exception_handlers: Vec<VectoredExceptionHandlerRegistration>,
    next_kernel_handle: u64,
    kernel_handles: BTreeMap<u64, KernelHandle>,
    next_thread_id: u64,
    created_threads: BTreeMap<u32, RunnableUnscheduledThread>,
    heap_cursor: u64,
    heap_allocations: BTreeMap<u64, HeapAllocation>,
    modules: BTreeMap<String, u64>,
    next_base: u64,
    synthetic_modules: BTreeMap<String, SyntheticModule>,
    proc_stubs: BTreeMap<String, u64>,
    proc_stub_mapped_end: u64,
    next_window_class_atom: u32,
    window_classes_by_atom: BTreeMap<u16, RegisteredWindowClassA>,
    window_class_atoms_by_name: BTreeMap<(u64, String), u16>,
}

impl Win64Env {
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            process_heap: EMULATED_PROCESS_HEAP_HANDLE,
            current_thread_id: EMULATED_CURRENT_THREAD_ID,
            current_directory: EMULATED_CURRENT_DIRECTORY,
            executable_path: EMULATED_EXECUTABLE_PATH,
            next_vectored_exception_handler_token: VECTORED_EXCEPTION_HANDLER_TOKEN_BASE,
            vectored_exception_handlers: Vec::new(),
            next_kernel_handle: KERNEL_HANDLE_BASE,
            kernel_handles: BTreeMap::new(),
            next_thread_id: CREATED_THREAD_ID_BASE,
            created_threads: BTreeMap::new(),
            heap_cursor: HEAP_ARENA_BASE,
            heap_allocations: BTreeMap::new(),
            modules: BTreeMap::new(),
            next_base: FAKE_MODULE_BASE_START,
            synthetic_modules: BTreeMap::new(),
            proc_stubs: BTreeMap::new(),
            proc_stub_mapped_end: PROC_STUB_BASE,
            next_window_class_atom: WINDOW_CLASS_ATOM_BASE,
            window_classes_by_atom: BTreeMap::new(),
            window_class_atoms_by_name: BTreeMap::new(),
        }
    }

    /// Iterate over immutable created-thread records in ascending thread-ID
    /// order. Observing these records does not schedule or execute them.
    pub fn runnable_unscheduled_threads(
        &self,
    ) -> impl Iterator<Item = (u32, &RunnableUnscheduledThread)> {
        self.created_threads
            .iter()
            .map(|(&thread_id, thread)| (thread_id, thread))
    }

    /// Resolve a synthetic-module or dynamic procedure stub address to the API
    /// name that the trap dispatcher would use.
    ///
    /// This is a read-only diagnostic projection. It does not dispatch the API
    /// or classify arbitrary image addresses and unbound import-name RVAs.
    pub fn callable_stub_name_at(&self, address: u64) -> Option<String> {
        self.stub_export_at(address)
            .or_else(|| self.proc_stub_at(address))
            .map(|(name, _rva)| name)
    }

    fn add_vectored_exception_handler(&mut self, first: u32, handler: u64) -> u64 {
        // Bounded policy: registration only records the opaque callback value
        // and insertion order. It does not inspect callback memory or model
        // dispatch, removal, lifetime, or synchronization semantics.
        let token = self.next_vectored_exception_handler_token;
        let Some(next_token) = token.checked_add(VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE) else {
            return 0;
        };
        if !(VECTORED_EXCEPTION_HANDLER_TOKEN_BASE..EMULATED_PROCESS_HEAP_HANDLE).contains(&token)
            || !token.is_multiple_of(VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE)
            || next_token > EMULATED_PROCESS_HEAP_HANDLE
            || self
                .vectored_exception_handlers
                .iter()
                .any(|registration| registration.token == token)
        {
            return 0;
        }

        let registration = VectoredExceptionHandlerRegistration { token, handler };
        if first == 0 {
            self.vectored_exception_handlers.push(registration);
        } else {
            self.vectored_exception_handlers.insert(0, registration);
        }
        self.next_vectored_exception_handler_token = next_token;
        token
    }

    fn kernel_handle_candidate(&self) -> Option<(u64, u64)> {
        let handle = self.next_kernel_handle;
        let next_handle = handle.checked_add(KERNEL_HANDLE_STRIDE)?;
        if !(KERNEL_HANDLE_BASE..HEAP_ARENA_BASE).contains(&handle)
            || next_handle > HEAP_ARENA_BASE
            || !handle.is_multiple_of(KERNEL_HANDLE_STRIDE)
            || self.kernel_handles.contains_key(&handle)
        {
            return None;
        }
        Some((handle, next_handle))
    }

    fn thread_id_candidate(&self) -> Option<(u32, u64)> {
        let cursor = self.next_thread_id;
        if !(CREATED_THREAD_ID_BASE..CREATED_THREAD_ID_EXHAUSTED).contains(&cursor) {
            return None;
        }
        let thread_id = u32::try_from(cursor).ok()?;
        let next_thread_id = cursor.checked_add(1)?;
        if next_thread_id > CREATED_THREAD_ID_EXHAUSTED
            || thread_id == self.current_thread_id
            || self.created_threads.contains_key(&thread_id)
        {
            return None;
        }
        Some((thread_id, next_thread_id))
    }

    fn window_class_atom_candidate(&self) -> Option<(u16, u32)> {
        let cursor = self.next_window_class_atom;
        if !(WINDOW_CLASS_ATOM_BASE..WINDOW_CLASS_ATOM_EXHAUSTED).contains(&cursor) {
            return None;
        }
        let atom = u16::try_from(cursor).ok()?;
        let next_atom = cursor.checked_add(1)?;
        if next_atom > WINDOW_CLASS_ATOM_EXHAUSTED
            || self.window_classes_by_atom.contains_key(&atom)
        {
            return None;
        }
        Some((atom, next_atom))
    }

    fn insert_window_class(
        &mut self,
        key: (u64, String),
        atom: u16,
        next_atom: u32,
        registration: RegisteredWindowClassA,
    ) {
        debug_assert_eq!(registration.atom, atom);
        let previous_class = self.window_classes_by_atom.insert(atom, registration);
        let previous_atom = self.window_class_atoms_by_name.insert(key, atom);
        debug_assert!(previous_class.is_none());
        debug_assert!(previous_atom.is_none());
        self.next_window_class_atom = next_atom;
    }

    fn insert_kernel_handle(&mut self, handle: u64, next_handle: u64, kernel_handle: KernelHandle) {
        let previous = self.kernel_handles.insert(handle, kernel_handle);
        debug_assert!(previous.is_none());
        self.next_kernel_handle = next_handle;
    }

    fn open_thread(&mut self, desired_access: u32, inheritable: bool, thread_id: u32) -> u64 {
        // Bounded support policy: accept any subset of the legacy all-access
        // mask. This is not complete ACL, token, or security semantics.
        let thread_exists =
            thread_id == self.current_thread_id || self.created_threads.contains_key(&thread_id);
        if desired_access & !LEGACY_THREAD_ALL_ACCESS != 0 || !thread_exists {
            return 0;
        }

        let Some((handle, next_handle)) = self.kernel_handle_candidate() else {
            return 0;
        };

        self.insert_kernel_handle(
            handle,
            next_handle,
            KernelHandle {
                object: KernelObject::Thread { thread_id },
                desired_access,
                inheritable,
            },
        );
        handle
    }

    #[allow(clippy::too_many_arguments)]
    fn create_thread(
        &mut self,
        emu: &mut Emu,
        thread_attributes: u64,
        requested_stack_size: u64,
        start_address: u64,
        parameter: u64,
        creation_flags: u32,
        thread_id_output: u64,
    ) -> Result<u64, EmuError> {
        // Bounded policy: record a runnable-but-unscheduled thread, but do not
        // allocate a guest stack/TEB or inspect/execute either pointer.
        // Lifecycle, signaling, wait/close, ACL/token, and last-error behavior
        // are likewise outside this slice.
        if thread_attributes != 0 || requested_stack_size != 0 || creation_flags != 0 {
            return Ok(0);
        }

        let Some((thread_id, next_thread_id)) = self.thread_id_candidate() else {
            return Ok(0);
        };
        let Some((handle, next_handle)) = self.kernel_handle_candidate() else {
            return Ok(0);
        };

        // Output validation and the DWORD write precede every state mutation.
        // `write_mem` preflights the full range, so an error cannot partially
        // modify the guest output or consume either allocator cursor.
        if thread_id_output != 0 {
            emu.write_mem(thread_id_output, &thread_id.to_le_bytes())?;
        }

        let previous = self.created_threads.insert(
            thread_id,
            RunnableUnscheduledThread {
                start_address,
                parameter,
                requested_stack_size,
                creation_flags,
            },
        );
        debug_assert!(previous.is_none());
        self.next_thread_id = next_thread_id;
        self.insert_kernel_handle(
            handle,
            next_handle,
            KernelHandle {
                object: KernelObject::Thread { thread_id },
                // This is the complete bounded Midas rights universe, not the
                // version-dependent Windows THREAD_ALL_ACCESS definition.
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            },
        );
        Ok(handle)
    }

    fn allocate_heap(
        &mut self,
        emu: &mut Emu,
        heap_handle: u64,
        flags: u32,
        requested_size: u64,
    ) -> Result<u64, EmuError> {
        if heap_handle != self.process_heap || flags & !(HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY) != 0
        {
            return Ok(0);
        }

        let page_size = u64::from(PAGE_SIZE);
        // Environment policy: a zero-byte request consumes a fresh minimum
        // block so success remains distinguishable from NULL failure.
        let effective_size = requested_size.max(1);
        let Some(mapped_size) = effective_size
            .checked_add(page_size - 1)
            .map(|size| size & !(page_size - 1))
        else {
            return Ok(0);
        };
        let allocation = HeapAllocation {
            requested_size,
            mapped_size,
        };
        if allocation.requested_size > allocation.mapped_size {
            return Ok(0);
        }

        let allocation_base = self.heap_cursor;
        let Some(next_cursor) = allocation_base.checked_add(allocation.mapped_size) else {
            return Ok(0);
        };
        let arena_end = HEAP_ARENA_BASE + HEAP_ARENA_SIZE;
        if !allocation_base.is_multiple_of(HEAP_ALIGNMENT) || next_cursor > arena_end {
            return Ok(0);
        }

        emu.map_zeroed_rw(allocation_base, allocation.mapped_size)?;
        self.heap_allocations.insert(allocation_base, allocation);
        self.heap_cursor = next_cursor;
        Ok(allocation_base)
    }

    fn module_base(&mut self, name: &str) -> u64 {
        let key = name.to_ascii_lowercase();
        if let Some(base) = self.modules.get(&key) {
            return *base;
        }

        let base = self.next_base;
        self.next_base = self.next_base.saturating_add(FAKE_MODULE_BASE_STEP);
        self.modules.insert(key, base);
        base
    }

    fn loaded_base(&self, name: &str) -> Option<u64> {
        self.modules
            .get(&normalize_module_name(name).to_ascii_lowercase())
            .copied()
    }

    fn ensure_module(
        &mut self,
        emu: &mut Emu,
        name: &str,
        exports: &[&str],
    ) -> Result<u64, EmuError> {
        let key = name.to_ascii_lowercase();
        if let Some(module) = self.synthetic_modules.get(&key) {
            return Ok(module.base);
        }

        let base = self.module_base(name);
        let module = SyntheticModule::build(base, name, exports);
        module.map_into(emu)?;
        self.synthetic_modules.insert(key, module);
        Ok(base)
    }

    fn ensure_kernel32(&mut self, emu: &mut Emu) -> Result<u64, EmuError> {
        self.ensure_module(emu, "kernel32.dll", KERNEL32_EXPORTS)
    }

    fn ensure_loaded_module(&mut self, emu: &mut Emu, name: &str) -> Result<u64, EmuError> {
        let normalized = normalize_module_name(name);
        let module_name = normalized
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(normalized.as_str());
        let exports: &[&str] = if module_name.eq_ignore_ascii_case("kernel32.dll") {
            KERNEL32_EXPORTS
        } else if module_name.eq_ignore_ascii_case("ntdll.dll") {
            NTDLL_EXPORTS
        } else if module_name.eq_ignore_ascii_case("user32.dll") {
            USER32_EXPORTS
        } else {
            &[]
        };
        self.ensure_module(emu, &normalized, exports)
    }

    fn export_stub_by_base(&self, module_base: u64, name: &str) -> Option<u64> {
        self.synthetic_modules
            .values()
            .find(|module| module.base == module_base)
            .and_then(|module| module.export_stub(name))
    }

    fn is_synthetic_module_base(&self, module_base: u64) -> bool {
        self.synthetic_modules
            .values()
            .any(|module| module.base == module_base)
    }

    fn resolve_proc(
        &mut self,
        emu: &mut Emu,
        module_base: u64,
        name: &str,
    ) -> Result<u64, EmuError> {
        // GetProcAddress resolves only against a loaded (registered synthetic)
        // module. A bogus/zero handle (e.g. from a failed LoadLibraryA) fails with
        // NULL rather than fabricating an export, matching Windows semantics.
        if !self.is_synthetic_module_base(module_base) {
            return Ok(0);
        }

        if let Some(addr) = self.export_stub_by_base(module_base, name) {
            return Ok(addr);
        }

        // The dynamic arena is keyed by name only (not by (module, name)): our trap
        // dispatches purely by name, so two modules resolving the same name share a
        // stub. This differs from real Windows (distinct addresses per module) but is
        // exact for by-name API emulation.
        if let Some(addr) = self.proc_stubs.get(name) {
            return Ok(*addr);
        }

        let index =
            u64::try_from(self.proc_stubs.len()).map_err(|_| EmuError::AddressRangeOverflow {
                base: PROC_STUB_BASE,
                size: u64::MAX,
            })?;
        let offset = index
            .checked_mul(PROC_STUB_STRIDE)
            .ok_or(EmuError::AddressRangeOverflow {
                base: PROC_STUB_BASE,
                size: index,
            })?;
        let addr = PROC_STUB_BASE
            .checked_add(offset)
            .ok_or(EmuError::AddressRangeOverflow {
                base: PROC_STUB_BASE,
                size: offset,
            })?;
        let stub_end =
            addr.checked_add(PROC_STUB_STRIDE)
                .ok_or(EmuError::AddressRangeOverflow {
                    base: addr,
                    size: PROC_STUB_STRIDE,
                })?;

        while self.proc_stub_mapped_end < stub_end {
            emu.map_readonly(self.proc_stub_mapped_end, &[0u8; PAGE_SIZE as usize])?;
            self.proc_stub_mapped_end = self
                .proc_stub_mapped_end
                .checked_add(u64::from(PAGE_SIZE))
                .ok_or(EmuError::AddressRangeOverflow {
                    base: self.proc_stub_mapped_end,
                    size: u64::from(PAGE_SIZE),
                })?;
        }

        self.proc_stubs.insert(name.to_owned(), addr);
        Ok(addr)
    }

    /// Reverse-map a faulting address to `(export name, module RVA)` across every
    /// registered synthetic module. The RVA is `addr - module.base`, which
    /// `stub_name` already proved fits in a `u32`, so it is returned directly
    /// rather than recomputed by the caller.
    fn stub_export_at(&self, addr: u64) -> Option<(String, u32)> {
        for module in self.synthetic_modules.values() {
            if let Some(name) = module.stub_name(addr) {
                let rva = (addr - module.base) as u32;
                return Some((name.to_owned(), rva));
            }
        }
        None
    }

    fn proc_stub_at(&self, addr: u64) -> Option<(String, u32)> {
        let rva = addr.checked_sub(PROC_STUB_BASE)?;
        let rva = u32::try_from(rva).ok()?;
        self.proc_stubs
            .iter()
            .find(|(_, stub_addr)| **stub_addr == addr)
            .map(|(name, _)| (name.clone(), rva))
    }
}

impl Default for Win64Env {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiOutcome {
    Handled { name: String, ret: u64 },
    HandledVoid { name: String },
    Unhandled { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RawUtf16Read {
    Terminated(Vec<u16>),
    CapExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RawAnsiClassNameRead {
    Terminated(Vec<u8>),
    CapExhausted,
    NonPrintable,
}

pub fn dispatch(env: &mut Win64Env, emu: &mut Emu, name: &str) -> Result<ApiOutcome, EmuError> {
    match name {
        "GetModuleHandleA" => {
            let module_name = read_arg_ascii_z(emu, RegisterX86::RCX)?;
            let normalized_module_name = normalize_module_name(&module_name);
            let base = if module_name.is_empty() {
                env.image_base
            } else if normalized_module_name.eq_ignore_ascii_case("kernel32.dll") {
                env.ensure_kernel32(emu)?
            } else {
                env.loaded_base(&normalized_module_name).unwrap_or(0)
            };
            emu.write_reg(RegisterX86::RAX, base)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: base,
            })
        }
        "LoadLibraryA" => {
            let module_name = read_arg_ascii_z(emu, RegisterX86::RCX)?;
            // Unlike GetModuleHandle(NULL) (which yields the process image base),
            // LoadLibrary of a NULL/empty name is a failed load: return 0. The
            // guest passes an ASCII DLL name; `read_arg_ascii_z` maps both a NULL
            // pointer and a pointer to "" to the empty string, both handled here.
            let base = if module_name.is_empty() {
                0
            } else {
                env.ensure_loaded_module(emu, &module_name)?
            };
            emu.write_reg(RegisterX86::RAX, base)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: base,
            })
        }
        "GetProcAddress" => {
            let module_base = emu.read_reg(RegisterX86::RCX)?;
            let name_ptr = emu.read_reg(RegisterX86::RDX)?;
            let ret = if name_ptr < 0x10000 {
                // MAKEINTRESOURCEA ordinal lookup; observed calls are name-based.
                0
            } else {
                let proc_name = read_ascii_z_at(emu, name_ptr)?;
                if proc_name.is_empty() {
                    0
                } else {
                    env.resolve_proc(emu, module_base, &proc_name)?
                }
            };
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetProcessHeap" => {
            let ret = env.process_heap;
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetCurrentThreadId" => {
            let ret = u64::from(env.current_thread_id);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetVersion" => {
            // DWORD is a 32-bit ABI value; explicitly zero-extend it into RAX.
            let ret = u64::from(EMULATED_WINDOWS_VERSION);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "timeGetTime" => {
            // Validate and consume the return frame before changing RAX so a
            // bad frame leaves every register and the environment untouched.
            api_return(emu)?;
            let ret = u64::from(EMULATED_UPTIME_MS);
            emu.write_reg(RegisterX86::RAX, ret)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "Sleep" => {
            // DWORD consumes only ECX. Zero and INFINITE are unsupported and
            // return before the return stack is read or any state is mutated.
            let interval = emu.read_reg(RegisterX86::RCX)? as u32;
            if interval == 0 || interval == u32::MAX {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // Deterministic wait elision: every finite positive interval
            // completes immediately. Sleep is VOID, so preserve RAX, all
            // incidental registers, and flags as an explicit Midas policy,
            // rather than as a Windows ABI guarantee.
            api_return(emu)?;
            Ok(ApiOutcome::HandledVoid {
                name: name.to_owned(),
            })
        }
        "LoadCursorA" => {
            let instance = emu.read_reg(RegisterX86::RCX)?;
            let cursor_name = emu.read_reg(RegisterX86::RDX)?;
            if instance != 0 || cursor_name != PREDEFINED_HAND_CURSOR_ID {
                // Module resources, string names, and other predefined cursors
                // can be valid Windows inputs but are not modeled. Do not
                // dereference a possible name pointer or consume a return frame.
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // Validate and consume the return frame before changing RAX so an
            // invalid frame leaves every register and environment field intact.
            api_return(emu)?;
            emu.write_reg(RegisterX86::RAX, EMULATED_HAND_CURSOR_HANDLE)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: EMULATED_HAND_CURSOR_HANDLE,
            })
        }
        "RegisterClassExA" => {
            let class_description = emu.read_reg(RegisterX86::RCX)?;
            let cb_size = read_u32_at(emu, class_description)?;

            // The size field is independently readable and sufficient to
            // reject the wrong structure form. Do not require the remaining
            // 76 bytes to be mapped for this known failure.
            if cb_size != WNDCLASSEXA_SIZE as u32 {
                return handled_scalar_api_return(emu, name, 0);
            }
            let raw = read_wnd_class_ex_a(emu, class_description)?;
            debug_assert_eq!(raw.cb_size, cb_size);

            // These required pointer fields are known registration failures,
            // distinct from valid Windows shapes that remain unmodeled.
            if raw.window_procedure == 0 || raw.instance == 0 {
                return handled_scalar_api_return(emu, name, 0);
            }

            // Any otherwise valid Windows class shape outside the one observed
            // on the formal sample remains unmodeled. In particular, do not
            // inspect a possible class-name pointer or return frame after this
            // classifier rejects the scalar fields.
            if !raw.matches_observed_shape(env.image_base) {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            if raw.class_name == 0 {
                return handled_scalar_api_return(emu, name, 0);
            }
            if raw.class_name < 0x1_0000 {
                // A low-word class atom is valid Win32 input, but registering
                // by atom is outside this bounded ANSI-string model.
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let class_name_bytes =
                match read_raw_ansi_class_name(emu, raw.class_name, WINDOW_CLASS_NAME_BYTE_CAP)? {
                    RawAnsiClassNameRead::Terminated(bytes) if !bytes.is_empty() => bytes,
                    RawAnsiClassNameRead::Terminated(_) | RawAnsiClassNameRead::CapExhausted => {
                        return handled_scalar_api_return(emu, name, 0);
                    }
                    RawAnsiClassNameRead::NonPrintable => {
                        return Ok(ApiOutcome::Unhandled {
                            name: name.to_owned(),
                        });
                    }
                };
            let class_name = class_name_bytes
                .into_iter()
                .map(char::from)
                .collect::<String>();
            let class_key = (raw.instance, class_name.to_ascii_lowercase());

            // Duplicate names, exhausted atoms, and atom collisions are
            // modeled registration failures. Selection is read-only; all guest
            // reads and the return-frame transition happen before insertion or
            // RAX mutation.
            let pending_registration = if env.window_class_atoms_by_name.contains_key(&class_key) {
                None
            } else {
                env.window_class_atom_candidate().map(|(atom, next_atom)| {
                    let registration = RegisteredWindowClassA::new(atom, raw, class_name);
                    (class_key, atom, next_atom, registration)
                })
            };
            let ret = pending_registration
                .as_ref()
                .map_or(0, |(_, atom, _, _)| u64::from(*atom));

            api_return(emu)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            if let Some((key, atom, next_atom, registration)) = pending_registration {
                env.insert_window_class(key, atom, next_atom, registration);
            }
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetCurrentDirectoryW" => {
            // DWORD capacity consumes only ECX; the LPWSTR uses the full RDX.
            let capacity = emu.read_reg(RegisterX86::RCX)? as u32;
            let buffer = emu.read_reg(RegisterX86::RDX)?;
            let path_len =
                u32::try_from(env.current_directory.len()).map_err(|_| EmuError::CodeTooLarge)?;
            let required = path_len.checked_add(1).ok_or(EmuError::CodeTooLarge)?;

            let result = if capacity < required {
                // Midas policy: Windows does not document undersized buffer
                // contents, so do not read or write the buffer in this case.
                required
            } else {
                let bytes = utf16le_with_nul(&env.current_directory)?;
                emu.write_mem(buffer, &bytes)?;
                path_len
            };

            let ret = u64::from(result);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "SetCurrentDirectoryW" => {
            let path = emu.read_reg(RegisterX86::RCX)?;
            // Bounded policy scans at most the first 260 UTF-16 units,
            // including any terminator. Read raw units so the selector can be
            // matched without decoding or consulting host filesystem state.
            let input = read_raw_utf16_z(emu, path, SET_CURRENT_DIRECTORY_W_UNIT_CAP)?;
            let accepted = match input {
                RawUtf16Read::Terminated(units) => {
                    matches!(units.as_slice(), [0x43, 0x3a] | [0x63, 0x3a])
                }
                RawUtf16Read::CapExhausted => false,
            };
            if accepted {
                // C: is drive-relative on Windows. The only modeled C-drive
                // directory is C:\, so canonicalize the observed selector to it.
                env.current_directory = EMULATED_CURRENT_DIRECTORY;
            }

            // BOOL is a 32-bit ABI value; explicitly zero-extend it into RAX.
            let ret = u64::from(accepted);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetModuleFileNameW" => {
            // HMODULE and LPWSTR use their full register widths; nSize consumes
            // only R8D and counts UTF-16 code units rather than bytes.
            let module = emu.read_reg(RegisterX86::RCX)?;
            let buffer = emu.read_reg(RegisterX86::RDX)?;
            let capacity = emu.read_reg(RegisterX86::R8)? as u32;
            let path_len =
                u32::try_from(env.executable_path.len()).map_err(|_| EmuError::CodeTooLarge)?;

            let result = if module != 0 || capacity == 0 {
                // Bounded support policy: only the NULL module (the process
                // executable) is modeled. A zero capacity is not a size query.
                0
            } else {
                let copied_units = if capacity > path_len {
                    path_len
                } else {
                    capacity - 1
                };
                let copied_units =
                    usize::try_from(copied_units).map_err(|_| EmuError::CodeTooLarge)?;
                let bytes = utf16le_with_nul(&env.executable_path[..copied_units])?;
                emu.write_mem(buffer, &bytes)?;

                if capacity > path_len {
                    path_len
                } else {
                    capacity
                }
            };

            let ret = u64::from(result);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "CreateThread" => {
            // Pointer/SIZE_T arguments retain their full widths. Stack arg 5
            // is a DWORD read from the low half of its eight-byte ABI slot;
            // stack arg 6 remains a full pointer.
            let thread_attributes = emu.read_reg(RegisterX86::RCX)?;
            let requested_stack_size = emu.read_reg(RegisterX86::RDX)?;
            let start_address = emu.read_reg(RegisterX86::R8)?;
            let parameter = emu.read_reg(RegisterX86::R9)?;
            let rsp = emu.read_reg(RegisterX86::RSP)?;
            let creation_flags_address = checked_stack_argument_address(rsp, 0x28, 4)?;
            let thread_id_output_address = checked_stack_argument_address(rsp, 0x30, 8)?;
            let creation_flags = read_u32_at(emu, creation_flags_address)?;
            let thread_id_output = read_u64_at(emu, thread_id_output_address)?;

            let ret = env.create_thread(
                emu,
                thread_attributes,
                requested_stack_size,
                start_address,
                parameter,
                creation_flags,
                thread_id_output,
            )?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "OpenThread" => {
            // DWORD/BOOL arguments consume only the low 32 bits on Win64.
            let desired_access = emu.read_reg(RegisterX86::RCX)? as u32;
            let inheritable = (emu.read_reg(RegisterX86::RDX)? as u32) != 0;
            let thread_id = emu.read_reg(RegisterX86::R8)? as u32;
            let ret = env.open_thread(desired_access, inheritable, thread_id);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "RtlAddVectoredExceptionHandler" => {
            // First is ULONG and consumes only ECX. Handler is a pointer and
            // retains the full RDX value, including NULL or an unmapped value.
            let first = emu.read_reg(RegisterX86::RCX)? as u32;
            let handler = emu.read_reg(RegisterX86::RDX)?;
            let ret = env.add_vectored_exception_handler(first, handler);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "RtlAllocateHeap" => {
            let heap_handle = emu.read_reg(RegisterX86::RCX)?;
            // Flags is ULONG, so the x64 ABI consumes only EDX.
            let flags = emu.read_reg(RegisterX86::RDX)? as u32;
            let requested_size = emu.read_reg(RegisterX86::R8)?;
            let ret = env.allocate_heap(emu, heap_handle, flags, requested_size)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetUserDefaultUILanguage" => {
            let ret = u64::from(EMULATED_USER_DEFAULT_UI_LANGID);
            emu.write_reg(RegisterX86::RAX, ret)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "RtlInitializeCriticalSection" => {
            let address = emu.read_reg(RegisterX86::RCX)?;
            // This is the minimal state currently exercised by the loader; a
            // complete Windows debug-list model is intentionally out of scope.
            let mut critical_section = [0u8; 40];
            critical_section[8..12].copy_from_slice(&(-1i32).to_le_bytes());
            emu.write_mem(address, &critical_section)?;
            emu.write_reg(RegisterX86::RAX, 0)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 0,
            })
        }
        _ => Ok(ApiOutcome::Unhandled {
            name: name.to_owned(),
        }),
    }
}

fn checked_stack_argument_address(rsp: u64, offset: u64, size: u64) -> Result<u64, EmuError> {
    debug_assert!(size > 0);
    let address = rsp
        .checked_add(offset)
        .ok_or(EmuError::AddressRangeOverflow {
            base: rsp,
            size: offset,
        })?;
    address
        .checked_add(size - 1)
        .ok_or(EmuError::AddressRangeOverflow {
            base: address,
            size,
        })?;
    Ok(address)
}

fn read_u32_at(emu: &Emu, address: u64) -> Result<u32, EmuError> {
    let bytes = emu.read_mem(address, 4)?;
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes);
    Ok(u32::from_le_bytes(value))
}

fn read_u64_at(emu: &Emu, address: u64) -> Result<u64, EmuError> {
    let bytes = emu.read_mem(address, 8)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

fn read_wnd_class_ex_a(emu: &Emu, address: u64) -> Result<WndClassExA, EmuError> {
    let bytes = emu.read_mem(address, WNDCLASSEXA_SIZE)?;
    Ok(WndClassExA {
        cb_size: u32_from_bytes(&bytes, 0),
        style: u32_from_bytes(&bytes, 4),
        window_procedure: u64_from_bytes(&bytes, 8),
        class_extra: i32_from_bytes(&bytes, 16),
        window_extra: i32_from_bytes(&bytes, 20),
        instance: u64_from_bytes(&bytes, 24),
        icon: u64_from_bytes(&bytes, 32),
        cursor: u64_from_bytes(&bytes, 40),
        background: u64_from_bytes(&bytes, 48),
        menu_name: u64_from_bytes(&bytes, 56),
        class_name: u64_from_bytes(&bytes, 64),
        icon_small: u64_from_bytes(&bytes, 72),
    })
}

fn u32_from_bytes(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn i32_from_bytes(bytes: &[u8], offset: usize) -> i32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    i32::from_le_bytes(value)
}

fn u64_from_bytes(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn read_raw_ansi_class_name(
    emu: &Emu,
    address: u64,
    byte_cap: usize,
) -> Result<RawAnsiClassNameRead, EmuError> {
    let mut bytes = Vec::with_capacity(byte_cap);
    for offset in 0..byte_cap {
        let offset = u64::try_from(offset).map_err(|_| EmuError::CodeTooLarge)?;
        let byte_address = address
            .checked_add(offset)
            .ok_or(EmuError::AddressRangeOverflow {
                base: address,
                size: offset,
            })?;
        let byte = emu.read_mem(byte_address, 1)?[0];
        if byte == 0 {
            return Ok(RawAnsiClassNameRead::Terminated(bytes));
        }
        if !(0x20..=0x7e).contains(&byte) {
            return Ok(RawAnsiClassNameRead::NonPrintable);
        }
        bytes.push(byte);
    }
    Ok(RawAnsiClassNameRead::CapExhausted)
}

fn read_arg_ascii_z(emu: &Emu, reg: RegisterX86) -> Result<String, EmuError> {
    let address = emu.read_reg(reg)?;
    read_ascii_z_at(emu, address)
}

fn read_raw_utf16_z(emu: &Emu, address: u64, unit_cap: usize) -> Result<RawUtf16Read, EmuError> {
    let mut units = Vec::with_capacity(unit_cap);
    for index in 0..unit_cap {
        let index = u64::try_from(index).map_err(|_| EmuError::CodeTooLarge)?;
        let unit_offset = index.checked_mul(2).ok_or(EmuError::AddressRangeOverflow {
            base: address,
            size: u64::MAX,
        })?;
        let read_size = unit_offset
            .checked_add(2)
            .ok_or(EmuError::AddressRangeOverflow {
                base: address,
                size: u64::MAX,
            })?;
        let unit_address =
            address
                .checked_add(unit_offset)
                .ok_or(EmuError::AddressRangeOverflow {
                    base: address,
                    size: read_size,
                })?;
        unit_address
            .checked_add(1)
            .ok_or(EmuError::AddressRangeOverflow {
                base: address,
                size: read_size,
            })?;

        let bytes = emu.read_mem(unit_address, 2)?;
        let unit = u16::from_le_bytes([bytes[0], bytes[1]]);
        if unit == 0 {
            return Ok(RawUtf16Read::Terminated(units));
        }
        units.push(unit);
    }
    Ok(RawUtf16Read::CapExhausted)
}

fn normalize_module_name(name: &str) -> String {
    let component_start = name.rfind(['/', '\\']).map_or(0, |index| index + 1);
    let component = &name[component_start..];
    if !component.is_empty() && !component.contains('.') {
        format!("{name}.dll")
    } else {
        name.to_owned()
    }
}

fn read_ascii_z_at(emu: &Emu, address: u64) -> Result<String, EmuError> {
    if address == 0 {
        return Ok(String::new());
    }

    let mut value = String::new();
    for offset in 0..IMPORT_NAME_CAP {
        let byte_address =
            address
                .checked_add(offset as u64)
                .ok_or(EmuError::AddressRangeOverflow {
                    base: address,
                    size: offset as u64,
                })?;
        let byte = emu.read_mem(byte_address, 1)?[0];
        if byte == 0 {
            break;
        }
        if (0x20..=0x7e).contains(&byte) {
            value.push(char::from(byte));
        }
    }
    Ok(value)
}

fn handled_scalar_api_return(emu: &mut Emu, name: &str, ret: u64) -> Result<ApiOutcome, EmuError> {
    api_return(emu)?;
    emu.write_reg(RegisterX86::RAX, ret)?;
    Ok(ApiOutcome::Handled {
        name: name.to_owned(),
        ret,
    })
}

fn api_return(emu: &mut Emu) -> Result<(), EmuError> {
    let rsp = emu.read_reg(RegisterX86::RSP)?;
    let bytes = emu.read_mem(rsp, 8)?;
    let mut ret_bytes = [0u8; 8];
    ret_bytes.copy_from_slice(&bytes);
    let ret = u64::from_le_bytes(ret_bytes);
    let new_rsp = rsp
        .checked_add(8)
        .ok_or(EmuError::AddressRangeOverflow { base: rsp, size: 8 })?;
    emu.write_reg(RegisterX86::RIP, ret)?;
    emu.write_reg(RegisterX86::RSP, new_rsp)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapStop {
    UnhandledApi { name: String, rva: u32 },
    UnexpectedFault { address: u64 },
    InstructionCap,
    NullControlTransfer,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapRun {
    pub handled: Vec<String>,
    pub stop: TrapStop,
}

pub fn run_with_import_trap(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &pe::PeImage,
    begin: u64,
    per_run_cap: u64,
    max_calls: usize,
) -> Result<TrapRun, EmuError> {
    let mut handled = Vec::new();
    let mut rip = begin;

    loop {
        let report = emu.resume(rip, per_run_cap)?;
        match report.stop_reason {
            StopReason::MemoryFault(fault)
                if matches!(fault.kind, FaultKind::FetchUnmapped | FaultKind::FetchProt) =>
            {
                if let Some((name, rva)) = env
                    .stub_export_at(fault.address)
                    .or_else(|| env.proc_stub_at(fault.address))
                {
                    if handled.len() >= max_calls {
                        return Ok(TrapRun {
                            handled,
                            stop: TrapStop::Other("max_calls reached".to_owned()),
                        });
                    }

                    match dispatch(env, emu, &name)? {
                        ApiOutcome::Handled { name, .. } | ApiOutcome::HandledVoid { name } => {
                            handled.push(name);
                            rip = emu.read_reg(RegisterX86::RIP)?;
                            continue;
                        }
                        ApiOutcome::Unhandled { name } => {
                            return Ok(TrapRun {
                                handled,
                                stop: TrapStop::UnhandledApi { name, rva },
                            });
                        }
                    }
                }

                if fault.kind != FaultKind::FetchUnmapped {
                    return Ok(TrapRun {
                        handled,
                        stop: TrapStop::UnexpectedFault {
                            address: fault.address,
                        },
                    });
                }

                // Classification heuristic: a fetch-fault at an in-image RVA whose
                // target parses as a printable IMAGE_IMPORT_BY_NAME is treated as
                // an unbound-import call. This does not yet cross-check the fault
                // RVA against the PE import descriptors, so a wild jump to an RVA
                // that coincidentally holds a printable string could be
                // misclassified. The blast radius is small: an unrecognized name
                // dispatches to Unhandled and stops cleanly, so only a coincidental
                // exact match of an implemented API name would misdispatch.
                // Cross-validating against the parsed import table is planned for
                // the module-image slice.
                let rva = fault.address;
                if rva >= u64::from(image.size_of_image) {
                    return Ok(TrapRun {
                        handled,
                        stop: TrapStop::UnexpectedFault {
                            address: fault.address,
                        },
                    });
                }

                let Some(name) =
                    read_import_by_name(emu, image.image_base, image.size_of_image, rva as u32)
                else {
                    return Ok(TrapRun {
                        handled,
                        stop: TrapStop::UnexpectedFault {
                            address: fault.address,
                        },
                    });
                };

                if handled.len() >= max_calls {
                    return Ok(TrapRun {
                        handled,
                        stop: TrapStop::Other("max_calls reached".to_owned()),
                    });
                }

                match dispatch(env, emu, &name)? {
                    ApiOutcome::Handled { name, .. } | ApiOutcome::HandledVoid { name } => {
                        handled.push(name);
                        rip = emu.read_reg(RegisterX86::RIP)?;
                    }
                    ApiOutcome::Unhandled { name } => {
                        return Ok(TrapRun {
                            handled,
                            stop: TrapStop::UnhandledApi {
                                name,
                                rva: rva as u32,
                            },
                        });
                    }
                }
            }
            StopReason::ReachedInstructionCap => {
                return Ok(TrapRun {
                    handled,
                    stop: TrapStop::InstructionCap,
                });
            }
            StopReason::ReachedUntil if report.final_rip == 0 => {
                return Ok(TrapRun {
                    handled,
                    stop: TrapStop::NullControlTransfer,
                });
            }
            other => {
                return Ok(TrapRun {
                    handled,
                    stop: TrapStop::Other(format!("{other:?}")),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{PeImage, Section};

    const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
    const CODE_RVA: u32 = 0x1000;
    const IMPORT_RVA: u32 = 0x2000;
    const DATA_RVA: u32 = 0x3000;
    const IMAGE_SIZE: u32 = 0x4000;
    const CURRENT_DIRECTORY_STATE_SENTINEL: [u16; 3] = [0x44, 0x3a, 0x5c];
    const CURRENT_DIRECTORY_W_BYTES: [u8; 8] = [0x43, 0, 0x3a, 0, 0x5c, 0, 0, 0];
    const MODULE_FILE_NAME_W_BYTES: [u8; 26] = [
        0x43, 0, 0x3a, 0, 0x5c, 0, 0x67, 0, 0x75, 0, 0x65, 0, 0x73, 0, 0x74, 0, 0x2e, 0, 0x65, 0,
        0x78, 0, 0x65, 0, 0, 0,
    ];

    fn wide_buffer_address() -> u64 {
        u64::from(u32::MAX) + 1 + u64::from(PAGE_SIZE)
    }

    fn test_image() -> PeImage {
        PeImage {
            image_base: IMAGE_BASE,
            entry_point_rva: CODE_RVA,
            size_of_headers: 0,
            size_of_image: IMAGE_SIZE,
            subsystem: 3,
            sections: vec![
                Section {
                    name: ".text".to_owned(),
                    virtual_address: CODE_RVA,
                    virtual_size: 0x1000,
                    pointer_to_raw_data: 0,
                    size_of_raw_data: 0,
                    characteristics: 0x6000_0020,
                },
                Section {
                    name: ".idata".to_owned(),
                    virtual_address: IMPORT_RVA,
                    virtual_size: 0x1000,
                    pointer_to_raw_data: 0,
                    size_of_raw_data: 0,
                    characteristics: 0x4000_0040,
                },
                Section {
                    name: ".data".to_owned(),
                    virtual_address: DATA_RVA,
                    virtual_size: 0x1000,
                    pointer_to_raw_data: 0,
                    size_of_raw_data: 0,
                    characteristics: 0x4000_0040,
                },
            ],
        }
    }

    fn map_import_name(emu: &mut Emu) {
        let mut idata = vec![0u8; 0x1000];
        idata[2..2 + b"GetModuleHandleA\0".len()].copy_from_slice(b"GetModuleHandleA\0");
        idata[0x80..0x84].copy_from_slice(&[0, b'A', 1, 0]);
        emu.map_code(IMAGE_BASE + u64::from(IMPORT_RVA), &idata)
            .unwrap();
    }

    fn map_module_name(emu: &mut Emu) {
        let mut data = vec![0u8; 0x1000];
        data[..b"kernel32.dll\0".len()].copy_from_slice(b"kernel32.dll\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();
    }

    fn read_u64_le(bytes: &[u8]) -> u64 {
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        u64::from_le_bytes(value)
    }

    fn read_u32_emu(emu: &Emu, addr: u64) -> u32 {
        let bytes = emu.read_mem(addr, 4).unwrap();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn read_ascii_z_emu(emu: &Emu, addr: u64) -> String {
        let mut bytes = Vec::new();
        for offset in 0..IMPORT_NAME_CAP {
            let byte = emu.read_mem(addr + offset as u64, 1).unwrap()[0];
            if byte == 0 {
                break;
            }
            bytes.push(byte);
        }
        String::from_utf8(bytes).unwrap()
    }

    const SLEEP_STATE_REGISTERS: [RegisterX86; 18] = [
        RegisterX86::RAX,
        RegisterX86::RBX,
        RegisterX86::RCX,
        RegisterX86::RDX,
        RegisterX86::RSI,
        RegisterX86::RDI,
        RegisterX86::RBP,
        RegisterX86::RSP,
        RegisterX86::R8,
        RegisterX86::R9,
        RegisterX86::R10,
        RegisterX86::R11,
        RegisterX86::R12,
        RegisterX86::R13,
        RegisterX86::R14,
        RegisterX86::R15,
        RegisterX86::RIP,
        RegisterX86::EFLAGS,
    ];

    fn seed_sleep_machine_state(emu: &mut Emu, rcx: u64, rsp: u64, rip: u64) {
        for (register, value) in [
            (RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd),
            (RegisterX86::RBX, 0x0101_0202_0303_0404),
            (RegisterX86::RDX, 0x1111_2222_3333_4444),
            (RegisterX86::RSI, 0x2121_2222_2323_2424),
            (RegisterX86::RDI, 0x3131_3232_3333_3434),
            (RegisterX86::RBP, 0x4141_4242_4343_4444),
            (RegisterX86::R8, 0x5151_5252_5353_5454),
            (RegisterX86::R9, 0x6161_6262_6363_6464),
            (RegisterX86::R10, 0x7171_7272_7373_7474),
            (RegisterX86::R11, 0x8181_8282_8383_8484),
            (RegisterX86::R12, 0x9191_9292_9393_9494),
            (RegisterX86::R13, 0xa1a1_a2a2_a3a3_a4a4),
            (RegisterX86::R14, 0xb1b1_b2b2_b3b3_b4b4),
            (RegisterX86::R15, 0xc1c1_c2c2_c3c3_c4c4),
        ] {
            emu.write_reg(register, value).unwrap();
        }
        emu.write_reg(RegisterX86::RCX, rcx).unwrap();
        emu.write_reg(RegisterX86::EFLAGS, 0x8c7).unwrap();
        emu.write_reg(RegisterX86::RIP, rip).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert_eq!(emu.read_reg(RegisterX86::EFLAGS).unwrap(), 0x8c7);
    }

    fn sleep_machine_state(emu: &Emu) -> Vec<(RegisterX86, u64)> {
        SLEEP_STATE_REGISTERS
            .iter()
            .map(|register| (*register, emu.read_reg(*register).unwrap()))
            .collect()
    }

    fn assert_sleep_return_state(emu: &Emu, before: &[(RegisterX86, u64)], return_address: u64) {
        for (register, value) in before {
            let expected = match *register {
                RegisterX86::RIP => return_address,
                RegisterX86::RSP => *value + 8,
                _ => *value,
            };
            assert_eq!(
                emu.read_reg(*register).unwrap(),
                expected,
                "unexpected {register:?} change"
            );
        }
    }

    fn sleep_environment_state(env: &Win64Env) -> String {
        format!("{env:#?}")
    }

    const WINDOW_CLASS_STRUCT_ADDRESS: u64 = crate::emu::STACK_BASE + 0x4000;
    const WINDOW_CLASS_NAME_ADDRESS: u64 = WINDOW_CLASS_STRUCT_ADDRESS + 0x100;
    const WINDOW_PROCEDURE_SENTINEL: u64 = 0x0000_0001_5000_1230;
    const ALTERNATE_WINDOW_PROCEDURE_SENTINEL: u64 = 0x0000_0001_5000_1240;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RegisterClassExAArgs {
        cb_size: u32,
        style: u32,
        window_procedure: u64,
        class_extra: i32,
        window_extra: i32,
        instance: u64,
        icon: u64,
        cursor: u64,
        background: u64,
        menu_name: u64,
        class_name: u64,
        icon_small: u64,
    }

    impl RegisterClassExAArgs {
        fn observed(class_name: u64) -> Self {
            Self {
                cb_size: WNDCLASSEXA_SIZE as u32,
                style: 3,
                window_procedure: WINDOW_PROCEDURE_SENTINEL,
                class_extra: 0,
                window_extra: 0,
                instance: IMAGE_BASE,
                icon: 0,
                cursor: EMULATED_HAND_CURSOR_HANDLE,
                background: 6,
                menu_name: 0,
                class_name,
                icon_small: 0,
            }
        }

        fn as_bytes(self) -> [u8; WNDCLASSEXA_SIZE] {
            let mut bytes = [0u8; WNDCLASSEXA_SIZE];
            write_u32(&mut bytes, 0, self.cb_size);
            write_u32(&mut bytes, 4, self.style);
            write_u64(&mut bytes, 8, self.window_procedure);
            write_bytes(&mut bytes, 16, &self.class_extra.to_le_bytes());
            write_bytes(&mut bytes, 20, &self.window_extra.to_le_bytes());
            write_u64(&mut bytes, 24, self.instance);
            write_u64(&mut bytes, 32, self.icon);
            write_u64(&mut bytes, 40, self.cursor);
            write_u64(&mut bytes, 48, self.background);
            write_u64(&mut bytes, 56, self.menu_name);
            write_u64(&mut bytes, 64, self.class_name);
            write_u64(&mut bytes, 72, self.icon_small);
            bytes
        }
    }

    fn prepare_register_class_ex_a_call(
        emu: &mut Emu,
        args: RegisterClassExAArgs,
        rsp: u64,
        return_address: u64,
    ) {
        emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &args.as_bytes())
            .unwrap();
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        seed_sleep_machine_state(emu, WINDOW_CLASS_STRUCT_ADDRESS, rsp, 0x1111_2222_3333_4444);
    }

    fn call_register_class_ex_a(
        env: &mut Win64Env,
        emu: &mut Emu,
        args: RegisterClassExAArgs,
        name: &[u8],
        rsp: u64,
        return_address: u64,
    ) -> u64 {
        if !name.is_empty() {
            emu.write_mem(args.class_name, name).unwrap();
        }
        prepare_register_class_ex_a_call(emu, args, rsp, return_address);
        let outcome = dispatch(env, emu, "RegisterClassExA").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected RegisterClassExA to be handled");
        };
        assert_eq!(name, "RegisterClassExA");
        ret
    }

    fn call_rtl_allocate_heap(
        env: &mut Win64Env,
        emu: &mut Emu,
        heap_handle: u64,
        flags: u64,
        requested_size: u64,
    ) -> u64 {
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, heap_handle).unwrap();
        emu.write_reg(RegisterX86::RDX, flags).unwrap();
        emu.write_reg(RegisterX86::R8, requested_size).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "RtlAllocateHeap").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected RtlAllocateHeap to be handled");
        };
        assert_eq!(name, "RtlAllocateHeap");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    fn call_rtl_add_vectored_exception_handler(
        env: &mut Win64Env,
        emu: &mut Emu,
        first: u64,
        handler: u64,
    ) -> u64 {
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RCX, first).unwrap();
        emu.write_reg(RegisterX86::RDX, handler).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "RtlAddVectoredExceptionHandler").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected RtlAddVectoredExceptionHandler to be handled");
        };
        assert_eq!(name, "RtlAddVectoredExceptionHandler");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), handler);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    fn call_open_thread(
        env: &mut Win64Env,
        emu: &mut Emu,
        desired_access: u64,
        inheritable: u64,
        thread_id: u64,
    ) -> u64 {
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, desired_access).unwrap();
        emu.write_reg(RegisterX86::RDX, inheritable).unwrap();
        emu.write_reg(RegisterX86::R8, thread_id).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "OpenThread").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected OpenThread to be handled");
        };
        assert_eq!(name, "OpenThread");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct CreateThreadArgs {
        thread_attributes: u64,
        requested_stack_size: u64,
        start_address: u64,
        parameter: u64,
        creation_flags_slot: u64,
        thread_id_output: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ThreadAllocatorState {
        next_thread_id: u64,
        created_threads: BTreeMap<u32, RunnableUnscheduledThread>,
        next_kernel_handle: u64,
        kernel_handles: BTreeMap<u64, KernelHandle>,
    }

    fn thread_allocator_state(env: &Win64Env) -> ThreadAllocatorState {
        ThreadAllocatorState {
            next_thread_id: env.next_thread_id,
            created_threads: env.created_threads.clone(),
            next_kernel_handle: env.next_kernel_handle,
            kernel_handles: env.kernel_handles.clone(),
        }
    }

    fn prepare_create_thread_call(
        emu: &mut Emu,
        args: CreateThreadArgs,
        rsp: u64,
        return_address: u64,
    ) {
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(rsp + 0x28, &args.creation_flags_slot.to_le_bytes())
            .unwrap();
        emu.write_mem(rsp + 0x30, &args.thread_id_output.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd)
            .unwrap();
        emu.write_reg(RegisterX86::RCX, args.thread_attributes)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, args.requested_stack_size)
            .unwrap();
        emu.write_reg(RegisterX86::R8, args.start_address).unwrap();
        emu.write_reg(RegisterX86::R9, args.parameter).unwrap();
        emu.write_reg(RegisterX86::RIP, 0x1111_2222_3333_4444)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
    }

    fn call_create_thread(
        env: &mut Win64Env,
        emu: &mut Emu,
        args: CreateThreadArgs,
        rsp: u64,
        return_address: u64,
    ) -> Result<u64, EmuError> {
        prepare_create_thread_call(emu, args, rsp, return_address);
        let outcome = dispatch(env, emu, "CreateThread")?;
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected CreateThread to be handled");
        };
        assert_eq!(name, "CreateThread");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(
            emu.read_reg(RegisterX86::RCX).unwrap(),
            args.thread_attributes
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RDX).unwrap(),
            args.requested_stack_size
        );
        assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), args.start_address);
        assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), args.parameter);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        Ok(ret)
    }

    fn call_get_current_directory_w(
        env: &mut Win64Env,
        emu: &mut Emu,
        capacity: u64,
        buffer: u64,
        rsp: u64,
        return_address: u64,
    ) -> u64 {
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RCX, capacity).unwrap();
        emu.write_reg(RegisterX86::RDX, buffer).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "GetCurrentDirectoryW").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected GetCurrentDirectoryW to be handled");
        };
        assert_eq!(name, "GetCurrentDirectoryW");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    fn call_set_current_directory_w(
        env: &mut Win64Env,
        emu: &mut Emu,
        path: u64,
        rsp: u64,
        return_address: u64,
    ) -> u64 {
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RCX, path).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "SetCurrentDirectoryW").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected SetCurrentDirectoryW to be handled");
        };
        assert_eq!(name, "SetCurrentDirectoryW");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    fn call_get_module_file_name_w(
        env: &mut Win64Env,
        emu: &mut Emu,
        module: u64,
        buffer: u64,
        capacity: u64,
        rsp: u64,
        return_address: u64,
    ) -> u64 {
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RCX, module).unwrap();
        emu.write_reg(RegisterX86::RDX, buffer).unwrap();
        emu.write_reg(RegisterX86::R8, capacity).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "GetModuleFileNameW").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected GetModuleFileNameW to be handled");
        };
        assert_eq!(name, "GetModuleFileNameW");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    #[test]
    fn read_import_by_name_reads_function_name() {
        let mut emu = Emu::new().unwrap();
        map_import_name(&mut emu);

        assert_eq!(
            read_import_by_name(&emu, IMAGE_BASE, IMAGE_SIZE, IMPORT_RVA),
            Some("GetModuleHandleA".to_owned())
        );
        assert_eq!(
            read_import_by_name(&emu, IMAGE_BASE, IMAGE_SIZE, IMPORT_RVA + 0x80),
            None
        );
    }

    #[test]
    fn read_import_by_name_reads_name_near_mapping_boundary() {
        // Map a single page at IMPORT_RVA; the page immediately after it is
        // unmapped. Place hint + "GetModuleHandleA\0" so the name terminates
        // inside the page but the name start + IMPORT_NAME_CAP window extends
        // past the page into unmapped memory. A bulk `read_mem(.., 256)` would
        // fail and reject a valid import; the byte-wise scan resolves it.
        let mut emu = Emu::new().unwrap();
        let mut page = vec![0u8; 0x1000];
        let name = b"GetModuleHandleA\0";
        let name_offset = 0x1000 - name.len() - 2; // hint (2 bytes) then name
        page[name_offset + 2..name_offset + 2 + name.len()].copy_from_slice(name);
        emu.map_code(IMAGE_BASE + u64::from(IMPORT_RVA), &page)
            .unwrap();

        // Confirm the window really would cross into the unmapped next page.
        let name_address = IMAGE_BASE + u64::from(IMPORT_RVA) + name_offset as u64 + 2;
        assert!(emu.read_mem(name_address, IMPORT_NAME_CAP).is_err());

        assert_eq!(
            read_import_by_name(
                &emu,
                IMAGE_BASE,
                IMAGE_SIZE,
                IMPORT_RVA + name_offset as u32
            ),
            Some("GetModuleHandleA".to_owned())
        );
    }

    #[test]
    fn synthetic_kernel32_is_parseable() {
        let mut emu = Emu::new().unwrap();
        let module =
            SyntheticModule::build(FAKE_MODULE_BASE_START, "kernel32.dll", KERNEL32_EXPORTS);
        module.map_into(&mut emu).unwrap();

        assert_eq!(emu.read_mem(module.base, 2).unwrap(), b"MZ");
        let pe_offset = read_u32_emu(&emu, module.base + 0x3c);
        assert_eq!(pe_offset, 0x80);
        assert_eq!(
            emu.read_mem(module.base + u64::from(pe_offset), 4).unwrap(),
            b"PE\0\0"
        );

        let optional_header = module.base + u64::from(pe_offset) + 24;
        let export_dir_rva = read_u32_emu(&emu, optional_header + 112);
        assert_eq!(export_dir_rva, SYNTHETIC_EXPORT_DIR_RVA);

        let export_dir = module.base + u64::from(export_dir_rva);
        let name_rva = read_u32_emu(&emu, export_dir + 12);
        assert_eq!(
            read_ascii_z_emu(&emu, module.base + u64::from(name_rva)),
            "kernel32.dll"
        );

        let number_of_names = read_u32_emu(&emu, export_dir + 24);
        let address_of_names = read_u32_emu(&emu, export_dir + 32);
        let mut walked = Vec::new();
        for index in 0..number_of_names {
            let export_name_rva = read_u32_emu(
                &emu,
                module.base + u64::from(address_of_names) + u64::from(index) * 4,
            );
            walked.push(read_ascii_z_emu(
                &emu,
                module.base + u64::from(export_name_rva),
            ));
        }

        let mut expected = KERNEL32_EXPORTS
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(walked, expected);
    }

    #[test]
    fn synthetic_module_empty_exports_is_parseable() {
        let mut emu = Emu::new().unwrap();
        let module = SyntheticModule::build(FAKE_MODULE_BASE_START, "somelib.dll", &[]);
        module.map_into(&mut emu).unwrap();

        assert_eq!(emu.read_mem(module.base, 2).unwrap(), b"MZ");
        let pe_offset = read_u32_emu(&emu, module.base + 0x3c);
        assert_eq!(pe_offset, 0x80);
        assert_eq!(
            emu.read_mem(module.base + u64::from(pe_offset), 4).unwrap(),
            b"PE\0\0"
        );

        let optional_header = module.base + u64::from(pe_offset) + 24;
        let export_dir_rva = read_u32_emu(&emu, optional_header + 112);
        assert_eq!(export_dir_rva, SYNTHETIC_EXPORT_DIR_RVA);

        let export_dir = module.base + u64::from(export_dir_rva);
        assert_eq!(read_u32_emu(&emu, export_dir + 20), 0);
        assert_eq!(read_u32_emu(&emu, export_dir + 24), 0);

        // With zero exports there is no stub region: map_into must not map one, so
        // the address just past the image blob is unmapped.
        assert_eq!(module.stub_region_size, 0);
        assert!(emu
            .read_mem(module.base + u64::from(module.stub_region_rva), 1)
            .is_err());
    }

    #[test]
    fn stub_export_at_disambiguates_multiple_modules() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        // Two distinct modules that share an export name, at distinct bases.
        let base_a = env.module_base("mod_a.dll");
        let base_b = env.module_base("mod_b.dll");
        assert_ne!(base_a, base_b);
        let mod_a = SyntheticModule::build(base_a, "mod_a.dll", &["Shared", "OnlyA"]);
        let mod_b = SyntheticModule::build(base_b, "mod_b.dll", &["Shared", "OnlyB"]);
        mod_a.map_into(&mut emu).unwrap();
        mod_b.map_into(&mut emu).unwrap();
        let a_shared = base_a + u64::from(*mod_a.exports.get("Shared").unwrap());
        let b_shared = base_b + u64::from(*mod_b.exports.get("Shared").unwrap());
        let b_only = base_b + u64::from(*mod_b.exports.get("OnlyB").unwrap());
        env.synthetic_modules.insert("mod_a.dll".to_owned(), mod_a);
        env.synthetic_modules.insert("mod_b.dll".to_owned(), mod_b);

        // Each shared-name stub reverse-maps to ITS OWN module (rva = addr - that base).
        assert_eq!(
            env.stub_export_at(a_shared),
            Some(("Shared".to_owned(), (a_shared - base_a) as u32))
        );
        assert_eq!(
            env.stub_export_at(b_shared),
            Some(("Shared".to_owned(), (b_shared - base_b) as u32))
        );
        assert_eq!(
            env.stub_export_at(b_only),
            Some(("OnlyB".to_owned(), (b_only - base_b) as u32))
        );
        // An address outside every module's stub region resolves to nothing.
        assert_eq!(env.stub_export_at(base_a - 1), None);
    }

    #[test]
    fn loadlibrarya_mixed_case_reuses_mapped_module() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut data = vec![0u8; 0x1000];
        data[..b"SomeLib.DLL\0".len()].copy_from_slice(b"SomeLib.DLL\0");
        data[0x80..0x80 + b"somelib.dll\0".len()].copy_from_slice(b"somelib.dll\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();

        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let first = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        let ApiOutcome::Handled { ret: base, .. } = first else {
            panic!("expected LoadLibraryA to be handled");
        };
        assert_ne!(base, 0);

        // A differently-cased spelling must reuse the cached module: a second
        // mem_map at the same base would return Err (and panic the unwrap).
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA) + 0x80)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let second = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "LoadLibraryA".to_owned(),
                ret: base
            }
        );
        assert_eq!(env.synthetic_modules.len(), 1);
    }

    #[test]
    fn loadlibrarya_ntdll_exports_match_seed() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let name_addr = crate::emu::STACK_BASE + 0x100;
        let rsp = crate::emu::STACK_BASE + 0x200;
        emu.write_mem(name_addr, b"ntdll.dll\0").unwrap();
        emu.write_mem(rsp, &0x1234_u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, name_addr).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let ApiOutcome::Handled { ret: base, .. } =
            dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap()
        else {
            panic!("expected LoadLibraryA to be handled");
        };
        let export_dir = base + u64::from(SYNTHETIC_EXPORT_DIR_RVA);
        let names_rva = read_u32_emu(&emu, export_dir + 32);
        let count = read_u32_emu(&emu, export_dir + 24);
        let names = (0..count)
            .map(|i| {
                read_ascii_z_emu(
                    &emu,
                    base + u64::from(read_u32_emu(
                        &emu,
                        base + u64::from(names_rva) + u64::from(i) * 4,
                    )),
                )
            })
            .collect::<Vec<_>>();
        let expected = vec![
            "NtQueryObject",
            "RtlAddVectoredExceptionHandler",
            "RtlAllocateHeap",
            "RtlEnterCriticalSection",
            "RtlFreeHeap",
            "RtlInitializeCriticalSection",
            "RtlLeaveCriticalSection",
            "RtlReAllocateHeap",
        ];
        assert_eq!(names, expected);
    }

    #[test]
    fn loadlibrarya_extensionless_ntdll_reuses_normalized_seed() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let name_addr = crate::emu::STACK_BASE + 0x100;
        let rsp = crate::emu::STACK_BASE + 0x200;
        emu.write_mem(name_addr, b"ntdll\0").unwrap();
        emu.write_mem(rsp, &0x1234_u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, name_addr).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let first = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        let ApiOutcome::Handled {
            ret: first_base, ..
        } = first
        else {
            panic!("expected LoadLibraryA to be handled");
        };
        assert!(env.synthetic_modules.contains_key("ntdll.dll"));
        assert_eq!(
            env.synthetic_modules.get("ntdll.dll").unwrap().base,
            first_base
        );
        let export_dir = first_base + u64::from(SYNTHETIC_EXPORT_DIR_RVA);
        let names_rva = read_u32_emu(&emu, export_dir + 32);
        let count = read_u32_emu(&emu, export_dir + 24);
        assert_eq!(count, 8);
        let names = (0..count)
            .map(|i| {
                read_ascii_z_emu(
                    &emu,
                    first_base
                        + u64::from(read_u32_emu(
                            &emu,
                            first_base + u64::from(names_rva) + u64::from(i) * 4,
                        )),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "NtQueryObject",
                "RtlAddVectoredExceptionHandler",
                "RtlAllocateHeap",
                "RtlEnterCriticalSection",
                "RtlFreeHeap",
                "RtlInitializeCriticalSection",
                "RtlLeaveCriticalSection",
                "RtlReAllocateHeap",
            ]
        );
        emu.write_mem(name_addr, b"NTDLL\0").unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let second = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "LoadLibraryA".to_owned(),
                ret: first_base,
            }
        );
        assert_eq!(
            env.synthetic_modules.get("ntdll.dll").unwrap().base,
            first_base
        );
    }

    #[test]
    fn normalize_module_name_handles_extensions_and_paths() {
        assert_eq!(normalize_module_name("ntdll"), "ntdll.dll");
        assert_eq!(normalize_module_name("dir/ntdll"), "dir/ntdll.dll");
        assert_eq!(normalize_module_name(r"dir\ntdll"), r"dir\ntdll.dll");
        assert_eq!(normalize_module_name("ntdll.sys"), "ntdll.sys");
        assert_eq!(normalize_module_name("ntdll."), "ntdll.");
        assert_eq!(normalize_module_name(""), "");
    }

    #[test]
    fn get_user_default_ui_language_returns_environment_policy() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address: u64 = 0x1234_5678_9abc_def0;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RDX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "GetUserDefaultUILanguage").unwrap();

        let expected = u64::from(EMULATED_USER_DEFAULT_UI_LANGID);
        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "GetUserDefaultUILanguage".to_owned(),
                ret: expected,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_process_heap_returns_stable_environment_handle() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let first_return_address: u64 = 0x1234_5678_9abc_def0;
        emu.write_mem(rsp, &first_return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RDX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let first = dispatch(&mut env, &mut emu, "GetProcessHeap").unwrap();
        let ApiOutcome::Handled {
            ret: first_handle, ..
        } = first
        else {
            panic!("expected GetProcessHeap to be handled");
        };
        assert_ne!(first_handle, 0);
        assert_eq!(first_handle, env.process_heap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), first_handle);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            first_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);

        let second_return_address: u64 = 0x0fed_cba9_8765_4321;
        emu.write_mem(rsp, &second_return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RAX, 0).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let second = dispatch(&mut env, &mut emu, "GetProcessHeap").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "GetProcessHeap".to_owned(),
                ret: first_handle,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), first_handle);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            second_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_current_thread_id_returns_stable_environment_policy_without_arguments() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first_rsp = crate::emu::STACK_BASE + 0x400;
        let second_rsp = crate::emu::STACK_BASE + 0x500;
        let first_return_address: u64 = 0x1234_5678_9abc_def0;
        let second_return_address: u64 = 0x0fed_cba9_8765_4321;
        emu.write_mem(first_rsp, &first_return_address.to_le_bytes())
            .unwrap();
        emu.write_mem(second_rsp, &second_return_address.to_le_bytes())
            .unwrap();

        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RCX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_5555_ffff_0000)
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0x0123_4567_89ab_cdef)
            .unwrap();
        emu.write_reg(RegisterX86::R9, 0xfedc_ba98_7654_3210)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, first_rsp).unwrap();

        let first = dispatch(&mut env, &mut emu, "GetCurrentThreadId").unwrap();
        let ApiOutcome::Handled {
            name: first_name,
            ret: first_id,
        } = first
        else {
            panic!("expected GetCurrentThreadId to be handled");
        };
        assert_eq!(first_name, "GetCurrentThreadId");
        assert_eq!(first_id, u64::from(env.current_thread_id));
        assert_eq!(first_id, 1);
        assert_ne!(first_id, 0);
        assert!(u32::try_from(first_id).is_ok());
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), first_id);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            first_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), first_rsp + 8);

        emu.write_reg(RegisterX86::RAX, 0xffff_ffff_0000_0000)
            .unwrap();
        emu.write_reg(RegisterX86::RCX, 0x1111_2222_3333_4444)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, 0x5555_6666_7777_8888)
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0x9999_aaaa_bbbb_cccc)
            .unwrap();
        emu.write_reg(RegisterX86::R9, 0xdddd_eeee_ffff_0000)
            .unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, second_rsp).unwrap();

        let second = dispatch(&mut env, &mut emu, "GetCurrentThreadId").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "GetCurrentThreadId".to_owned(),
                ret: first_id,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), first_id);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            second_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), second_rsp + 8);
    }

    #[test]
    fn get_version_returns_stable_packed_environment_policy_without_arguments() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first_rsp = crate::emu::STACK_BASE + 0x400;
        let second_rsp = crate::emu::STACK_BASE + 0x500;
        let first_return_address = 0x1234_5678_9abc_def0_u64;
        let second_return_address = 0x0fed_cba9_8765_4321_u64;
        emu.write_mem(first_rsp, &first_return_address.to_le_bytes())
            .unwrap();
        emu.write_mem(second_rsp, &second_return_address.to_le_bytes())
            .unwrap();

        let first_rcx = u64::MAX;
        let first_rdx = 0xaaaa_5555_ffff_0000;
        let first_r8 = 0x0123_4567_89ab_cdef;
        let first_r9 = 0xfedc_ba98_7654_3210;
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RCX, first_rcx).unwrap();
        emu.write_reg(RegisterX86::RDX, first_rdx).unwrap();
        emu.write_reg(RegisterX86::R8, first_r8).unwrap();
        emu.write_reg(RegisterX86::R9, first_r9).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, first_rsp).unwrap();

        let first = dispatch(&mut env, &mut emu, "GetVersion").unwrap();
        let expected = u64::from(EMULATED_WINDOWS_VERSION);
        assert_eq!(
            first,
            ApiOutcome::Handled {
                name: "GetVersion".to_owned(),
                ret: expected,
            }
        );
        let packed = u32::try_from(expected).unwrap();
        assert_eq!(packed, 0x23f0_0206);
        assert_eq!(packed & 0xff, 6);
        assert_eq!((packed >> 8) & 0xff, 2);
        assert_eq!((packed >> 16) & 0x7fff, 9200);
        assert_eq!(packed >> 31, 0);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), first_rcx);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), first_rdx);
        assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), first_r8);
        assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), first_r9);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            first_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), first_rsp + 8);

        let second_rcx = 0x1111_2222_3333_4444;
        let second_rdx = 0x5555_6666_7777_8888;
        let second_r8 = 0x9999_aaaa_bbbb_cccc;
        let second_r9 = 0xdddd_eeee_ffff_0000;
        emu.write_reg(RegisterX86::RAX, 0xffff_ffff_0000_0000)
            .unwrap();
        emu.write_reg(RegisterX86::RCX, second_rcx).unwrap();
        emu.write_reg(RegisterX86::RDX, second_rdx).unwrap();
        emu.write_reg(RegisterX86::R8, second_r8).unwrap();
        emu.write_reg(RegisterX86::R9, second_r9).unwrap();
        emu.write_reg(RegisterX86::RIP, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, second_rsp).unwrap();

        let second = dispatch(&mut env, &mut emu, "GetVersion").unwrap();
        assert_eq!(second, first);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), second_rcx);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), second_rdx);
        assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), second_r8);
        assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), second_r9);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            second_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), second_rsp + 8);
    }

    #[test]
    fn time_get_time_returns_stable_zero_without_arguments() {
        let call_and_assert =
            |env: &mut Win64Env, emu: &mut Emu, rsp: u64, return_address: u64, rcx: u64| {
                emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
                seed_sleep_machine_state(emu, rcx, rsp, 0x1111_2222_3333_4444);
                let machine_before = sleep_machine_state(emu);
                let environment_before = sleep_environment_state(env);
                let return_frame_before = emu.read_mem(rsp, 8).unwrap();

                let outcome = dispatch(env, emu, "timeGetTime").unwrap();

                let expected = u64::from(EMULATED_UPTIME_MS);
                assert_eq!(
                    outcome,
                    ApiOutcome::Handled {
                        name: "timeGetTime".to_owned(),
                        ret: expected,
                    }
                );
                assert_eq!(expected, 0);
                assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected);
                assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap() >> 32, 0);
                for (register, value) in machine_before {
                    let expected_register_value = match register {
                        RegisterX86::RAX => expected,
                        RegisterX86::RIP => return_address,
                        RegisterX86::RSP => value + 8,
                        _ => value,
                    };
                    assert_eq!(
                        emu.read_reg(register).unwrap(),
                        expected_register_value,
                        "unexpected {register:?} change"
                    );
                }
                assert_eq!(emu.read_mem(rsp, 8).unwrap(), return_frame_before);
                assert_eq!(sleep_environment_state(env), environment_before);
                expected
            };

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first = call_and_assert(
            &mut env,
            &mut emu,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
            u64::MAX,
        );
        let second = call_and_assert(
            &mut env,
            &mut emu,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
            0xaaaa_5555_ffff_0000,
        );

        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        let fresh = call_and_assert(
            &mut fresh_env,
            &mut fresh_emu,
            crate::emu::STACK_BASE + 0x600,
            0x1357_2468_ace0_bdf1,
            0x0123_4567_89ab_cdef,
        );

        assert_eq!(first, second);
        assert_eq!(second, fresh);
    }

    #[test]
    fn time_get_time_invalid_return_frame_is_failure_atomic() {
        for rsp in [0x0000_0000_dead_0000, u64::MAX] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            assert!(emu.read_mem(rsp, 8).is_err());
            seed_sleep_machine_state(&mut emu, 0xaaaa_5555_ffff_0000, rsp, 0x1111_2222_3333_4444);
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "timeGetTime").unwrap_err();

            assert!(
                matches!(error, EmuError::ReadMem { addr, size, .. } if addr == rsp && size == 8),
                "return-frame read must precede RSP arithmetic: {error:?}"
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn load_cursor_a_observed_idc_hand_returns_stable_opaque_handle() {
        let call_and_assert = |env: &mut Win64Env, emu: &mut Emu, rsp: u64, return_address: u64| {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(emu, 0, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, PREDEFINED_HAND_CURSOR_ID)
                .unwrap();
            let machine_before = sleep_machine_state(emu);
            let environment_before = sleep_environment_state(env);
            let return_frame_before = emu.read_mem(rsp, 8).unwrap();

            let outcome = dispatch(env, emu, "LoadCursorA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Handled {
                    name: "LoadCursorA".to_owned(),
                    ret: EMULATED_HAND_CURSOR_HANDLE,
                }
            );
            for (register, value) in machine_before {
                let expected = match register {
                    RegisterX86::RAX => EMULATED_HAND_CURSOR_HANDLE,
                    RegisterX86::RIP => return_address,
                    RegisterX86::RSP => value + 8,
                    _ => value,
                };
                assert_eq!(
                    emu.read_reg(register).unwrap(),
                    expected,
                    "unexpected {register:?} change"
                );
            }
            assert_eq!(emu.read_mem(rsp, 8).unwrap(), return_frame_before);
            assert_eq!(sleep_environment_state(env), environment_before);
            assert!(emu.read_mem(EMULATED_HAND_CURSOR_HANDLE, 1).is_err());
            EMULATED_HAND_CURSOR_HANDLE
        };

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first = call_and_assert(
            &mut env,
            &mut emu,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        let second = call_and_assert(
            &mut env,
            &mut emu,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );

        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        let fresh = call_and_assert(
            &mut fresh_env,
            &mut fresh_emu,
            crate::emu::STACK_BASE + 0x600,
            0x1357_2468_ace0_bdf1,
        );

        assert_eq!(first, second);
        assert_eq!(second, fresh);
        assert_ne!(first, 0);
        assert_ne!(first, EMULATED_PROCESS_HEAP_HANDLE);
        assert!((EMULATED_PROCESS_HEAP_HANDLE..KERNEL_HANDLE_BASE).contains(&first));
    }

    #[test]
    fn load_cursor_a_unmodeled_inputs_do_not_access_pointer_or_stack() {
        for (instance, cursor_name, rsp) in [
            (0x0000_0001_0000_0000, PREDEFINED_HAND_CURSOR_ID, u64::MAX),
            (0, 0x0000_0001_0000_7f89, 0x0000_0000_dead_0000),
            (0, 0x7f00, u64::MAX),
            (0, 0x0000_0000_dead_0000, 0x0000_0000_dead_1000),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            assert!(emu.read_mem(rsp, 8).is_err());
            seed_sleep_machine_state(&mut emu, instance, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, cursor_name).unwrap();
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "LoadCursorA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Unhandled {
                    name: "LoadCursorA".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn load_cursor_a_invalid_return_frame_is_failure_atomic() {
        for rsp in [0x0000_0000_dead_0000, u64::MAX] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            assert!(emu.read_mem(rsp, 8).is_err());
            seed_sleep_machine_state(&mut emu, 0, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, PREDEFINED_HAND_CURSOR_ID)
                .unwrap();
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "LoadCursorA").unwrap_err();

            assert!(
                matches!(error, EmuError::ReadMem { addr, size, .. } if addr == rsp && size == 8),
                "unexpected return-frame error: {error:?}"
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn register_class_ex_a_observed_shape_owns_record_and_returns_stable_atom() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0;
        let class_name = b"MidasTestClass\0";
        let args = RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS);
        assert!(u32::try_from(WINDOW_CLASS_STRUCT_ADDRESS).is_err());
        assert!(u32::try_from(WINDOW_CLASS_NAME_ADDRESS).is_err());
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, class_name)
            .unwrap();
        prepare_register_class_ex_a_call(&mut emu, args, rsp, return_address);
        let machine_before = sleep_machine_state(&emu);
        let return_frame_before = emu.read_mem(rsp, 8).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap();

        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "RegisterClassExA".to_owned(),
                ret: u64::from(WINDOW_CLASS_ATOM_BASE),
            }
        );
        for (register, value) in machine_before {
            let expected = match register {
                RegisterX86::RAX => u64::from(WINDOW_CLASS_ATOM_BASE),
                RegisterX86::RIP => return_address,
                RegisterX86::RSP => value + 8,
                _ => value,
            };
            assert_eq!(
                emu.read_reg(register).unwrap(),
                expected,
                "unexpected {register:?} change"
            );
        }
        assert_eq!(emu.read_mem(rsp, 8).unwrap(), return_frame_before);
        assert_eq!(env.next_window_class_atom, WINDOW_CLASS_ATOM_BASE + 1);
        assert_eq!(
            env.window_class_atoms_by_name
                .get(&(IMAGE_BASE, "midastestclass".to_owned())),
            Some(&(WINDOW_CLASS_ATOM_BASE as u16))
        );
        let registration = env
            .window_classes_by_atom
            .get(&(WINDOW_CLASS_ATOM_BASE as u16))
            .unwrap()
            .clone();
        assert_eq!(
            registration,
            RegisteredWindowClassA {
                atom: WINDOW_CLASS_ATOM_BASE as u16,
                cb_size: WNDCLASSEXA_SIZE as u32,
                style: 3,
                window_procedure: WINDOW_PROCEDURE_SENTINEL,
                class_extra: 0,
                window_extra: 0,
                instance: IMAGE_BASE,
                icon: 0,
                cursor: EMULATED_HAND_CURSOR_HANDLE,
                background: 6,
                menu_name: None,
                class_name: "MidasTestClass".to_owned(),
                icon_small: 0,
            }
        );

        // The environment record owns every retained value; guest mutations
        // after return cannot rename or reshape it.
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"ChangedInGuest\0")
            .unwrap();
        emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &[0; WNDCLASSEXA_SIZE])
            .unwrap();
        assert_eq!(
            env.window_classes_by_atom
                .get(&(WINDOW_CLASS_ATOM_BASE as u16)),
            Some(&registration)
        );

        let second_atom = call_register_class_ex_a(
            &mut env,
            &mut emu,
            args,
            b"SecondMidasClass\0",
            crate::emu::STACK_BASE + 0x600,
            0x2468_1357_bdf1_ace0,
        );
        assert_eq!(second_atom, u64::from(WINDOW_CLASS_ATOM_BASE + 1));
        assert_eq!(
            env.window_class_atoms_by_name
                .get(&(IMAGE_BASE, "secondmidasclass".to_owned())),
            Some(&((WINDOW_CLASS_ATOM_BASE + 1) as u16))
        );

        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        let fresh_atom = call_register_class_ex_a(
            &mut fresh_env,
            &mut fresh_emu,
            args,
            class_name,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );
        assert_eq!(fresh_atom, u64::from(WINDOW_CLASS_ATOM_BASE));
    }

    #[test]
    fn register_class_ex_a_duplicate_name_is_case_insensitive_and_nonmutating() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let args = RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS);
        let first = call_register_class_ex_a(
            &mut env,
            &mut emu,
            args,
            b"MidasTestClass\0",
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        assert_eq!(first, u64::from(WINDOW_CLASS_ATOM_BASE));

        let duplicate_args = RegisterClassExAArgs {
            window_procedure: ALTERNATE_WINDOW_PROCEDURE_SENTINEL,
            ..args
        };
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"mIDaStEStcLASS\0")
            .unwrap();
        let rsp = crate::emu::STACK_BASE + 0x500;
        let return_address = 0x0fed_cba9_8765_4321;
        prepare_register_class_ex_a_call(&mut emu, duplicate_args, rsp, return_address);
        let environment_before = sleep_environment_state(&env);
        let machine_before = sleep_machine_state(&emu);

        let outcome = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap();

        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "RegisterClassExA".to_owned(),
                ret: 0,
            }
        );
        for (register, value) in machine_before {
            let expected = match register {
                RegisterX86::RAX => 0,
                RegisterX86::RIP => return_address,
                RegisterX86::RSP => value + 8,
                _ => value,
            };
            assert_eq!(emu.read_reg(register).unwrap(), expected);
        }
        assert_eq!(sleep_environment_state(&env), environment_before);
        assert_eq!(env.next_window_class_atom, WINDOW_CLASS_ATOM_BASE + 1);
        assert_eq!(env.window_classes_by_atom.len(), 1);
    }

    #[test]
    fn register_class_ex_a_unmodeled_shapes_do_not_touch_name_or_return_frame() {
        let base = RegisterClassExAArgs::observed(0x0000_0000_dead_0000);
        let variations = [
            RegisterClassExAArgs { style: 4, ..base },
            RegisterClassExAArgs {
                class_extra: 1,
                ..base
            },
            RegisterClassExAArgs {
                window_extra: 1,
                ..base
            },
            RegisterClassExAArgs {
                instance: IMAGE_BASE + (1 << 32),
                ..base
            },
            RegisterClassExAArgs { icon: 1, ..base },
            RegisterClassExAArgs { cursor: 0, ..base },
            RegisterClassExAArgs {
                background: 7,
                ..base
            },
            RegisterClassExAArgs {
                menu_name: 0x0000_0000_dead_1000,
                ..base
            },
            RegisterClassExAArgs {
                icon_small: 1,
                ..base
            },
        ];
        for args in variations {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &args.as_bytes())
                .unwrap();
            seed_sleep_machine_state(
                &mut emu,
                WINDOW_CLASS_STRUCT_ADDRESS,
                u64::MAX,
                0x1111_2222_3333_4444,
            );
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Unhandled {
                    name: "RegisterClassExA".to_owned(),
                },
                "unexpected classification for {args:?}"
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }

        for (class_name, bytes) in [
            (PREDEFINED_HAND_CURSOR_ID, Vec::new()),
            (WINDOW_CLASS_NAME_ADDRESS, vec![b'A', 0x80, 0]),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let args = RegisterClassExAArgs::observed(class_name);
            if !bytes.is_empty() {
                emu.write_mem(class_name, &bytes).unwrap();
            }
            emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &args.as_bytes())
                .unwrap();
            seed_sleep_machine_state(
                &mut emu,
                WINDOW_CLASS_STRUCT_ADDRESS,
                u64::MAX,
                0x1111_2222_3333_4444,
            );
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Unhandled {
                    name: "RegisterClassExA".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn register_class_ex_a_known_invalid_inputs_return_zero() {
        // A wrong cbSize is conclusive from the first DWORD alone. Place it at
        // the end of the mapped stack to prove the remaining 76 bytes are not
        // required.
        {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let short_structure = crate::emu::STACK_BASE + crate::emu::STACK_SIZE - 4;
            emu.write_mem(
                short_structure,
                &((WNDCLASSEXA_SIZE - 1) as u32).to_le_bytes(),
            )
            .unwrap();
            assert!(emu.read_mem(short_structure, WNDCLASSEXA_SIZE).is_err());
            let rsp = crate::emu::STACK_BASE + 0x400;
            let return_address = 0x0123_4567_89ab_cdef_u64;
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(&mut emu, short_structure, rsp, 0x1111_2222_3333_4444);
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Handled {
                    name: "RegisterClassExA".to_owned(),
                    ret: 0,
                }
            );
            for (register, value) in machine_before {
                let expected = match register {
                    RegisterX86::RAX => 0,
                    RegisterX86::RIP => return_address,
                    RegisterX86::RSP => value + 8,
                    _ => value,
                };
                assert_eq!(emu.read_reg(register).unwrap(), expected);
            }
            assert_eq!(sleep_environment_state(&env), environment_before);
        }

        let cases = [
            (
                RegisterClassExAArgs {
                    cb_size: (WNDCLASSEXA_SIZE - 1) as u32,
                    class_name: 0x0000_0000_dead_0000,
                    ..RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS)
                },
                Vec::new(),
            ),
            (
                RegisterClassExAArgs {
                    window_procedure: 0,
                    ..RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS)
                },
                Vec::new(),
            ),
            (
                RegisterClassExAArgs {
                    instance: 0,
                    ..RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS)
                },
                Vec::new(),
            ),
            (RegisterClassExAArgs::observed(0), Vec::new()),
            (
                RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
                vec![0],
            ),
            (
                RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
                vec![b'A'; WINDOW_CLASS_NAME_BYTE_CAP],
            ),
        ];

        for (index, (args, class_name)) in cases.into_iter().enumerate() {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            if !class_name.is_empty() {
                emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, &class_name)
                    .unwrap();
            }
            let rsp = crate::emu::STACK_BASE + 0x400 + index as u64 * 0x20;
            let return_address = 0x1234_5678_9abc_def0 + index as u64;
            prepare_register_class_ex_a_call(&mut emu, args, rsp, return_address);
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Handled {
                    name: "RegisterClassExA".to_owned(),
                    ret: 0,
                }
            );
            for (register, value) in machine_before {
                let expected = match register {
                    RegisterX86::RAX => 0,
                    RegisterX86::RIP => return_address,
                    RegisterX86::RSP => value + 8,
                    _ => value,
                };
                assert_eq!(emu.read_reg(register).unwrap(), expected);
            }
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn register_class_ex_a_memory_and_return_failures_are_atomic() {
        // Invalid structure pointer: the cbSize pre-read fails before the
        // return frame or environment is touched.
        {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            seed_sleep_machine_state(
                &mut emu,
                0x0000_0000_dead_0000,
                crate::emu::STACK_BASE + 0x400,
                0x1111_2222_3333_4444,
            );
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap_err();

            assert!(
                matches!(error, EmuError::ReadMem { addr, size: 4, .. } if addr == 0x0000_0000_dead_0000)
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }

        // Supported scalar shape with an invalid full-width class pointer.
        {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let args = RegisterClassExAArgs::observed(0x0000_0001_dead_0000);
            emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &args.as_bytes())
                .unwrap();
            seed_sleep_machine_state(
                &mut emu,
                WINDOW_CLASS_STRUCT_ADDRESS,
                crate::emu::STACK_BASE + 0x400,
                0x1111_2222_3333_4444,
            );
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap_err();

            assert!(
                matches!(error, EmuError::ReadMem { addr, size: 1, .. } if addr == args.class_name)
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }

        // All guest inputs are accepted, but the return-frame preflight fails.
        for args in [
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            RegisterClassExAArgs {
                cb_size: 0,
                ..RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS)
            },
            RegisterClassExAArgs {
                window_procedure: 0,
                ..RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS)
            },
            RegisterClassExAArgs {
                instance: 0,
                ..RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS)
            },
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"AtomicClass\0")
                .unwrap();
            emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &args.as_bytes())
                .unwrap();
            seed_sleep_machine_state(
                &mut emu,
                WINDOW_CLASS_STRUCT_ADDRESS,
                u64::MAX,
                0x1111_2222_3333_4444,
            );
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "RegisterClassExA").unwrap_err();

            assert!(matches!(error, EmuError::ReadMem { addr, size: 8, .. } if addr == u64::MAX));
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn register_class_ex_a_enforces_name_and_atom_bounds() {
        let mut maximum_name = vec![b'A'; WINDOW_CLASS_NAME_BYTE_CAP - 1];
        maximum_name.push(0);
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let atom = call_register_class_ex_a(
            &mut env,
            &mut emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            &maximum_name,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        assert_eq!(atom, u64::from(WINDOW_CLASS_ATOM_BASE));
        assert_eq!(
            env.window_classes_by_atom
                .get(&(WINDOW_CLASS_ATOM_BASE as u16))
                .unwrap()
                .class_name
                .len(),
            WINDOW_CLASS_NAME_BYTE_CAP - 1
        );

        let mut unterminated_emu = Emu::new().unwrap();
        let mut unterminated_env = Win64Env::new(IMAGE_BASE);
        let ret = call_register_class_ex_a(
            &mut unterminated_env,
            &mut unterminated_emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            &vec![b'B'; WINDOW_CLASS_NAME_BYTE_CAP],
            crate::emu::STACK_BASE + 0x400,
            0x0fed_cba9_8765_4321,
        );
        assert_eq!(ret, 0);
        assert_eq!(
            unterminated_env.next_window_class_atom,
            WINDOW_CLASS_ATOM_BASE
        );
        assert!(unterminated_env.window_classes_by_atom.is_empty());

        let mut last_emu = Emu::new().unwrap();
        let mut last_env = Win64Env::new(IMAGE_BASE);
        last_env.next_window_class_atom = u32::from(u16::MAX);
        let last = call_register_class_ex_a(
            &mut last_env,
            &mut last_emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            b"LastClass\0",
            crate::emu::STACK_BASE + 0x400,
            0x1111_2222_3333_4444,
        );
        assert_eq!(last, u64::from(u16::MAX));
        assert_eq!(last_env.next_window_class_atom, WINDOW_CLASS_ATOM_EXHAUSTED);
        let exhausted_before = sleep_environment_state(&last_env);
        let exhausted = call_register_class_ex_a(
            &mut last_env,
            &mut last_emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            b"BeyondClass\0",
            crate::emu::STACK_BASE + 0x500,
            0x2222_3333_4444_5555,
        );
        assert_eq!(exhausted, 0);
        assert_eq!(sleep_environment_state(&last_env), exhausted_before);

        let mut collision_emu = Emu::new().unwrap();
        let mut collision_env = Win64Env::new(IMAGE_BASE);
        let first = call_register_class_ex_a(
            &mut collision_env,
            &mut collision_emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            b"FirstClass\0",
            crate::emu::STACK_BASE + 0x400,
            0x3333_4444_5555_6666,
        );
        assert_eq!(first, u64::from(WINDOW_CLASS_ATOM_BASE));
        collision_env.next_window_class_atom = WINDOW_CLASS_ATOM_BASE;
        let collision_before = sleep_environment_state(&collision_env);
        let collision = call_register_class_ex_a(
            &mut collision_env,
            &mut collision_emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            b"SecondClass\0",
            crate::emu::STACK_BASE + 0x500,
            0x4444_5555_6666_7777,
        );
        assert_eq!(collision, 0);
        assert_eq!(sleep_environment_state(&collision_env), collision_before);
    }

    #[test]
    fn sleep_observed_one_returns_void_and_preserves_machine_state() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let initial_rip = 0x1111_2222_3333_4444;
        let return_address = 0x1234_5678_9abc_def0_u64;
        let rcx = 0xfedc_ba98_0000_0001;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        seed_sleep_machine_state(&mut emu, rcx, rsp, initial_rip);
        let before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);
        let return_frame_before = emu.read_mem(rsp, 8).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "Sleep").unwrap();

        assert_eq!(
            outcome,
            ApiOutcome::HandledVoid {
                name: "Sleep".to_owned(),
            }
        );
        assert_sleep_return_state(&emu, &before, return_address);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            0xaaaa_bbbb_cccc_dddd
        );
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), rcx);
        assert_eq!(emu.read_reg(RegisterX86::EFLAGS).unwrap(), 0x8c7);
        assert_eq!(emu.read_mem(rsp, 8).unwrap(), return_frame_before);
        assert_eq!(sleep_environment_state(&env), environment_before);
    }

    #[test]
    fn sleep_elides_finite_positive_boundary_and_generalization_cases() {
        for (index, interval) in [2, 0x8000_0000, u32::MAX - 1].into_iter().enumerate() {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let rsp = crate::emu::STACK_BASE + 0x400;
            let return_address = 0x1234_5678_9abc_def0_u64 + index as u64;
            let rcx = 0xa5a5_5a5a_0000_0000 | u64::from(interval);
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(&mut emu, rcx, rsp, 0x1111_2222_3333_4444);
            let before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "Sleep").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::HandledVoid {
                    name: "Sleep".to_owned(),
                },
                "interval {interval:#x}"
            );
            assert_sleep_return_state(&emu, &before, return_address);
            assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), rcx);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn sleep_zero_and_infinite_are_unsupported_without_stack_access() {
        for (rcx, rsp) in [
            (0xffff_ffff_0000_0000, 0x0000_0000_dead_0000),
            (0x1357_2468_ffff_ffff, u64::MAX),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            assert!(emu.read_mem(rsp, 8).is_err());
            seed_sleep_machine_state(&mut emu, rcx, rsp, 0x1111_2222_3333_4444);
            let before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "Sleep").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Unhandled {
                    name: "Sleep".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn sleep_invalid_return_frame_pointers_are_failure_atomic() {
        for (rcx, rsp) in [
            (0xaaaa_5555_0000_0001, 0x0000_0000_dead_0000),
            (0x5555_aaaa_ffff_fffe, u64::MAX),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            assert!(emu.read_mem(rsp, 8).is_err());
            seed_sleep_machine_state(&mut emu, rcx, rsp, 0x1111_2222_3333_4444);
            let before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "Sleep").unwrap_err();

            assert!(
                matches!(error, EmuError::ReadMem { addr, size, .. } if addr == rsp && size == 8),
                "unexpected return-frame error: {error:?}"
            );
            assert_eq!(sleep_machine_state(&emu), before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn get_current_directory_w_zero_null_query_returns_required_size_without_buffer_access() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0;

        let ret = call_get_current_directory_w(&mut env, &mut emu, 0, 0, rsp, return_address);

        assert_eq!(ret, 4);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 4);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_current_directory_w_uses_low_capacity_bits_and_full_buffer_pointer() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let buffer = wide_buffer_address();
        assert!(u32::try_from(buffer).is_err());
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(buffer, &[0xa5; 16]).unwrap();

        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0;
        let ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            0xa5a5_5a5a_0000_0004,
            buffer,
            rsp,
            return_address,
        );

        assert_eq!(ret, 3);
        assert_eq!(
            emu.read_mem(buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 3);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_current_directory_w_handles_observed_heap_buffer_and_preserves_suffix() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let allocations = [0x1000, 0x10, 0x410, 0x10, 0x410].map(|requested_size| {
            call_rtl_allocate_heap(
                &mut env,
                &mut emu,
                process_heap,
                u64::from(HEAP_ZERO_MEMORY),
                requested_size,
            )
        });
        let buffer = allocations[4];
        assert_eq!(buffer, 0x0000_000f_4000_4000);

        let sentinel = [0xa5; 0x410];
        emu.write_mem(buffer, &sentinel).unwrap();

        let ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            0x208,
            buffer,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );

        assert_eq!(ret, 3);
        let actual = emu.read_mem(buffer, sentinel.len()).unwrap();
        assert_eq!(
            &actual[..CURRENT_DIRECTORY_W_BYTES.len()],
            &CURRENT_DIRECTORY_W_BYTES
        );
        assert_eq!(
            &actual[CURRENT_DIRECTORY_W_BYTES.len()..],
            &sentinel[CURRENT_DIRECTORY_W_BYTES.len()..]
        );
    }

    #[test]
    fn get_current_directory_w_undersized_capacities_preserve_entire_buffer() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let buffer = wide_buffer_address();
        let sentinel = [0x5a; 32];
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(buffer, &sentinel).unwrap();

        for (index, capacity) in [1_u64, 2, 3].into_iter().enumerate() {
            let rsp = crate::emu::STACK_BASE + 0x400 + index as u64 * 0x10;
            let return_address = 0x1234_5678_9abc_def0 + index as u64;
            let dirty_capacity = 0xffff_ffff_0000_0000 | capacity;
            let ret = call_get_current_directory_w(
                &mut env,
                &mut emu,
                dirty_capacity,
                buffer,
                rsp,
                return_address,
            );

            assert_eq!(ret, 4);
            assert_eq!(emu.read_mem(buffer, sentinel.len()).unwrap(), sentinel);
        }
    }

    #[test]
    fn get_current_directory_w_repeated_calls_are_stable() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first_buffer = wide_buffer_address();
        let second_buffer = first_buffer + 0x100;
        emu.map_zeroed_rw(first_buffer, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_mem(first_buffer, &[0xa5; 16]).unwrap();
        emu.write_mem(second_buffer, &[0x5a; 16]).unwrap();

        let first_ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            4,
            first_buffer,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        let second_ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            4,
            second_buffer,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );

        assert_eq!(first_ret, 3);
        assert_eq!(second_ret, first_ret);
        assert_eq!(
            emu.read_mem(first_buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
        assert_eq!(
            emu.read_mem(second_buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
    }

    #[test]
    fn set_current_directory_w_handles_exact_observed_heap_derived_state() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let allocations = [0x1000, 0x10, 0x410].map(|requested_size| {
            call_rtl_allocate_heap(
                &mut env,
                &mut emu,
                process_heap,
                u64::from(HEAP_ZERO_MEMORY),
                requested_size,
            )
        });
        let path = allocations[2];
        assert_eq!(path, 0x0000_000f_4000_2000);
        assert!(u32::try_from(path).is_err());

        let module_ret = call_get_module_file_name_w(
            &mut env,
            &mut emu,
            0,
            path,
            0x208,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        assert_eq!(module_ret, 12);
        emu.write_mem(path + 4, &[0, 0]).unwrap();
        let input_before = emu.read_mem(path, 0x410).unwrap();
        assert_eq!(
            &input_before[..10],
            &[0x43, 0, 0x3a, 0, 0, 0, 0x67, 0, 0x75, 0]
        );

        let rsp = crate::emu::STACK_BASE + 0x500;
        let return_address = 0x0fed_cba9_8765_4321;
        let ret = call_set_current_directory_w(&mut env, &mut emu, path, rsp, return_address);

        assert_eq!(ret, 1);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        assert_eq!(env.current_directory, EMULATED_CURRENT_DIRECTORY);
        assert_eq!(emu.read_mem(path, 0x410).unwrap(), input_before);

        let current_directory_buffer = allocations[0];
        let current_ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            4,
            current_directory_buffer,
            crate::emu::STACK_BASE + 0x600,
            0x1020_3040_5060_7080,
        );
        assert_eq!(current_ret, 3);
        assert_eq!(
            emu.read_mem(current_directory_buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
        assert_eq!(emu.read_mem(path, 0x410).unwrap(), input_before);
    }

    #[test]
    fn set_current_directory_w_accepts_lowercase_selector_and_canonicalizes() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let page = wide_buffer_address();
        emu.map_zeroed_rw(page, u64::from(PAGE_SIZE)).unwrap();
        let path = page + 0x100;
        assert!(u32::try_from(path).is_err());
        let input = utf16le_with_nul(&[0x63, 0x3a]).unwrap();
        emu.write_mem(path, &input).unwrap();
        env.current_directory = [0x63, 0x3a, 0x5c];

        let ret = call_set_current_directory_w(
            &mut env,
            &mut emu,
            path,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );

        assert_eq!(ret, 1);
        assert_eq!(env.current_directory, EMULATED_CURRENT_DIRECTORY);
        assert_eq!(emu.read_mem(path, input.len()).unwrap(), input);

        let current_directory_buffer = page + 0x200;
        let current_ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            4,
            current_directory_buffer,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );
        assert_eq!(current_ret, 3);
        assert_eq!(
            emu.read_mem(current_directory_buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
    }

    #[test]
    fn set_current_directory_w_rejects_paths_outside_bounded_policy() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let page = wide_buffer_address();
        emu.map_zeroed_rw(page, u64::from(PAGE_SIZE)).unwrap();
        // A test-only noncanonical sentinel makes unintended normalization on
        // rejected inputs observable.
        env.current_directory = CURRENT_DIRECTORY_STATE_SENTINEL;
        let state_before = env.current_directory;
        let cases: [(&str, &[u16]); 5] = [
            ("empty", &[]),
            ("other drive", &[0x44, 0x3a]),
            (
                "drive-relative subdirectory",
                &[0x43, 0x3a, 0x73, 0x75, 0x62, 0x64, 0x69, 0x72],
            ),
            ("relative path", &[0x73, 0x75, 0x62, 0x64, 0x69, 0x72]),
            (
                "UNC path",
                &[
                    0x5c, 0x5c, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5c, 0x73, 0x68, 0x61, 0x72,
                    0x65,
                ],
            ),
        ];

        for (index, (label, units)) in cases.into_iter().enumerate() {
            let path = page + index as u64 * 0x100;
            let sentinel = [0xa5; 0x80];
            emu.write_mem(path, &sentinel).unwrap();
            let bytes = utf16le_with_nul(units).unwrap();
            emu.write_mem(path, &bytes).unwrap();
            let input_before = emu.read_mem(path, sentinel.len()).unwrap();
            let rsp = crate::emu::STACK_BASE + 0x400 + index as u64 * 0x20;
            let return_address = 0x1234_5678_9abc_def0 + index as u64;

            let ret = call_set_current_directory_w(&mut env, &mut emu, path, rsp, return_address);

            assert_eq!(ret, 0, "{label}");
            assert_eq!(env.current_directory, state_before, "{label}");
            assert_eq!(
                emu.read_mem(path, sentinel.len()).unwrap(),
                input_before,
                "{label}"
            );
        }
    }

    #[test]
    fn set_current_directory_w_cap_exhaustion_stops_at_mapped_page_boundary() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let page = wide_buffer_address();
        let next_page = page + u64::from(PAGE_SIZE);
        emu.map_zeroed_rw(page, u64::from(PAGE_SIZE)).unwrap();
        assert!(emu.read_mem(next_page, 1).is_err());

        const POLICY_UNIT_CAP: usize = 260;
        assert_eq!(SET_CURRENT_DIRECTORY_W_UNIT_CAP, POLICY_UNIT_CAP);
        let mut input = Vec::with_capacity(POLICY_UNIT_CAP * 2);
        for _ in 0..POLICY_UNIT_CAP {
            input.extend_from_slice(&0x41_u16.to_le_bytes());
        }
        let path = next_page - u64::try_from(input.len()).unwrap();
        assert_eq!(path + u64::try_from(input.len()).unwrap(), next_page);
        emu.write_mem(path, &input).unwrap();
        env.current_directory = CURRENT_DIRECTORY_STATE_SENTINEL;
        let state_before = env.current_directory;

        let ret = call_set_current_directory_w(
            &mut env,
            &mut emu,
            path,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );

        assert_eq!(ret, 0);
        assert_eq!(env.current_directory, state_before);
        assert_eq!(emu.read_mem(path, input.len()).unwrap(), input);
        assert!(emu.read_mem(next_page, 1).is_err());
    }

    #[test]
    fn set_current_directory_w_invalid_base_pointers_are_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.current_directory = CURRENT_DIRECTORY_STATE_SENTINEL;
        let state_before = env.current_directory;
        let unmapped = 0x0000_0000_dead_0000;
        assert!(emu.read_mem(unmapped, 1).is_err());

        for (index, path) in [0, unmapped].into_iter().enumerate() {
            let rsp = crate::emu::STACK_BASE + 0x400 + index as u64 * 0x20;
            let return_address = 0x1234_5678_9abc_def0 + index as u64;
            let rax_before = 0xa5a5_5a5a_1122_3344 + index as u64;
            let rip_before = 0x0fed_cba9_8765_4321 + index as u64;
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            emu.write_reg(RegisterX86::RAX, rax_before).unwrap();
            emu.write_reg(RegisterX86::RCX, path).unwrap();
            emu.write_reg(RegisterX86::RIP, rip_before).unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();

            assert!(matches!(
                dispatch(&mut env, &mut emu, "SetCurrentDirectoryW"),
                Err(EmuError::ReadMem { addr, size: 2, .. }) if addr == path
            ));
            assert_eq!(env.current_directory, state_before);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), rax_before);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), rip_before);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
        }

        let path = u64::MAX;
        let rsp = crate::emu::STACK_BASE + 0x500;
        let return_address = 0x1020_3040_5060_7080_u64;
        let rax_before = 0xa5a5_5a5a_5566_7788;
        let rip_before = 0x8877_6655_4433_2211;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, rax_before).unwrap();
        emu.write_reg(RegisterX86::RCX, path).unwrap();
        emu.write_reg(RegisterX86::RIP, rip_before).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert!(matches!(
            dispatch(&mut env, &mut emu, "SetCurrentDirectoryW"),
            Err(EmuError::AddressRangeOverflow { base, size: 2 }) if base == path
        ));
        assert_eq!(env.current_directory, state_before);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), rax_before);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), rip_before);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
    }

    #[test]
    fn set_current_directory_w_unmapped_terminator_is_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let page = wide_buffer_address();
        let next_page = page + u64::from(PAGE_SIZE);
        emu.map_zeroed_rw(page, u64::from(PAGE_SIZE)).unwrap();
        let path = next_page - 4;
        let prefix = [0x43, 0, 0x3a, 0];
        emu.write_mem(path, &prefix).unwrap();
        assert!(emu.read_mem(next_page, 1).is_err());

        env.current_directory = CURRENT_DIRECTORY_STATE_SENTINEL;
        let state_before = env.current_directory;
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0_u64;
        let rax_before = 0xa5a5_5a5a_1122_3344;
        let rip_before = 0x0fed_cba9_8765_4321;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, rax_before).unwrap();
        emu.write_reg(RegisterX86::RCX, path).unwrap();
        emu.write_reg(RegisterX86::RIP, rip_before).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert!(matches!(
            dispatch(&mut env, &mut emu, "SetCurrentDirectoryW"),
            Err(EmuError::ReadMem { addr, size: 2, .. }) if addr == next_page
        ));
        assert_eq!(env.current_directory, state_before);
        assert_eq!(emu.read_mem(path, prefix.len()).unwrap(), prefix);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), rax_before);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), rip_before);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
    }

    #[test]
    fn get_module_file_name_w_handles_exact_observed_heap_call() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let allocations = [0x1000, 0x10, 0x410].map(|requested_size| {
            call_rtl_allocate_heap(
                &mut env,
                &mut emu,
                process_heap,
                u64::from(HEAP_ZERO_MEMORY),
                requested_size,
            )
        });
        let buffer = allocations[2];
        assert_eq!(buffer, 0x0000_000f_4000_2000);
        assert_eq!(
            env.heap_allocations.get(&buffer),
            Some(&HeapAllocation {
                requested_size: 0x410,
                mapped_size: u64::from(PAGE_SIZE),
            })
        );

        let sentinel = [0xa5; 0x410];
        emu.write_mem(buffer, &sentinel).unwrap();
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0;

        let ret =
            call_get_module_file_name_w(&mut env, &mut emu, 0, buffer, 0x208, rsp, return_address);

        assert_eq!(ret, 12);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 12);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        let actual = emu.read_mem(buffer, sentinel.len()).unwrap();
        assert_eq!(
            &actual[..MODULE_FILE_NAME_W_BYTES.len()],
            &MODULE_FILE_NAME_W_BYTES
        );
        assert_eq!(
            &actual[MODULE_FILE_NAME_W_BYTES.len()..],
            &sentinel[MODULE_FILE_NAME_W_BYTES.len()..]
        );
    }

    #[test]
    fn get_module_file_name_w_exact_fit_uses_abi_widths_and_is_stable() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let buffer = wide_buffer_address();
        assert!(u32::try_from(buffer).is_err());
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        let sentinel = [0x5a; 64];
        emu.write_mem(buffer, &sentinel).unwrap();
        let dirty_exact_fit = 0xa5a5_5a5a_0000_000d;

        let first_ret = call_get_module_file_name_w(
            &mut env,
            &mut emu,
            0,
            buffer,
            dirty_exact_fit,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        let first_actual = emu.read_mem(buffer, sentinel.len()).unwrap();

        assert_eq!(first_ret, 12);
        assert_eq!(
            &first_actual[..MODULE_FILE_NAME_W_BYTES.len()],
            &MODULE_FILE_NAME_W_BYTES
        );
        assert_eq!(
            &first_actual[MODULE_FILE_NAME_W_BYTES.len()..],
            &sentinel[MODULE_FILE_NAME_W_BYTES.len()..]
        );

        let second_ret = call_get_module_file_name_w(
            &mut env,
            &mut emu,
            0,
            buffer,
            dirty_exact_fit,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );

        assert_eq!(second_ret, first_ret);
        assert_eq!(emu.read_mem(buffer, sentinel.len()).unwrap(), first_actual);
    }

    #[test]
    fn get_module_file_name_w_modern_truncation_boundaries() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first_buffer = wide_buffer_address();
        emu.map_zeroed_rw(first_buffer, u64::from(PAGE_SIZE))
            .unwrap();
        let sentinel = [0x5a; 32];

        for (index, capacity) in [1_usize, 12].into_iter().enumerate() {
            let buffer = first_buffer + index as u64 * 0x100;
            emu.write_mem(buffer, &sentinel).unwrap();
            let dirty_capacity = 0xffff_ffff_0000_0000 | capacity as u64;
            let ret = call_get_module_file_name_w(
                &mut env,
                &mut emu,
                0,
                buffer,
                dirty_capacity,
                crate::emu::STACK_BASE + 0x400 + index as u64 * 0x100,
                0x1234_5678_9abc_def0 + index as u64,
            );

            assert_eq!(ret, capacity as u64);
            let written_len = capacity * std::mem::size_of::<u16>();
            let copied_len = (capacity - 1) * std::mem::size_of::<u16>();
            let mut expected = MODULE_FILE_NAME_W_BYTES[..copied_len].to_vec();
            expected.extend_from_slice(&[0, 0]);
            assert_eq!(expected.len(), written_len);

            let actual = emu.read_mem(buffer, sentinel.len()).unwrap();
            assert_eq!(&actual[..written_len], &expected);
            assert_eq!(&actual[written_len..], &sentinel[written_len..]);
        }
    }

    #[test]
    fn get_module_file_name_w_zero_size_is_not_a_query_and_does_not_access_buffer() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let unmapped = 0x0000_0000_dead_0000;
        assert!(emu.read_mem(unmapped, 1).is_err());

        for (index, buffer) in [0, unmapped].into_iter().enumerate() {
            let ret = call_get_module_file_name_w(
                &mut env,
                &mut emu,
                0,
                buffer,
                0xffff_ffff_0000_0000,
                crate::emu::STACK_BASE + 0x400 + index as u64 * 0x100,
                0x1234_5678_9abc_def0 + index as u64,
            );
            assert_eq!(ret, 0);
        }
    }

    #[test]
    fn get_module_file_name_w_rejects_high_only_module_without_touching_buffer() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let buffer = wide_buffer_address();
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        let sentinel = [0xa5; 64];
        emu.write_mem(buffer, &sentinel).unwrap();

        let ret = call_get_module_file_name_w(
            &mut env,
            &mut emu,
            1_u64 << 32,
            buffer,
            13,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );

        assert_eq!(ret, 0);
        assert_eq!(emu.read_mem(buffer, sentinel.len()).unwrap(), sentinel);
    }

    #[test]
    fn get_module_file_name_w_invalid_sufficient_buffer_is_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let page = wide_buffer_address();
        emu.map_zeroed_rw(page, u64::from(PAGE_SIZE)).unwrap();
        let buffer = page + u64::from(PAGE_SIZE) - 24;
        let sentinel = [0xa5; 24];
        emu.write_mem(buffer, &sentinel).unwrap();
        let rsp = crate::emu::STACK_BASE + 0x400;
        emu.write_mem(rsp, &0x1234_5678_9abc_def0_u64.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, 0).unwrap();
        emu.write_reg(RegisterX86::RDX, buffer).unwrap();
        emu.write_reg(RegisterX86::R8, 13).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert!(matches!(
            dispatch(&mut env, &mut emu, "GetModuleFileNameW"),
            Err(EmuError::WriteUnmapped { .. })
        ));
        assert_eq!(emu.read_mem(buffer, sentinel.len()).unwrap(), sentinel);
    }

    #[test]
    fn trap_dispatches_get_module_file_name_w_via_name_resolved_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("GetModuleFileNameW")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "GetModuleFileNameW")
            .unwrap();
        assert_eq!(stub, export_stub);

        let buffer = wide_buffer_address();
        assert!(u32::try_from(buffer).is_err());
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        let sentinel = [0xa5; 64];
        emu.write_mem(buffer, &sentinel).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&0_u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&buffer.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xb8]);
        code.extend_from_slice(&0x208_u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetModuleFileNameW".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 12);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        let actual = emu.read_mem(buffer, sentinel.len()).unwrap();
        assert_eq!(
            &actual[..MODULE_FILE_NAME_W_BYTES.len()],
            &MODULE_FILE_NAME_W_BYTES
        );
        assert_eq!(
            &actual[MODULE_FILE_NAME_W_BYTES.len()..],
            &sentinel[MODULE_FILE_NAME_W_BYTES.len()..]
        );
    }

    #[test]
    fn rtl_add_vectored_exception_handler_handles_exact_observed_call() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let observed_handler = 0x0000_0001_4006_aa83;

        assert!(emu.read_mem(observed_handler, 1).is_err());
        let token =
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, observed_handler);

        assert_eq!(token, VECTORED_EXCEPTION_HANDLER_TOKEN_BASE);
        assert_ne!(token, 0);
        assert!(token > u64::from(u32::MAX));
        assert!(token < EMULATED_PROCESS_HEAP_HANDLE);
        assert!(emu.read_mem(token, 1).is_err());
        assert_eq!(
            env.vectored_exception_handlers,
            vec![VectoredExceptionHandlerRegistration {
                token,
                handler: observed_handler,
            }]
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), token);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            0x1234_5678_9abc_def0
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RSP).unwrap(),
            crate::emu::STACK_BASE + 0x408
        );
    }

    #[test]
    fn rtl_add_vectored_exception_handler_uses_low_32_first_bits_and_full_handler_width_in_order() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let handler_a = 0x1111_2222_3333_4444;
        let handler_b = 0x5555_6666_7777_8888;
        let handler_c = 0x9999_aaaa_bbbb_cccc;
        let handler_d = 0xdddd_eeee_ffff_0001;

        let token_a = call_rtl_add_vectored_exception_handler(
            &mut env,
            &mut emu,
            0xaaaa_bbbb_0000_0000,
            handler_a,
        );
        let token_b = call_rtl_add_vectored_exception_handler(
            &mut env,
            &mut emu,
            0xcccc_dddd_0000_0000,
            handler_b,
        );
        let token_c = call_rtl_add_vectored_exception_handler(
            &mut env,
            &mut emu,
            0xeeee_ffff_0000_0001,
            handler_c,
        );
        let token_d = call_rtl_add_vectored_exception_handler(
            &mut env,
            &mut emu,
            0x1234_5678_8000_0000,
            handler_d,
        );

        assert_eq!(token_a, VECTORED_EXCEPTION_HANDLER_TOKEN_BASE);
        assert_eq!(token_b, token_a + VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE);
        assert_eq!(token_c, token_b + VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE);
        assert_eq!(token_d, token_c + VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE);
        assert_eq!(
            env.vectored_exception_handlers,
            vec![
                VectoredExceptionHandlerRegistration {
                    token: token_d,
                    handler: handler_d,
                },
                VectoredExceptionHandlerRegistration {
                    token: token_c,
                    handler: handler_c,
                },
                VectoredExceptionHandlerRegistration {
                    token: token_a,
                    handler: handler_a,
                },
                VectoredExceptionHandlerRegistration {
                    token: token_b,
                    handler: handler_b,
                },
            ]
        );
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), handler_d);
    }

    #[test]
    fn rtl_add_vectored_exception_handler_keeps_duplicate_and_zero_callbacks_independent() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let duplicate_handler = 0x0000_7fff_dead_beef;

        assert!(emu.read_mem(duplicate_handler, 1).is_err());
        assert!(emu.read_mem(0, 1).is_err());
        let first =
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, duplicate_handler);
        let zero = call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, 0);
        let duplicate =
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, duplicate_handler);

        assert_ne!(first, zero);
        assert_ne!(first, duplicate);
        assert_ne!(zero, duplicate);
        assert_eq!(
            env.vectored_exception_handlers,
            vec![
                VectoredExceptionHandlerRegistration {
                    token: first,
                    handler: duplicate_handler,
                },
                VectoredExceptionHandlerRegistration {
                    token: zero,
                    handler: 0,
                },
                VectoredExceptionHandlerRegistration {
                    token: duplicate,
                    handler: duplicate_handler,
                },
            ]
        );
    }

    #[test]
    fn rtl_add_vectored_exception_handler_allocator_failures_are_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        for rejected_cursor in [
            VECTORED_EXCEPTION_HANDLER_TOKEN_BASE - VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE,
            VECTORED_EXCEPTION_HANDLER_TOKEN_BASE + 1,
            EMULATED_PROCESS_HEAP_HANDLE,
            u64::MAX,
        ] {
            env.next_vectored_exception_handler_token = rejected_cursor;
            let registrations_before = env.vectored_exception_handlers.clone();
            assert_eq!(
                call_rtl_add_vectored_exception_handler(
                    &mut env,
                    &mut emu,
                    0,
                    0x1111_2222_3333_4444,
                ),
                0
            );
            assert_eq!(env.next_vectored_exception_handler_token, rejected_cursor);
            assert_eq!(env.vectored_exception_handlers, registrations_before);
        }

        env.next_vectored_exception_handler_token = VECTORED_EXCEPTION_HANDLER_TOKEN_BASE;
        let first =
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, 0x5555_6666_7777_8888);
        assert_eq!(first, VECTORED_EXCEPTION_HANDLER_TOKEN_BASE);

        env.next_vectored_exception_handler_token = first;
        let registrations_before_collision = env.vectored_exception_handlers.clone();
        assert_eq!(
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, 0x9999_aaaa_bbbb_cccc),
            0
        );
        assert_eq!(env.next_vectored_exception_handler_token, first);
        assert_eq!(
            env.vectored_exception_handlers,
            registrations_before_collision
        );

        let last_token = EMULATED_PROCESS_HEAP_HANDLE - VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE;
        env.next_vectored_exception_handler_token = last_token;
        assert_eq!(
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, 0xdddd_eeee_ffff_0001),
            last_token
        );
        assert_eq!(
            env.next_vectored_exception_handler_token,
            EMULATED_PROCESS_HEAP_HANDLE
        );

        let registrations_at_limit = env.vectored_exception_handlers.clone();
        assert_eq!(
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, u64::MAX),
            0
        );
        assert_eq!(
            env.next_vectored_exception_handler_token,
            EMULATED_PROCESS_HEAP_HANDLE
        );
        assert_eq!(env.vectored_exception_handlers, registrations_at_limit);
    }

    #[test]
    fn rtl_add_vectored_exception_handler_is_deterministic_and_isolated_per_environment() {
        let mut first_emu = Emu::new().unwrap();
        let mut first_env = Win64Env::new(IMAGE_BASE);
        let mut second_emu = Emu::new().unwrap();
        let mut second_env = Win64Env::new(IMAGE_BASE);

        let first_token = call_rtl_add_vectored_exception_handler(
            &mut first_env,
            &mut first_emu,
            0,
            0x1111_2222_3333_4444,
        );
        let second_token = call_rtl_add_vectored_exception_handler(
            &mut second_env,
            &mut second_emu,
            0,
            0x5555_6666_7777_8888,
        );

        assert_eq!(first_token, VECTORED_EXCEPTION_HANDLER_TOKEN_BASE);
        assert_eq!(second_token, VECTORED_EXCEPTION_HANDLER_TOKEN_BASE);
        assert_eq!(first_env.vectored_exception_handlers.len(), 1);
        assert_eq!(second_env.vectored_exception_handlers.len(), 1);
        assert_eq!(
            first_env.vectored_exception_handlers[0].handler,
            0x1111_2222_3333_4444
        );
        assert_eq!(
            second_env.vectored_exception_handlers[0].handler,
            0x5555_6666_7777_8888
        );
        assert_eq!(
            first_env.next_vectored_exception_handler_token,
            VECTORED_EXCEPTION_HANDLER_TOKEN_BASE + VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE
        );
        assert_eq!(
            second_env.next_vectored_exception_handler_token,
            VECTORED_EXCEPTION_HANDLER_TOKEN_BASE + VECTORED_EXCEPTION_HANDLER_TOKEN_STRIDE
        );
    }

    #[test]
    fn open_thread_handles_observed_call_with_dirty_upper_halves() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        let handle = call_open_thread(
            &mut env,
            &mut emu,
            0xa5a5_5a5a_001f_03ff,
            0xffff_ffff_0000_0000,
            0xdead_beef_0000_0001,
        );

        assert_eq!(handle, KERNEL_HANDLE_BASE);
        assert_ne!(handle, 0);
        assert_ne!(handle, env.process_heap);
        assert_ne!(handle, env.image_base);
        assert!(handle < HEAP_ARENA_BASE);
        assert!(handle < crate::emu::STACK_BASE);
        assert!(handle < PROC_STUB_BASE);
        assert!(handle < FAKE_MODULE_BASE_START);
        assert!(emu.read_mem(handle, 1).is_err());
        assert_eq!(
            env.kernel_handles.get(&handle),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 1 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            })
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), handle);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            0x1234_5678_9abc_def0
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RSP).unwrap(),
            crate::emu::STACK_BASE + 0x408
        );
    }

    #[test]
    fn open_thread_uses_current_id_and_allocates_fresh_handles() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let id_rsp = crate::emu::STACK_BASE + 0x500;
        let id_return_address = 0x0fed_cba9_8765_4321u64;
        emu.write_mem(id_rsp, &id_return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RSP, id_rsp).unwrap();

        let id_outcome = dispatch(&mut env, &mut emu, "GetCurrentThreadId").unwrap();
        let ApiOutcome::Handled { ret: thread_id, .. } = id_outcome else {
            panic!("expected GetCurrentThreadId to be handled");
        };
        assert_eq!(thread_id, 1);

        // The legacy unnamed 0x4 bit is deliberately supported, not rejected
        // as an unknown access right.
        let first = call_open_thread(&mut env, &mut emu, 0x4, 0, thread_id);
        let second = call_open_thread(
            &mut env,
            &mut emu,
            u64::from(LEGACY_THREAD_ALL_ACCESS),
            0xfeed_face_0000_0100,
            thread_id,
        );

        assert_eq!(first, KERNEL_HANDLE_BASE);
        assert_eq!(second, KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE);
        assert_ne!(first, second);
        assert_eq!(
            env.kernel_handles.get(&first),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 1 },
                desired_access: 0x4,
                inheritable: false,
            })
        );
        assert_eq!(
            env.kernel_handles.get(&second),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 1 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: true,
            })
        );
        assert_eq!(
            env.next_kernel_handle,
            KERNEL_HANDLE_BASE + 2 * KERNEL_HANDLE_STRIDE
        );
    }

    #[test]
    fn open_thread_rejects_invalid_requests_and_exhaustion_atomically() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let initial_cursor = env.next_kernel_handle;
        let initial_handles = env.kernel_handles.clone();

        for (desired_access, thread_id) in [
            (u64::from(LEGACY_THREAD_ALL_ACCESS), 0),
            (u64::from(LEGACY_THREAD_ALL_ACCESS), 2),
            (u64::from(LEGACY_THREAD_ALL_ACCESS | 0x0020_0000), 1),
        ] {
            assert_eq!(
                call_open_thread(&mut env, &mut emu, desired_access, 0, thread_id),
                0
            );
            assert_eq!(env.next_kernel_handle, initial_cursor);
            assert_eq!(env.kernel_handles, initial_handles);
        }

        for rejected_cursor in [KERNEL_HANDLE_BASE + 1, HEAP_ARENA_BASE, u64::MAX] {
            env.next_kernel_handle = rejected_cursor;
            let rejected_handles = env.kernel_handles.clone();
            assert_eq!(
                call_open_thread(
                    &mut env,
                    &mut emu,
                    u64::from(LEGACY_THREAD_ALL_ACCESS),
                    0,
                    1,
                ),
                0
            );
            assert_eq!(env.next_kernel_handle, rejected_cursor);
            assert_eq!(env.kernel_handles, rejected_handles);
        }

        let last_handle = HEAP_ARENA_BASE - KERNEL_HANDLE_STRIDE;
        env.next_kernel_handle = last_handle;
        assert_eq!(
            call_open_thread(
                &mut env,
                &mut emu,
                u64::from(LEGACY_THREAD_ALL_ACCESS),
                0,
                1,
            ),
            last_handle
        );
        assert_eq!(env.next_kernel_handle, HEAP_ARENA_BASE);

        let handles_at_limit = env.kernel_handles.clone();
        assert_eq!(
            call_open_thread(
                &mut env,
                &mut emu,
                u64::from(LEGACY_THREAD_ALL_ACCESS),
                0,
                1,
            ),
            0
        );
        assert_eq!(env.next_kernel_handle, HEAP_ARENA_BASE);
        assert_eq!(env.kernel_handles, handles_at_limit);

        env.next_kernel_handle = last_handle;
        let handles_before_collision = env.kernel_handles.clone();
        assert_eq!(
            call_open_thread(
                &mut env,
                &mut emu,
                u64::from(LEGACY_THREAD_ALL_ACCESS),
                0,
                1,
            ),
            0
        );
        assert_eq!(env.next_kernel_handle, last_handle);
        assert_eq!(env.kernel_handles, handles_before_collision);
    }

    #[test]
    fn create_thread_handles_exact_observed_call_after_open_thread() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first_handle = call_open_thread(
            &mut env,
            &mut emu,
            u64::from(LEGACY_THREAD_ALL_ACCESS),
            0,
            u64::from(EMULATED_CURRENT_THREAD_ID),
        );
        assert_eq!(first_handle, KERNEL_HANDLE_BASE);

        let formal_rsp = 0x0000_000f_ffff_ef78;
        let formal_return_address = 0x0000_0001_4025_961e;
        let formal_start_address = 0x0000_0001_4005_8fa0;
        let start_page = formal_start_address & !(u64::from(PAGE_SIZE) - 1);
        emu.map_code(start_page, &[0; PAGE_SIZE as usize]).unwrap();
        let args = CreateThreadArgs {
            start_address: formal_start_address,
            ..CreateThreadArgs::default()
        };

        let handle =
            call_create_thread(&mut env, &mut emu, args, formal_rsp, formal_return_address)
                .unwrap();

        assert_eq!(handle, KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE);
        assert_ne!(handle, 0);
        assert!(emu.read_mem(handle, 1).is_err());
        assert_eq!(env.next_thread_id, 3);
        assert_eq!(env.next_kernel_handle, handle + KERNEL_HANDLE_STRIDE);
        assert_eq!(
            env.created_threads.get(&2),
            Some(&RunnableUnscheduledThread {
                start_address: formal_start_address,
                parameter: 0,
                requested_stack_size: 0,
                creation_flags: 0,
            })
        );
        assert_eq!(
            env.runnable_unscheduled_threads()
                .map(|(thread_id, thread)| (thread_id, *thread))
                .collect::<Vec<_>>(),
            vec![(
                2,
                RunnableUnscheduledThread {
                    start_address: formal_start_address,
                    parameter: 0,
                    requested_stack_size: 0,
                    creation_flags: 0,
                }
            )]
        );
        assert_eq!(
            env.kernel_handles.get(&handle),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 2 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            })
        );
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), formal_start_address);
        assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), handle);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            formal_return_address
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), formal_rsp + 8);
    }

    #[test]
    fn create_thread_preserves_full_width_values_allocates_fresh_ids_and_opens_created_id() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let output = wide_buffer_address();
        assert!(output > u64::from(u32::MAX));
        emu.map_zeroed_rw(output, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(output, &[0xcc; 16]).unwrap();
        let rsp = crate::emu::STACK_BASE + 0x600;
        let return_address = 0x1234_5678_9abc_def0;

        let first_parameter = 0xfedc_ba98_7654_3210;
        let first = call_create_thread(
            &mut env,
            &mut emu,
            CreateThreadArgs {
                start_address: 0,
                parameter: first_parameter,
                creation_flags_slot: 0xa5a5_5a5a_0000_0000,
                thread_id_output: output,
                ..CreateThreadArgs::default()
            },
            rsp,
            return_address,
        )
        .unwrap();
        assert_eq!(first, KERNEL_HANDLE_BASE);
        assert_eq!(
            emu.read_mem(output, 8).unwrap(),
            vec![2, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc]
        );
        assert_eq!(
            env.created_threads.get(&2),
            Some(&RunnableUnscheduledThread {
                start_address: 0,
                parameter: first_parameter,
                requested_stack_size: 0,
                creation_flags: 0,
            })
        );

        let unmapped_start = 0x7654_3210_fedc_ba98;
        let second_parameter = 0x8000_0001_0000_0002;
        assert!(emu.read_mem(unmapped_start, 1).is_err());
        let second = call_create_thread(
            &mut env,
            &mut emu,
            CreateThreadArgs {
                start_address: unmapped_start,
                parameter: second_parameter,
                creation_flags_slot: 0xffff_ffff_0000_0000,
                thread_id_output: output + 8,
                ..CreateThreadArgs::default()
            },
            rsp,
            return_address,
        )
        .unwrap();
        assert_eq!(second, KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE);
        assert_eq!(read_u32_emu(&emu, output + 8), 3);
        assert_eq!(emu.read_mem(output + 12, 4).unwrap(), vec![0xcc; 4]);
        assert_eq!(
            env.created_threads.get(&3),
            Some(&RunnableUnscheduledThread {
                start_address: unmapped_start,
                parameter: second_parameter,
                requested_stack_size: 0,
                creation_flags: 0,
            })
        );
        assert_eq!(
            env.runnable_unscheduled_threads()
                .map(|(thread_id, _thread)| thread_id)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );

        let opened = call_open_thread(
            &mut env,
            &mut emu,
            u64::from(LEGACY_THREAD_ALL_ACCESS),
            0,
            2,
        );
        assert_eq!(opened, KERNEL_HANDLE_BASE + 2 * KERNEL_HANDLE_STRIDE);
        assert_eq!(
            env.kernel_handles.get(&opened),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 2 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            })
        );

        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let current = dispatch(&mut env, &mut emu, "GetCurrentThreadId").unwrap();
        assert!(matches!(
            current,
            ApiOutcome::Handled {
                name,
                ret: 1
            } if name == "GetCurrentThreadId"
        ));
    }

    #[test]
    fn create_thread_policy_failures_return_null_without_state_or_output_access() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x600;
        let return_address = 0x1234_5678_9abc_def0;
        let unmapped_output = 0x0000_0000_dead_0000;
        assert!(emu.read_mem(unmapped_output, 1).is_err());
        let mapped_output = wide_buffer_address();
        emu.map_zeroed_rw(mapped_output, u64::from(PAGE_SIZE))
            .unwrap();
        let initial_state = thread_allocator_state(&env);
        let unsupported = [
            CreateThreadArgs {
                thread_attributes: 1,
                ..CreateThreadArgs::default()
            },
            CreateThreadArgs {
                thread_attributes: 0x1_0000_0000,
                ..CreateThreadArgs::default()
            },
            CreateThreadArgs {
                requested_stack_size: 1,
                ..CreateThreadArgs::default()
            },
            CreateThreadArgs {
                requested_stack_size: 0x1_0000_0000,
                ..CreateThreadArgs::default()
            },
            CreateThreadArgs {
                creation_flags_slot: 0xffff_ffff_0000_0001,
                ..CreateThreadArgs::default()
            },
            CreateThreadArgs {
                creation_flags_slot: 0x0000_0000_0000_0004,
                ..CreateThreadArgs::default()
            },
            CreateThreadArgs {
                creation_flags_slot: 0x0000_0000_0001_0000,
                ..CreateThreadArgs::default()
            },
        ];

        for mut args in unsupported {
            emu.write_mem(mapped_output, &0x7856_3412u32.to_le_bytes())
                .unwrap();
            args.thread_id_output = mapped_output;
            assert_eq!(
                call_create_thread(&mut env, &mut emu, args, rsp, return_address).unwrap(),
                0
            );
            assert_eq!(thread_allocator_state(&env), initial_state);
            assert_eq!(read_u32_emu(&emu, mapped_output), 0x7856_3412);

            args.thread_id_output = unmapped_output;
            assert_eq!(
                call_create_thread(&mut env, &mut emu, args, rsp, return_address).unwrap(),
                0
            );
            assert_eq!(thread_allocator_state(&env), initial_state);
        }

        let accepted = call_create_thread(
            &mut env,
            &mut emu,
            CreateThreadArgs {
                creation_flags_slot: 0xffff_ffff_0000_0000,
                ..CreateThreadArgs::default()
            },
            rsp,
            return_address,
        )
        .unwrap();
        assert_eq!(accepted, KERNEL_HANDLE_BASE);
        assert_eq!(env.created_threads.get(&2).unwrap().creation_flags, 0);
    }

    #[test]
    fn create_thread_id_allocator_supports_last_valid_and_fails_atomically() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let output = wide_buffer_address();
        emu.map_zeroed_rw(output, u64::from(PAGE_SIZE)).unwrap();
        let rsp = crate::emu::STACK_BASE + 0x600;
        let return_address = 0x1234_5678_9abc_def0;
        let args = CreateThreadArgs {
            thread_id_output: output,
            ..CreateThreadArgs::default()
        };

        env.next_thread_id = u64::from(u32::MAX);
        assert_eq!(
            call_create_thread(&mut env, &mut emu, args, rsp, return_address).unwrap(),
            KERNEL_HANDLE_BASE
        );
        assert_eq!(read_u32_emu(&emu, output), u32::MAX);
        assert_eq!(env.next_thread_id, CREATED_THREAD_ID_EXHAUSTED);
        assert!(env.created_threads.contains_key(&u32::MAX));

        for rejected_cursor in [
            0,
            1,
            CREATED_THREAD_ID_EXHAUSTED,
            CREATED_THREAD_ID_EXHAUSTED + 1,
            u64::MAX,
            u64::from(u32::MAX),
        ] {
            env.next_thread_id = rejected_cursor;
            emu.write_mem(output, &0x7856_3412u32.to_le_bytes())
                .unwrap();
            let state_before = thread_allocator_state(&env);
            assert_eq!(
                call_create_thread(&mut env, &mut emu, args, rsp, return_address).unwrap(),
                0
            );
            assert_eq!(thread_allocator_state(&env), state_before);
            assert_eq!(read_u32_emu(&emu, output), 0x7856_3412);
        }
    }

    #[test]
    fn create_thread_handle_allocator_supports_last_valid_and_fails_atomically() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let output = wide_buffer_address();
        emu.map_zeroed_rw(output, u64::from(PAGE_SIZE)).unwrap();
        let rsp = crate::emu::STACK_BASE + 0x600;
        let return_address = 0x1234_5678_9abc_def0;
        let args = CreateThreadArgs {
            thread_id_output: output,
            ..CreateThreadArgs::default()
        };
        let last_handle = HEAP_ARENA_BASE - KERNEL_HANDLE_STRIDE;

        env.next_kernel_handle = last_handle;
        assert_eq!(
            call_create_thread(&mut env, &mut emu, args, rsp, return_address).unwrap(),
            last_handle
        );
        assert_eq!(read_u32_emu(&emu, output), 2);
        assert_eq!(env.next_kernel_handle, HEAP_ARENA_BASE);
        assert_eq!(env.next_thread_id, 3);

        for rejected_cursor in [
            HEAP_ARENA_BASE,
            KERNEL_HANDLE_BASE - KERNEL_HANDLE_STRIDE,
            KERNEL_HANDLE_BASE + 1,
            u64::MAX,
            last_handle,
        ] {
            env.next_kernel_handle = rejected_cursor;
            emu.write_mem(output, &0x7856_3412u32.to_le_bytes())
                .unwrap();
            let state_before = thread_allocator_state(&env);
            assert_eq!(
                call_create_thread(&mut env, &mut emu, args, rsp, return_address).unwrap(),
                0
            );
            assert_eq!(thread_allocator_state(&env), state_before);
            assert_eq!(read_u32_emu(&emu, output), 0x7856_3412);
        }
    }

    #[test]
    fn create_thread_state_is_deterministic_and_isolated_per_environment() {
        let mut first_emu = Emu::new().unwrap();
        let mut first_env = Win64Env::new(IMAGE_BASE);
        let mut second_emu = Emu::new().unwrap();
        let mut second_env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x600;
        let return_address = 0x1234_5678_9abc_def0;
        let first_args = CreateThreadArgs {
            start_address: 0x1111_2222_3333_4444,
            parameter: 0xaaaa_bbbb_cccc_dddd,
            ..CreateThreadArgs::default()
        };
        let second_args = CreateThreadArgs {
            start_address: 0x5555_6666_7777_8888,
            parameter: 0xeeee_ffff_0000_1111,
            ..CreateThreadArgs::default()
        };

        let first = call_create_thread(
            &mut first_env,
            &mut first_emu,
            first_args,
            rsp,
            return_address,
        )
        .unwrap();
        let second = call_create_thread(
            &mut second_env,
            &mut second_emu,
            second_args,
            rsp,
            return_address,
        )
        .unwrap();

        assert_eq!(first, KERNEL_HANDLE_BASE);
        assert_eq!(second, KERNEL_HANDLE_BASE);
        assert_eq!(first_env.next_thread_id, 3);
        assert_eq!(second_env.next_thread_id, 3);
        assert_eq!(
            first_env.created_threads.get(&2).unwrap().start_address,
            first_args.start_address
        );
        assert_eq!(
            second_env.created_threads.get(&2).unwrap().start_address,
            second_args.start_address
        );
        assert_eq!(
            first_env.created_threads.get(&2).unwrap().parameter,
            first_args.parameter
        );
        assert_eq!(
            second_env.created_threads.get(&2).unwrap().parameter,
            second_args.parameter
        );
    }

    #[test]
    fn create_thread_stack_argument_read_errors_precede_all_mutations() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let stack_end = crate::emu::STACK_BASE + crate::emu::STACK_SIZE;
        let return_address = 0x1234_5678_9abc_def0u64;
        let initial_rax = 0xaaaa_bbbb_cccc_dddd;
        let initial_rip = 0x1111_2222_3333_4444;
        let initial_state = thread_allocator_state(&env);

        for (rsp, arg5_is_mapped, expected_read_size) in
            [(stack_end - 0x28, false, 4), (stack_end - 0x30, true, 8)]
        {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            if arg5_is_mapped {
                emu.write_mem(rsp + 0x28, &0u64.to_le_bytes()).unwrap();
            }
            emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
            emu.write_reg(RegisterX86::RCX, 0).unwrap();
            emu.write_reg(RegisterX86::RDX, 0).unwrap();
            emu.write_reg(RegisterX86::R8, 0).unwrap();
            emu.write_reg(RegisterX86::R9, 0).unwrap();
            emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();

            assert!(matches!(
                dispatch(&mut env, &mut emu, "CreateThread"),
                Err(EmuError::ReadMem { addr, size, .. })
                    if addr == stack_end && size == expected_read_size
            ));
            assert_eq!(thread_allocator_state(&env), initial_state);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
        }

        for (rsp, expected_size) in [(u64::MAX - 0x27, 0x28), (u64::MAX - 0x2f, 0x30)] {
            emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
            emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();
            assert!(matches!(
                dispatch(&mut env, &mut emu, "CreateThread"),
                Err(EmuError::AddressRangeOverflow { base, size })
                    if base == rsp && size == expected_size
            ));
            assert_eq!(thread_allocator_state(&env), initial_state);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
        }

        for (rsp, expected_base, expected_size) in [
            (u64::MAX - 0x28, u64::MAX, 4),
            (u64::MAX - 0x36, u64::MAX - 6, 8),
        ] {
            emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
            emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();
            assert!(matches!(
                dispatch(&mut env, &mut emu, "CreateThread"),
                Err(EmuError::AddressRangeOverflow { base, size })
                    if base == expected_base && size == expected_size
            ));
            assert_eq!(thread_allocator_state(&env), initial_state);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
        }
    }

    #[test]
    fn create_thread_invalid_output_errors_are_failure_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x600;
        let return_address = 0x1234_5678_9abc_def0;
        let initial_rax = 0xaaaa_bbbb_cccc_dddd;
        let initial_rip = 0x1111_2222_3333_4444;
        let unmapped_output = 0x0000_0000_dead_0000;
        let readonly_output = wide_buffer_address();
        emu.map_readonly(readonly_output, &[0x5a; 4]).unwrap();
        let stack_end = crate::emu::STACK_BASE + crate::emu::STACK_SIZE;
        let crossing_output = stack_end - 2;
        emu.write_mem(crossing_output, &[0xab, 0xcd]).unwrap();
        let initial_state = thread_allocator_state(&env);

        for output in [
            unmapped_output,
            readonly_output,
            crossing_output,
            u64::MAX - 2,
        ] {
            let error = call_create_thread(
                &mut env,
                &mut emu,
                CreateThreadArgs {
                    thread_id_output: output,
                    ..CreateThreadArgs::default()
                },
                rsp,
                return_address,
            )
            .unwrap_err();
            assert!(match output {
                value if value == unmapped_output => matches!(
                    error,
                    EmuError::WriteUnmapped { addr, size: 4 } if addr == unmapped_output
                ),
                value if value == readonly_output => matches!(
                    error,
                    EmuError::WriteProt { addr, size: 4 } if addr == readonly_output
                ),
                value if value == crossing_output => matches!(
                    error,
                    EmuError::WriteUnmapped { addr, size: 4 } if addr == stack_end
                ),
                _ => matches!(
                    error,
                    EmuError::AddressRangeOverflow { base, size: 4 } if base == u64::MAX - 2
                ),
            });
            assert_eq!(thread_allocator_state(&env), initial_state);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
            assert_eq!(emu.read_mem(readonly_output, 4).unwrap(), vec![0x5a; 4]);
            assert_eq!(emu.read_mem(crossing_output, 2).unwrap(), vec![0xab, 0xcd]);
        }
    }

    #[test]
    fn rtl_allocate_heap_handles_observed_zeroed_page_request() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;

        let allocation = call_rtl_allocate_heap(
            &mut env,
            &mut emu,
            process_heap,
            u64::from(HEAP_ZERO_MEMORY),
            0x1000,
        );

        assert_eq!(allocation, HEAP_ARENA_BASE);
        assert_ne!(allocation, 0);
        assert!(allocation.is_multiple_of(HEAP_ALIGNMENT));
        assert_eq!(emu.read_mem(allocation, 16).unwrap(), vec![0; 16]);
        assert_eq!(
            emu.read_mem(allocation + u64::from(PAGE_SIZE) - 16, 16)
                .unwrap(),
            vec![0; 16]
        );
        emu.write_mem(allocation, &[1, 2, 3, 4]).unwrap();
        assert_eq!(emu.read_mem(allocation, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(
            env.heap_allocations.get(&allocation),
            Some(&HeapAllocation {
                requested_size: 0x1000,
                mapped_size: u64::from(PAGE_SIZE),
            })
        );
        assert_eq!(env.heap_cursor, HEAP_ARENA_BASE + u64::from(PAGE_SIZE));
    }

    #[test]
    fn rtl_allocate_heap_returns_distinct_nonoverlapping_blocks() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;

        let first = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, 17);
        let marker = [0xa5; 17];
        emu.write_mem(first, &marker).unwrap();

        let second = call_rtl_allocate_heap(
            &mut env,
            &mut emu,
            process_heap,
            u64::from(HEAP_NO_SERIALIZE),
            u64::from(PAGE_SIZE) + 1,
        );
        let third = call_rtl_allocate_heap(
            &mut env,
            &mut emu,
            process_heap,
            0xa5a5_5a5a_0000_0000 | u64::from(HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY),
            32,
        );

        let first_size = env.heap_allocations[&first].mapped_size;
        let second_size = env.heap_allocations[&second].mapped_size;
        assert!(first + first_size <= second);
        assert!(second + second_size <= third);
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_eq!(emu.read_mem(first, marker.len()).unwrap(), marker);
        assert_eq!(emu.read_mem(third, 16).unwrap(), vec![0; 16]);
    }

    #[test]
    fn rtl_allocate_heap_rejects_invalid_heap_handle_without_state_change() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let invalid_heap = env.process_heap + 1;
        let cursor = env.heap_cursor;
        let allocations = env.heap_allocations.clone();

        let ret = call_rtl_allocate_heap(
            &mut env,
            &mut emu,
            invalid_heap,
            u64::from(HEAP_ZERO_MEMORY),
            0x1000,
        );

        assert_eq!(ret, 0);
        assert_eq!(env.heap_cursor, cursor);
        assert_eq!(env.heap_allocations, allocations);
        assert!(emu.read_mem(HEAP_ARENA_BASE, 1).is_err());
    }

    #[test]
    fn rtl_allocate_heap_rejects_unsupported_flags_without_state_change() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let cursor = env.heap_cursor;
        let allocations = env.heap_allocations.clone();

        let ret = call_rtl_allocate_heap(
            &mut env,
            &mut emu,
            process_heap,
            u64::from(HEAP_ZERO_MEMORY | 0x2),
            0x1000,
        );

        assert_eq!(ret, 0);
        assert_eq!(env.heap_cursor, cursor);
        assert_eq!(env.heap_allocations, allocations);
        assert!(emu.read_mem(HEAP_ARENA_BASE, 1).is_err());
    }

    #[test]
    fn rtl_allocate_heap_reports_size_failures_without_state_change() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let initial_cursor = env.heap_cursor;
        let initial_allocations = env.heap_allocations.clone();

        let oversized =
            call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, HEAP_ARENA_SIZE + 1);
        assert_eq!(oversized, 0);
        assert_eq!(env.heap_cursor, initial_cursor);
        assert_eq!(env.heap_allocations, initial_allocations);

        let overflowed = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, u64::MAX);
        assert_eq!(overflowed, 0);
        assert_eq!(env.heap_cursor, initial_cursor);
        assert_eq!(env.heap_allocations, initial_allocations);

        let page_size = u64::from(PAGE_SIZE);
        env.heap_cursor = HEAP_ARENA_BASE + HEAP_ARENA_SIZE - page_size;
        let exhausted_cursor = env.heap_cursor;
        let exhausted_allocations = env.heap_allocations.clone();
        let exhausted = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, page_size + 1);
        assert_eq!(exhausted, 0);
        assert_eq!(env.heap_cursor, exhausted_cursor);
        assert_eq!(env.heap_allocations, exhausted_allocations);
        assert!(emu.read_mem(exhausted_cursor, 1).is_err());
    }

    #[test]
    fn rtl_allocate_heap_zero_size_returns_unique_minimum_blocks() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;

        let first = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, 0);
        let second = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, 0);

        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);
        assert_eq!(env.heap_allocations[&first].requested_size, 0);
        assert_eq!(
            env.heap_allocations[&first].mapped_size,
            u64::from(PAGE_SIZE)
        );
        assert_eq!(env.heap_allocations[&second].requested_size, 0);
        assert_eq!(
            env.heap_allocations[&second].mapped_size,
            u64::from(PAGE_SIZE)
        );
        assert_eq!(emu.read_mem(first, 1).unwrap(), vec![0]);
        assert_eq!(emu.read_mem(second, 1).unwrap(), vec![0]);
    }

    #[test]
    fn trap_dispatches_get_process_heap_via_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_kernel32(&mut emu).unwrap();
        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let stub = module.export_stub("GetProcessHeap").unwrap();
        let expected_handle = env.process_heap;
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetProcessHeap".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_ne!(expected_handle, 0);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected_handle);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            image.entry_point_va() + 12
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_get_current_thread_id_via_name_resolved_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_kernel32(&mut emu).unwrap();
        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let stub = module.export_stub("GetCurrentThreadId").unwrap();
        let expected_id = u64::from(env.current_thread_id);
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetCurrentThreadId".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(expected_id, 1);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected_id);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            image.entry_point_va() + 12
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_get_version_via_name_resolved_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("GetVersion")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "GetVersion")
            .unwrap();
        assert_eq!(stub, export_stub);
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetVersion".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            u64::from(EMULATED_WINDOWS_VERSION)
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_name_resolved_kernel32_sleep_with_shadow_space() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("Sleep")
            .unwrap();
        let stub = env.resolve_proc(&mut emu, kernel32_base, "Sleep").unwrap();
        assert_eq!(stub, export_stub);
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let interval = 0xa5a5_5a5a_0000_0002_u64;
        let rax_sentinel = 0xaaaa_bbbb_cccc_dddd_u64;

        let mut code = Vec::new();
        // Reserve the Win64 caller shadow area and balance it after the call.
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&interval.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&rax_sentinel.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xbb]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xff, 0xd3]);
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();
        let environment_before = sleep_environment_state(&env);

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), rax_sentinel);
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), interval);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(sleep_environment_state(&env), environment_before);
    }

    #[test]
    fn synthetic_user32_export_traps_load_cursor_a() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let user32_base = env.ensure_loaded_module(&mut emu, "user32.dll").unwrap();
        let module = env.synthetic_modules.get("user32.dll").unwrap();
        assert_eq!(
            module
                .exports
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["LoadCursorA", "RegisterClassExA"]
        );
        let stub = module.export_stub("LoadCursorA").unwrap();
        assert_eq!(
            env.callable_stub_name_at(stub).as_deref(),
            Some("LoadCursorA")
        );
        assert_eq!(
            env.resolve_proc(&mut emu, user32_base, "LoadCursorA")
                .unwrap(),
            stub
        );
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        // Reserve the Win64 caller shadow area and balance it after the call.
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
        code.extend_from_slice(&[0x31, 0xc9]);
        code.push(0xba);
        code.extend_from_slice(&(PREDEFINED_HAND_CURSOR_ID as u32).to_le_bytes());
        code.extend_from_slice(&[0x49, 0xbb]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xff, 0xd3]);
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["LoadCursorA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            EMULATED_HAND_CURSOR_HANDLE
        );
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RDX).unwrap(),
            PREDEFINED_HAND_CURSOR_ID
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn synthetic_user32_export_traps_register_class_ex_a() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let user32_base = env.ensure_loaded_module(&mut emu, "user32.dll").unwrap();
        let module = env.synthetic_modules.get("user32.dll").unwrap();
        let stub = module.export_stub("RegisterClassExA").unwrap();
        assert_eq!(
            env.callable_stub_name_at(stub).as_deref(),
            Some("RegisterClassExA")
        );
        assert_eq!(
            env.resolve_proc(&mut emu, user32_base, "RegisterClassExA")
                .unwrap(),
            stub
        );

        let args = RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS);
        emu.write_mem(WINDOW_CLASS_STRUCT_ADDRESS, &args.as_bytes())
            .unwrap();
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"MidasTestClass\0")
            .unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        // Reserve the Win64 caller shadow area and balance it after the call.
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&WINDOW_CLASS_STRUCT_ADDRESS.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xbb]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xff, 0xd3]);
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["RegisterClassExA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            u64::from(WINDOW_CLASS_ATOM_BASE)
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RCX).unwrap(),
            WINDOW_CLASS_STRUCT_ADDRESS
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        let registration = env
            .window_classes_by_atom
            .get(&(WINDOW_CLASS_ATOM_BASE as u16))
            .unwrap();
        assert_eq!(registration.class_name, "MidasTestClass");
        assert_eq!(registration.instance, IMAGE_BASE);
        assert_eq!(
            env.window_class_atoms_by_name
                .get(&(IMAGE_BASE, "midastestclass".to_owned())),
            Some(&(WINDOW_CLASS_ATOM_BASE as u16))
        );
    }

    #[test]
    fn trap_dispatches_get_current_directory_w_via_name_resolved_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("GetCurrentDirectoryW")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "GetCurrentDirectoryW")
            .unwrap();
        assert_eq!(stub, export_stub);

        let buffer = wide_buffer_address();
        assert!(u32::try_from(buffer).is_err());
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(buffer, &[0xa5; 16]).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&0xffff_ffff_0000_0004_u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&buffer.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetCurrentDirectoryW".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 3);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(
            emu.read_mem(buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
    }

    #[test]
    fn trap_dispatches_set_current_directory_w_via_name_resolved_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("SetCurrentDirectoryW")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "SetCurrentDirectoryW")
            .unwrap();
        assert_eq!(stub, export_stub);

        let buffer = wide_buffer_address();
        assert!(u32::try_from(buffer).is_err());
        emu.map_zeroed_rw(buffer, u64::from(PAGE_SIZE)).unwrap();
        let path = utf16le_with_nul(&[0x43, 0x3a]).unwrap();
        emu.write_mem(buffer, &path).unwrap();
        let input_before = emu.read_mem(buffer, path.len()).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&buffer.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["SetCurrentDirectoryW".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(emu.read_mem(buffer, path.len()).unwrap(), input_before);

        let current_directory_buffer = buffer + 0x100;
        let current_ret = call_get_current_directory_w(
            &mut env,
            &mut emu,
            4,
            current_directory_buffer,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        assert_eq!(current_ret, 3);
        assert_eq!(
            emu.read_mem(current_directory_buffer, CURRENT_DIRECTORY_W_BYTES.len())
                .unwrap(),
            CURRENT_DIRECTORY_W_BYTES
        );
        assert_eq!(emu.read_mem(buffer, path.len()).unwrap(), input_before);
    }

    #[test]
    fn trap_dispatches_name_resolved_kernel32_open_thread_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("OpenThread")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "OpenThread")
            .unwrap();
        assert_eq!(stub, export_stub);
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&u64::from(LEGACY_THREAD_ALL_ACCESS).to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&0u64.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xb8]);
        code.extend_from_slice(&1u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["OpenThread".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        let handle = emu.read_reg(RegisterX86::RAX).unwrap();
        assert_eq!(handle, KERNEL_HANDLE_BASE);
        assert_eq!(
            env.kernel_handles.get(&handle),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 1 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            })
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_name_resolved_kernel32_create_thread_stub_with_balanced_stack() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let export_stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("CreateThread")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "CreateThread")
            .unwrap();
        assert_eq!(stub, export_stub);
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let output = wide_buffer_address();
        emu.map_zeroed_rw(output, u64::from(PAGE_SIZE)).unwrap();
        let start_address = 0x7654_3210_fedc_ba98u64;
        let parameter = 0x8000_0001_0000_0002u64;

        let mut code = Vec::new();
        // Reserve the Win64 shadow area plus the two stack-argument slots.
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x30]);
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&0u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&0u64.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xb8]);
        code.extend_from_slice(&start_address.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xb9]);
        code.extend_from_slice(&parameter.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xba]);
        code.extend_from_slice(&0xffff_ffff_0000_0000u64.to_le_bytes());
        code.extend_from_slice(&[0x4c, 0x89, 0x54, 0x24, 0x20]);
        code.extend_from_slice(&[0x49, 0xbb]);
        code.extend_from_slice(&output.to_le_bytes());
        code.extend_from_slice(&[0x4c, 0x89, 0x5c, 0x24, 0x28]);
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x30]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["CreateThread".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(read_u32_emu(&emu, output), 2);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), KERNEL_HANDLE_BASE);
        assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), start_address);
        assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), parameter);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(
            env.created_threads.get(&2),
            Some(&RunnableUnscheduledThread {
                start_address,
                parameter,
                requested_stack_size: 0,
                creation_flags: 0,
            })
        );
        assert_eq!(
            env.kernel_handles.get(&KERNEL_HANDLE_BASE),
            Some(&KernelHandle {
                object: KernelObject::Thread { thread_id: 2 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            })
        );
        // The record is pending/runnable but unscheduled: no scheduler, guest
        // stack/TEB, callback execution, lifecycle, signaling, wait, close,
        // ACL/token, or last-error behavior is modeled.
    }

    #[test]
    fn trap_dispatches_get_user_default_ui_language_via_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let stub =
            kernel32_base + u64::from(*module.exports.get("GetUserDefaultUILanguage").unwrap());
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetUserDefaultUILanguage".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            u64::from(EMULATED_USER_DEFAULT_UI_LANGID)
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            image.entry_point_va() + 12
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn rtl_initialize_critical_section_initializes_layout_and_returns() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let critical_section = crate::emu::STACK_BASE + 0x300;
        let rsp = crate::emu::STACK_BASE + 0x400;
        emu.write_mem(critical_section, &[0xa5; 40]).unwrap();
        let return_address: u64 = 0x1234_5678_9abc_def0;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, critical_section).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let outcome = dispatch(&mut env, &mut emu, "RtlInitializeCriticalSection").unwrap();
        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "RtlInitializeCriticalSection".to_owned(),
                ret: 0,
            }
        );
        let mut expected = [0u8; 40];
        expected[8..12].copy_from_slice(&(-1i32).to_le_bytes());
        assert_eq!(emu.read_mem(critical_section, 40).unwrap(), expected);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn trap_dispatches_ntdll_critical_section_initialization() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let ntdll_base = env.ensure_loaded_module(&mut emu, "ntdll.dll").unwrap();
        let module = env.synthetic_modules.get("ntdll.dll").unwrap();
        let stub =
            ntdll_base + u64::from(*module.exports.get("RtlInitializeCriticalSection").unwrap());
        let critical_section = crate::emu::STACK_BASE + 0x300;
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        emu.write_mem(critical_section, &[0xa5; 40]).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&critical_section.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(
            result.handled,
            vec!["RtlInitializeCriticalSection".to_owned()]
        );
        assert_eq!(result.stop, TrapStop::InstructionCap);
        let mut expected = [0u8; 40];
        expected[8..12].copy_from_slice(&(-1i32).to_le_bytes());
        assert_eq!(emu.read_mem(critical_section, 40).unwrap(), expected);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            image.entry_point_va() + 22
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_name_resolved_ntdll_rtl_add_vectored_exception_handler_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let ntdll_base = env.ensure_loaded_module(&mut emu, "ntdll.dll").unwrap();
        let export_stub = env
            .synthetic_modules
            .get("ntdll.dll")
            .unwrap()
            .export_stub("RtlAddVectoredExceptionHandler")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, ntdll_base, "RtlAddVectoredExceptionHandler")
            .unwrap();
        assert_eq!(stub, export_stub);

        let observed_handler = 0x0000_0001_4006_aa83u64;
        assert!(emu.read_mem(observed_handler, 1).is_err());
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&1u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&observed_handler.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(
            result.handled,
            vec!["RtlAddVectoredExceptionHandler".to_owned()]
        );
        assert_eq!(result.stop, TrapStop::InstructionCap);
        let token = emu.read_reg(RegisterX86::RAX).unwrap();
        assert_eq!(token, VECTORED_EXCEPTION_HANDLER_TOKEN_BASE);
        assert!(token > u64::from(u32::MAX));
        assert!(emu.read_mem(token, 1).is_err());
        assert!(emu.read_mem(observed_handler, 1).is_err());
        assert_eq!(
            env.vectored_exception_handlers,
            vec![VectoredExceptionHandlerRegistration {
                token,
                handler: observed_handler,
            }]
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_name_resolved_ntdll_rtl_allocate_heap_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let ntdll_base = env.ensure_loaded_module(&mut emu, "ntdll.dll").unwrap();
        let export_stub = env
            .synthetic_modules
            .get("ntdll.dll")
            .unwrap()
            .export_stub("RtlAllocateHeap")
            .unwrap();
        let stub = env
            .resolve_proc(&mut emu, ntdll_base, "RtlAllocateHeap")
            .unwrap();
        assert_eq!(stub, export_stub);

        let process_heap = env.process_heap;
        let requested_size = 0x30u64;
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&process_heap.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]);
        code.extend_from_slice(&u64::from(HEAP_ZERO_MEMORY).to_le_bytes());
        code.extend_from_slice(&[0x49, 0xb8]);
        code.extend_from_slice(&requested_size.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["RtlAllocateHeap".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        let allocation = emu.read_reg(RegisterX86::RAX).unwrap();
        assert_ne!(allocation, 0);
        assert_eq!(
            env.heap_allocations.get(&allocation),
            Some(&HeapAllocation {
                requested_size,
                mapped_size: u64::from(PAGE_SIZE),
            })
        );
        assert_eq!(
            emu.read_mem(allocation, requested_size as usize).unwrap(),
            vec![0; requested_size as usize]
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn synthetic_kernel32_stub_region_is_readable() {
        let mut emu = Emu::new().unwrap();
        let module =
            SyntheticModule::build(FAKE_MODULE_BASE_START, "kernel32.dll", KERNEL32_EXPORTS);
        let stub_rva = *module.exports.get("VirtualAlloc").unwrap();
        let stub_addr = module.base + u64::from(stub_rva);
        module.map_into(&mut emu).unwrap();

        assert_eq!(emu.read_mem(stub_addr, 16).unwrap(), vec![0u8; 16]);
    }

    #[test]
    fn getmodulehandlea_maps_kernel32_and_exposes_e_lfanew() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        map_module_name(&mut emu);

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        let ApiOutcome::Handled { ret, .. } = outcome else {
            panic!("expected GetModuleHandleA to be handled");
        };

        assert_ne!(ret, 0);
        assert_eq!(read_u32_emu(&emu, ret + 0x3c), 0x80);
    }

    #[test]
    fn getmodulehandlea_extensionless_mixed_case_kernel32_maps_and_reuses() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut data = vec![0u8; 0x1000];
        data[..b"KeRnEl32\0".len()].copy_from_slice(b"KeRnEl32\0");
        data[0x100..0x100 + b"kErNeL32\0".len()].copy_from_slice(b"kErNeL32\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let first = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        let ApiOutcome::Handled {
            ret: first_base, ..
        } = first
        else {
            panic!("expected GetModuleHandleA to be handled");
        };
        assert_ne!(first_base, 0);
        assert!(env.synthetic_modules.contains_key("kernel32.dll"));
        assert_eq!(env.synthetic_modules["kernel32.dll"].base, first_base);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), stack_address + 8);

        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA) + 0x100)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let second = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "GetModuleHandleA".to_owned(),
                ret: first_base,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), first_base);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), stack_address + 8);
        assert_eq!(env.synthetic_modules.len(), 1);
    }

    #[test]
    fn getmodulehandlea_null_returns_image_base() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "GetModuleHandleA".to_owned(),
                ret: IMAGE_BASE
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), IMAGE_BASE);
    }

    #[test]
    fn stub_name_reverse_maps_resolved_export() {
        let module =
            SyntheticModule::build(FAKE_MODULE_BASE_START, "kernel32.dll", KERNEL32_EXPORTS);
        let rva = *module.exports.get("VirtualAlloc").unwrap();

        assert_eq!(
            module.stub_name(module.base + u64::from(rva)),
            Some("VirtualAlloc")
        );
        assert_eq!(module.stub_name(module.base + 0x1234), None);
    }

    #[test]
    fn callable_stub_name_projection_covers_seeded_and_dynamic_stubs() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let seeded = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("Sleep")
            .unwrap();
        let dynamic = env
            .resolve_proc(&mut emu, kernel32, "DiagnosticOnlyName")
            .unwrap();

        assert_eq!(env.callable_stub_name_at(seeded).as_deref(), Some("Sleep"));
        assert_eq!(
            env.callable_stub_name_at(dynamic).as_deref(),
            Some("DiagnosticOnlyName")
        );
        assert_eq!(env.callable_stub_name_at(IMAGE_BASE), None);
    }

    #[test]
    fn synthetic_kernel32_stub_region_clears_large_export_table() {
        let names = (0..2000)
            .map(|index| format!("Func{index:04}"))
            .collect::<Vec<_>>();
        let exports = names.iter().map(String::as_str).collect::<Vec<_>>();
        let module = SyntheticModule::build(FAKE_MODULE_BASE_START, "kernel32.dll", &exports);

        let pe_offset = u32::from_le_bytes([
            module.image[0x3c],
            module.image[0x3d],
            module.image[0x3e],
            module.image[0x3f],
        ]) as usize;
        let optional_header = pe_offset + 24;
        let export_dir_rva = u32::from_le_bytes([
            module.image[optional_header + 112],
            module.image[optional_header + 113],
            module.image[optional_header + 114],
            module.image[optional_header + 115],
        ]);
        let export_area_size = u32::from_le_bytes([
            module.image[optional_header + 116],
            module.image[optional_header + 117],
            module.image[optional_header + 118],
            module.image[optional_header + 119],
        ]);
        let export_data_end = export_dir_rva + export_area_size;

        assert!(module.stub_region_rva >= export_data_end);
        assert!(module.image.len() <= module.stub_region_rva as usize);

        let first_rva = *module.exports.get("Func0000").unwrap();
        let last_rva = *module.exports.get("Func1999").unwrap();
        assert_eq!(
            module.stub_name(module.base + u64::from(first_rva)),
            Some("Func0000")
        );
        assert_eq!(
            module.stub_name(module.base + u64::from(last_rva)),
            Some("Func1999")
        );
        assert_eq!(
            module.stub_name(module.base + u64::from(module.stub_region_rva - 1)),
            None
        );
    }

    #[test]
    fn getmodulehandlea_returns_nonnull_and_returns() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        map_module_name(&mut emu);

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        let ApiOutcome::Handled { ret, .. } = outcome else {
            panic!("expected GetModuleHandleA to be handled");
        };

        assert_ne!(ret, 0);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), stack_address + 8);
    }

    #[test]
    fn getmodulehandlea_unknown_module_returns_null_and_returns() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut data = vec![0u8; 0x1000];
        data[..b"user32.dll\0".len()].copy_from_slice(b"user32.dll\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "GetModuleHandleA".to_owned(),
                ret: 0
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), stack_address + 8);
    }

    #[test]
    fn loadlibrarya_kernel32_returns_synthetic_base_and_returns() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        map_module_name(&mut emu);

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        let ApiOutcome::Handled { ret, .. } = outcome else {
            panic!("expected LoadLibraryA to be handled");
        };

        assert_ne!(ret, 0);
        assert_eq!(read_u32_emu(&emu, ret + 0x3c), 0x80);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), stack_address + 8);
    }

    #[test]
    fn loadlibrarya_maps_parseable_module_for_new_dll() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut data = vec![0u8; 0x1000];
        data[..b"somelib.dll\0".len()].copy_from_slice(b"somelib.dll\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        let ApiOutcome::Handled { ret, .. } = outcome else {
            panic!("expected LoadLibraryA to be handled");
        };

        assert_ne!(ret, 0);
        assert_eq!(read_u32_emu(&emu, ret + 0x3c), 0x80);
        let export_dir = ret + u64::from(SYNTHETIC_EXPORT_DIR_RVA);
        assert_eq!(read_u32_emu(&emu, export_dir + 20), 0);
        assert_eq!(read_u32_emu(&emu, export_dir + 24), 0);
    }

    #[test]
    fn loadlibrarya_null_returns_zero() {
        // LoadLibrary(NULL) is a failed load (returns 0), NOT the image base —
        // that is GetModuleHandle(NULL)'s semantics, not LoadLibrary's.
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();

        let outcome = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "LoadLibraryA".to_owned(),
                ret: 0
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), stack_address + 8);
    }

    #[test]
    fn loadlibrarya_allocates_consistent_handle_and_getmodulehandle_finds_it() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut data = vec![0u8; 0x1000];
        data[..b"user32.dll\0".len()].copy_from_slice(b"user32.dll\0");
        data[0x80..0x80 + b"gdi32.dll\0".len()].copy_from_slice(b"gdi32.dll\0");
        // Same module as the load above, different casing: the registry keys on
        // the lowercased name, so this must resolve to the same handle.
        data[0x100..0x100 + b"USER32.DLL\0".len()].copy_from_slice(b"USER32.DLL\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();

        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let first = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        let ApiOutcome::Handled {
            ret: user32_base, ..
        } = first
        else {
            panic!("expected LoadLibraryA to be handled");
        };
        assert_ne!(user32_base, 0);

        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let second = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "LoadLibraryA".to_owned(),
                ret: user32_base
            }
        );

        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let found = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        assert_eq!(
            found,
            ApiOutcome::Handled {
                name: "GetModuleHandleA".to_owned(),
                ret: user32_base
            }
        );

        // Case-insensitive handle reuse: "USER32.DLL" resolves to the handle
        // allocated for the lowercased "user32.dll" load above.
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA) + 0x100)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let found_mixed_case = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        assert_eq!(
            found_mixed_case,
            ApiOutcome::Handled {
                name: "GetModuleHandleA".to_owned(),
                ret: user32_base
            }
        );

        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA) + 0x80)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let missing = dispatch(&mut env, &mut emu, "GetModuleHandleA").unwrap();
        assert_eq!(
            missing,
            ApiOutcome::Handled {
                name: "GetModuleHandleA".to_owned(),
                ret: 0
            }
        );
    }

    #[test]
    fn getprocaddress_resolves_named_export_to_callable_stub() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();

        let mut data = vec![0u8; 0x1000];
        data[..b"SetLastError\0".len()].copy_from_slice(b"SetLastError\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();

        emu.write_reg(RegisterX86::RCX, kernel32_base).unwrap();
        emu.write_reg(RegisterX86::RDX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let first = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        let ApiOutcome::Handled { ret, .. } = first else {
            panic!("expected GetProcAddress to be handled");
        };

        assert_ne!(ret, 0);
        assert!((PROC_STUB_BASE..FAKE_MODULE_BASE_START).contains(&ret));
        assert!(emu.read_mem(ret, PROC_STUB_STRIDE as usize).is_ok());

        emu.write_reg(RegisterX86::RCX, kernel32_base).unwrap();
        emu.write_reg(RegisterX86::RDX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let second = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        assert_eq!(
            second,
            ApiOutcome::Handled {
                name: "GetProcAddress".to_owned(),
                ret
            }
        );
    }

    #[test]
    fn getprocaddress_reuses_existing_module_export_stub() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();

        let mut data = vec![0u8; 0x1000];
        data[..b"LoadLibraryA\0".len()].copy_from_slice(b"LoadLibraryA\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();

        emu.write_reg(RegisterX86::RCX, kernel32_base).unwrap();
        emu.write_reg(RegisterX86::RDX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let outcome = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        let ApiOutcome::Handled { ret, .. } = outcome else {
            panic!("expected GetProcAddress to be handled");
        };

        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let load_library_rva = *module.exports.get("LoadLibraryA").unwrap();
        let expected = kernel32_base + u64::from(load_library_rva);
        assert_eq!(ret, expected);
        assert!(env.proc_stubs.is_empty());
        assert_eq!(
            env.stub_export_at(ret),
            Some(("LoadLibraryA".to_owned(), load_library_rva))
        );
    }

    #[test]
    fn getprocaddress_ordinal_request_returns_zero() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();

        emu.write_reg(RegisterX86::RCX, kernel32_base).unwrap();
        emu.write_reg(RegisterX86::RDX, 1).unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let outcome = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();

        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "GetProcAddress".to_owned(),
                ret: 0
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
    }

    #[test]
    fn getprocaddress_invalid_module_and_empty_name_return_zero() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();

        let mut data = vec![0u8; 0x1000];
        data[..b"SetLastError\0".len()].copy_from_slice(b"SetLastError\0");
        // An empty (NUL-first) name at +0x80.
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let return_address = IMAGE_BASE + u64::from(CODE_RVA) + 0x80;
        let stack_address = IMAGE_BASE + u64::from(CODE_RVA);
        emu.map_code(stack_address, &return_address.to_le_bytes())
            .unwrap();

        // Bogus module handle (never a registered synthetic module): NULL result,
        // and no arena stub minted.
        emu.write_reg(RegisterX86::RCX, 0).unwrap();
        emu.write_reg(RegisterX86::RDX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let bogus = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        assert_eq!(
            bogus,
            ApiOutcome::Handled {
                name: "GetProcAddress".to_owned(),
                ret: 0
            }
        );
        assert!(env.proc_stubs.is_empty());

        // Valid module but an empty name string: NULL result.
        emu.write_reg(RegisterX86::RCX, kernel32_base).unwrap();
        emu.write_reg(RegisterX86::RDX, IMAGE_BASE + u64::from(DATA_RVA) + 0x80)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, stack_address).unwrap();
        let empty = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        assert_eq!(
            empty,
            ApiOutcome::Handled {
                name: "GetProcAddress".to_owned(),
                ret: 0
            }
        );
        assert!(env.proc_stubs.is_empty());
    }

    #[test]
    fn resolve_proc_distinct_names_span_pages_and_stay_mapped() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();

        // Resolve enough distinct names to cross the first arena page (256 slots of
        // 16 bytes = 0x1000): each gets a distinct, mapped, readable stub.
        let count = 260u32;
        let mut seen = std::collections::BTreeSet::new();
        for index in 0..count {
            let name = format!("Api{index:04}");
            let addr = env.resolve_proc(&mut emu, kernel32_base, &name).unwrap();
            assert_ne!(addr, 0);
            assert!((PROC_STUB_BASE..FAKE_MODULE_BASE_START).contains(&addr));
            assert!(emu.read_mem(addr, PROC_STUB_STRIDE as usize).is_ok());
            assert!(seen.insert(addr), "arena stub addresses must be distinct");
            // Reverse-map resolves back to the same name.
            assert_eq!(
                env.proc_stub_at(addr).map(|(name, _)| name),
                Some(name.clone())
            );
        }
        assert_eq!(seen.len(), count as usize);
        // A stub in the second arena page (index 256+) is mapped and readable.
        let second_page = env
            .resolve_proc(&mut emu, kernel32_base, "Api0256")
            .unwrap();
        assert!(second_page >= PROC_STUB_BASE + u64::from(PAGE_SIZE));
    }

    #[test]
    fn trap_handles_getmodulehandlea_end_to_end() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&(IMAGE_BASE + u64::from(DATA_RVA)).to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&u64::from(IMPORT_RVA).to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0xeb, 0xfe]);

        emu.map_code(image.entry_point_va(), &code).unwrap();
        map_import_name(&mut emu);
        map_module_name(&mut emu);

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetModuleHandleA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_ne!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(
            read_u64_le(
                &emu.read_mem(emu.read_reg(RegisterX86::RSP).unwrap() - 8, 8)
                    .unwrap()
            ),
            image.entry_point_va() + 22
        );
    }

    #[test]
    fn trap_reports_null_control_transfer_for_ret_to_zero() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        let code = [
            0x6a, 0x00, // push 0
            0xc3, // ret
        ];
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, Vec::<String>::new());
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
    }

    #[test]
    fn trap_reports_unhandled_kernel32_export_call_by_name() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_module(&mut emu, "kernel32.dll", KERNEL32_EXPORTS)
            .unwrap();
        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let virtual_alloc_rva = *module.exports.get("VirtualAlloc").unwrap();
        let virtual_alloc_addr = module.base + u64::from(virtual_alloc_rva);

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&(IMAGE_BASE + u64::from(DATA_RVA)).to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&u64::from(IMPORT_RVA).to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&virtual_alloc_addr.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0xeb, 0xfe]);

        emu.map_code(image.entry_point_va(), &code).unwrap();
        map_import_name(&mut emu);
        map_module_name(&mut emu);

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetModuleHandleA".to_owned()]);
        assert_eq!(
            result.stop,
            TrapStop::UnhandledApi {
                name: "VirtualAlloc".to_owned(),
                rva: virtual_alloc_rva
            }
        );
    }

    #[test]
    fn trap_dispatches_loadlibrarya_via_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        // Reserve kernel32's base through the registry (as the real
        // ensure_kernel32 path does), so the subsequent user32 load gets a
        // DISTINCT base instead of aliasing kernel32's.
        let kernel32_base = env.module_base("kernel32.dll");
        let module = SyntheticModule::build(kernel32_base, "kernel32.dll", KERNEL32_EXPORTS);
        let load_library_rva = *module.exports.get("LoadLibraryA").unwrap();
        let load_library_addr = module.base + u64::from(load_library_rva);
        module.map_into(&mut emu).unwrap();
        env.synthetic_modules
            .insert("kernel32.dll".to_owned(), module);

        let mut data = vec![0u8; 0x1000];
        data[..b"user32.dll\0".len()].copy_from_slice(b"user32.dll\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&(IMAGE_BASE + u64::from(DATA_RVA)).to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&load_library_addr.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0xeb, 0xfe]);

        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["LoadLibraryA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        // user32's handle must be non-null and distinct from kernel32's base.
        let user32_base = emu.read_reg(RegisterX86::RAX).unwrap();
        assert_ne!(user32_base, 0);
        assert_ne!(user32_base, kernel32_base);
    }

    #[test]
    fn trap_dispatches_dynamic_winmm_time_get_time_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut data = vec![0u8; 0x1000];
        data[..b"winmm.dll\0".len()].copy_from_slice(b"winmm.dll\0");
        data[0x40..0x40 + b"timeGetTime\0".len()].copy_from_slice(b"timeGetTime\0");
        emu.map_code(IMAGE_BASE + u64::from(DATA_RVA), &data)
            .unwrap();

        let direct_rsp = crate::emu::STACK_BASE + 0x400;
        let load_return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(direct_rsp, &load_return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, IMAGE_BASE + u64::from(DATA_RVA))
            .unwrap();
        emu.write_reg(RegisterX86::RSP, direct_rsp).unwrap();
        let load = dispatch(&mut env, &mut emu, "LoadLibraryA").unwrap();
        let ApiOutcome::Handled {
            ret: winmm_handle, ..
        } = load
        else {
            panic!("expected LoadLibraryA to be handled");
        };
        assert_ne!(winmm_handle, 0);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), winmm_handle);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), load_return_address);
        let winmm = env.synthetic_modules.get("winmm.dll").unwrap();
        assert_eq!(winmm.base, winmm_handle);
        assert!(winmm.exports.is_empty());
        assert!(winmm.stub_rva_to_name.is_empty());
        assert!(env.proc_stubs.is_empty());

        let get_proc_rsp = crate::emu::STACK_BASE + 0x500;
        let get_proc_return_address = 0x0fed_cba9_8765_4321_u64;
        emu.write_mem(get_proc_rsp, &get_proc_return_address.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, winmm_handle).unwrap();
        emu.write_reg(RegisterX86::RDX, IMAGE_BASE + u64::from(DATA_RVA) + 0x40)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, get_proc_rsp).unwrap();
        let get_proc = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        let ApiOutcome::Handled {
            ret: time_get_time_stub,
            ..
        } = get_proc
        else {
            panic!("expected GetProcAddress to be handled");
        };
        assert_ne!(time_get_time_stub, 0);
        assert_eq!(env.proc_stubs.get("timeGetTime"), Some(&time_get_time_stub));
        assert!(env.stub_export_at(time_get_time_stub).is_none());
        assert_eq!(
            env.proc_stub_at(time_get_time_stub).map(|(name, _)| name),
            Some("timeGetTime".to_owned())
        );

        let marker = 0xfeed_face_cafe_beef_u64;
        let mut code = Vec::new();
        // Enter with the Win64 function-entry alignment, reserve 32 bytes of
        // shadow space plus 8 bytes of alignment, call, then balance RSP.
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&time_get_time_stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
        code.extend_from_slice(&[0x49, 0xba]);
        code.extend_from_slice(&marker.to_le_bytes());
        code.extend_from_slice(&[0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let run_rsp = crate::emu::STACK_BASE + 0x808;
        assert_eq!(run_rsp & 0xf, 8);
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::R10, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, run_rsp).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["timeGetTime".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::R10).unwrap(), marker);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), run_rsp);
        assert_eq!(
            read_u64_le(&emu.read_mem(run_rsp - 0x30, 8).unwrap()),
            image.entry_point_va() + 16
        );
    }

    #[test]
    fn trap_dispatches_resolved_proc_stub_by_name() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .resolve_proc(&mut emu, kernel32_base, "SomeApi")
            .unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, Vec::<String>::new());
        assert_eq!(
            result.stop,
            TrapStop::UnhandledApi {
                name: "SomeApi".to_owned(),
                rva: (stub - PROC_STUB_BASE) as u32
            }
        );
    }

    #[test]
    fn trap_reports_unexpected_fault_for_non_stub_fetchprot() {
        // A FetchProt fault that is NOT a synthetic export stub must stop as
        // UnexpectedFault and must NOT be run through the in-image
        // import-by-name fallback (that path is FetchUnmapped-only). Here the
        // call target is a readable-but-non-executable page that is not part of
        // any mapped module, so calling it faults FetchProt at a non-stub
        // address.
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        // Non-stub, non-executable target: a read-only page distinct from the
        // entry code, with no synthetic module mapped.
        let target = IMAGE_BASE + u64::from(DATA_RVA);
        emu.map_readonly(target, &[0u8; 0x10]).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&target.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert!(env.synthetic_modules.is_empty());
        assert_eq!(result.handled, Vec::<String>::new());
        assert_eq!(result.stop, TrapStop::UnexpectedFault { address: target });
    }
}
