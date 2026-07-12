//! Minimal Win64 import-call trap and API stubs.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use crate::{
    emu::{
        Emu, EmuError, FaultKind, IndirectTransferObservation, PageProtection, RegisterX86,
        StopReason, PEB_BASE, STACK_BASE, STACK_SIZE, TEB_PEB_OFFSET, TEB_SELF_OFFSET, TEB_SIZE,
        TEB_STACKBASE_OFFSET, TEB_STACKLIMIT_OFFSET,
    },
    pe,
};

const IMPORT_NAME_CAP: usize = 256;
const SET_CURRENT_DIRECTORY_W_UNIT_CAP: usize = 260;
const WIDE_CHAR_TO_MULTI_BYTE_UNIT_CAP: usize = 260;
const WINDOW_CLASS_NAME_BYTE_CAP: usize = 256;
const REGISTRY_SUBKEY_BYTE_CAP: usize = 256;
const DIAGNOSTIC_EXPORT_NAME_CAP: usize = 4_096;
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
const VIRTUAL_ALLOCATION_GRANULARITY: u64 = 0x1_0000;
const VIRTUAL_ALLOCATION_ARENA_BASE: u64 = STACK_BASE + STACK_SIZE;
const VIRTUAL_ALLOCATION_ARENA_SIZE: u64 = 0x1000_0000;
const VIRTUAL_ALLOCATION_ARENA_END: u64 =
    VIRTUAL_ALLOCATION_ARENA_BASE + VIRTUAL_ALLOCATION_ARENA_SIZE;
const SID_ALLOCATION_ARENA_BASE: u64 = VIRTUAL_ALLOCATION_ARENA_END;
const SID_ALLOCATION_ARENA_SIZE: u64 = 0x0100_0000;
const SID_ALLOCATION_ARENA_END: u64 = SID_ALLOCATION_ARENA_BASE + SID_ALLOCATION_ARENA_SIZE;
const EXCEPTION_DISPATCH_ARENA_BASE: u64 = SID_ALLOCATION_ARENA_END;
const EXCEPTION_DISPATCH_ARENA_SIZE: u64 = 0x0100_0000;
const EXCEPTION_DISPATCH_ARENA_END: u64 =
    EXCEPTION_DISPATCH_ARENA_BASE + EXCEPTION_DISPATCH_ARENA_SIZE;
const EXCEPTION_POINTERS_OFFSET: usize = 0;
const EXCEPTION_RECORD_OFFSET: usize = 0x20;
const EXCEPTION_RECORD_SIZE: usize = 0x98;
const AMD64_CONTEXT_OFFSET: usize = 0xc0;
const AMD64_CONTEXT_SIZE: usize = 0x4d0;
const AMD64_CONTEXT_FLAGS_OFFSET: usize = 0x30;
const AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS: [usize; 6] = [0x48, 0x50, 0x58, 0x60, 0x68, 0x70];
const AMD64_CONTEXT_EFLAGS_OFFSET: usize = 0x44;
const AMD64_CONTEXT_RAX_OFFSET: usize = 0x78;
const AMD64_CONTEXT_RCX_OFFSET: usize = 0x80;
const AMD64_CONTEXT_RDX_OFFSET: usize = 0x88;
const AMD64_CONTEXT_RBX_OFFSET: usize = 0x90;
const AMD64_CONTEXT_RSP_OFFSET: usize = 0x98;
const AMD64_CONTEXT_RBP_OFFSET: usize = 0xa0;
const AMD64_CONTEXT_RSI_OFFSET: usize = 0xa8;
const AMD64_CONTEXT_RDI_OFFSET: usize = 0xb0;
const AMD64_CONTEXT_R8_OFFSET: usize = 0xb8;
const AMD64_CONTEXT_R9_OFFSET: usize = 0xc0;
const AMD64_CONTEXT_R10_OFFSET: usize = 0xc8;
const AMD64_CONTEXT_R11_OFFSET: usize = 0xd0;
const AMD64_CONTEXT_R12_OFFSET: usize = 0xd8;
const AMD64_CONTEXT_R13_OFFSET: usize = 0xe0;
const AMD64_CONTEXT_R14_OFFSET: usize = 0xe8;
const AMD64_CONTEXT_R15_OFFSET: usize = 0xf0;
const AMD64_CONTEXT_RIP_OFFSET: usize = 0xf8;
const CONTEXT_AMD64_DEBUG_REGISTERS: u32 = 0x0010_0010;
const CONTEXT_AMD64_CONTROL_INTEGER: u32 = 0x0010_0003;
const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;
const EXCEPTION_NONCONTINUABLE: u32 = 1;
const EXCEPTION_CONTINUE_EXECUTION: u32 = u32::MAX;
const EXCEPTION_CALLBACK_STACK_HEADROOM: u64 = 0x100;
const _: () = assert!(EXCEPTION_RECORD_OFFSET + EXCEPTION_RECORD_SIZE <= AMD64_CONTEXT_OFFSET);
const MEM_COMMIT: u32 = 0x1000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const FIRMWARE_PROVIDER_RSMB: u32 = 0x5253_4d42;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const SID_REVISION: u8 = 1;
const SID_IDENTIFIER_AUTHORITY_SIZE: usize = 6;
const SID_MAX_SUB_AUTHORITIES: u8 = 8;
const TOKEN_QUERY: u32 = 0x8;
const TOKEN_INFORMATION_CLASS_GROUPS: u32 = 2;
const EMPTY_TOKEN_GROUPS_SIZE: u32 = 4;
const PROCESS_INFORMATION_CLASS_DEBUG_PORT: u32 = 7;
const PROCESS_INFORMATION_CLASS_DEBUG_OBJECT_HANDLE: u32 = 30;
const SYSTEM_INFORMATION_CLASS_MODULE_INFORMATION: u32 = 11;
const SYSTEM_MODULE_INFORMATION_COUNT_SIZE: u32 = 4;
const THREAD_INFORMATION_CLASS_HIDE_FROM_DEBUGGER: u32 = 17;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xc000_0004;
const STATUS_PORT_NOT_SET: u32 = 0xc000_0353;

const EXCEPTION_DISPATCH_REGISTER_ORDER: [RegisterX86; 29] = [
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
    RegisterX86::FS_BASE,
    RegisterX86::GS_BASE,
    RegisterX86::MXCSR,
    RegisterX86::FPCW,
    RegisterX86::FPSW,
    RegisterX86::FPTAG,
    RegisterX86::FIP,
    RegisterX86::FCS,
    RegisterX86::FDP,
    RegisterX86::FDS,
    RegisterX86::FOP,
];
const EXCEPTION_DISPATCH_XMM_REGISTERS: [RegisterX86; 16] = [
    RegisterX86::XMM0,
    RegisterX86::XMM1,
    RegisterX86::XMM2,
    RegisterX86::XMM3,
    RegisterX86::XMM4,
    RegisterX86::XMM5,
    RegisterX86::XMM6,
    RegisterX86::XMM7,
    RegisterX86::XMM8,
    RegisterX86::XMM9,
    RegisterX86::XMM10,
    RegisterX86::XMM11,
    RegisterX86::XMM12,
    RegisterX86::XMM13,
    RegisterX86::XMM14,
    RegisterX86::XMM15,
];
const EXCEPTION_DISPATCH_X87_REGISTERS: [RegisterX86; 8] = [
    RegisterX86::ST0,
    RegisterX86::ST1,
    RegisterX86::ST2,
    RegisterX86::ST3,
    RegisterX86::ST4,
    RegisterX86::ST5,
    RegisterX86::ST6,
    RegisterX86::ST7,
];
const EXCEPTION_DISPATCH_FP_CONTROL_REGISTERS: [RegisterX86; 9] = [
    RegisterX86::MXCSR,
    RegisterX86::FPCW,
    RegisterX86::FPSW,
    RegisterX86::FPTAG,
    RegisterX86::FIP,
    RegisterX86::FCS,
    RegisterX86::FDP,
    RegisterX86::FDS,
    RegisterX86::FOP,
];

/// Total instruction budget for one cooperatively selected child run.
const COOPERATIVE_CHILD_INSTRUCTION_CAP: u64 = 100_000;

/// Maximum number of named APIs one cooperatively selected child may handle.
const COOPERATIVE_CHILD_API_CAP: usize = 32;

/// Fresh runtime layout for each cooperatively selected child. The arena starts
/// immediately after the bounded process heap and ends before the main stack.
const COOPERATIVE_THREAD_RUNTIME_BASE: u64 = HEAP_ARENA_BASE + HEAP_ARENA_SIZE;
const COOPERATIVE_THREAD_RUNTIME_SIZE: u64 = STACK_SIZE + TEB_SIZE;
const COOPERATIVE_THREAD_ENTRY_HEADROOM: u64 = 0x1000;

/// Emulated-environment policy for the default user UI language: en-US.
const EMULATED_USER_DEFAULT_UI_LANGID: u16 = 0x0409;

/// Deterministic ID assigned to the initial/main emulated thread.
const EMULATED_CURRENT_THREAD_ID: u32 = 1;

/// Full-width Win64 pseudo handles returned for the calling process/thread.
/// They identify the caller context and are not entries in the real-handle
/// registry modeled for `CreateThread`/`OpenThread`.
const CURRENT_PROCESS_PSEUDO_HANDLE: u64 = u64::MAX;
const CURRENT_THREAD_PSEUDO_HANDLE: u64 = u64::MAX - 1;

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

/// Host-independent ANSI command line exposed by the emulated environment.
const EMULATED_COMMAND_LINE_A: &[u8] = b"C:\\guest.exe\0";

/// Dedicated read-only page for the process-owned ANSI command-line buffer.
const EMULATED_COMMAND_LINE_A_BASE: u64 = 0x0000_7ffd_0000_0000;

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

/// Observed zero-extended predefined handle for HKEY_LOCAL_MACHINE.
const HKEY_LOCAL_MACHINE: u64 = 0x0000_0000_8000_0002;

/// Opaque handle for the sole modeled shared system cursor. It occupies the
/// unmapped gap after the process-heap handle and before the kernel-handle
/// namespace.
const EMULATED_HAND_CURSOR_HANDLE: u64 = 0x0000_000f_3000_0010;

/// Stable opaque handle returned by the bounded window-creation treatment.
const EMULATED_WINDOW_HANDLE: u64 = 0x0000_000f_3000_0020;

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

/// Sorted export-name snapshot derived from the authorized names-only
/// `samples/kernel32.dll` support asset. No bytes or implementation from that
/// DLL are mapped or executed. The complete catalog is required when the guest
/// validates the provider while rebuilding its original imports; a short
/// incremental seed reaches the loader's explicit "Wrong DLL" path.
pub static KERNEL32_EXPORTS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let names = include_str!("kernel32_exports.txt")
        .lines()
        .collect::<Vec<_>>();
    assert!(!names.is_empty() && names.len() <= DIAGNOSTIC_EXPORT_NAME_CAP);
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(names.iter().all(|name| {
        !name.is_empty()
            && name.len() <= IMPORT_NAME_CAP
            && name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }));
    names
});

/// Seed ntdll export names observed during the bootstrap export walk; this is
/// not a completeness claim.
const NTDLL_EXPORTS: &[&str] = &[
    "RtlEnterCriticalSection",
    "RtlLeaveCriticalSection",
    "RtlInitializeCriticalSection",
    "RtlAddVectoredExceptionHandler",
    "RtlRemoveVectoredExceptionHandler",
    "NtQueryObject",
    "ZwQueryInformationProcess",
    "ZwSetInformationThread",
    "RtlAllocateHeap",
    "RtlReAllocateHeap",
    "RtlFreeHeap",
];

const USER32_EXPORTS: &[&str] = &[
    "CreateWindowExA",
    "FindWindowA",
    "LoadCursorA",
    "RegisterClassExA",
    // Names-only provider evidence: no natural call has established an ABI
    // treatment, so dispatch deliberately remains unimplemented.
    "SendMessageA",
];
const ADVAPI32_EXPORTS: &[&str] = &[
    "AllocateAndInitializeSid",
    "FreeSid",
    "GetTokenInformation",
    "OpenProcessToken",
    "OpenThreadToken",
    "RegOpenKeyA",
];
/// Sorted, bounded names-only catalog required by the protected loader's
/// `msvcrt.dll` export-name validation. The guest hashes these names before it
/// reads any function or ordinal table. A one-name declared-import seed reaches
/// the loader's explicit wrong-provider path; this same catalog escapes that
/// path unchanged on both exercised protected samples. No DLL implementation
/// bytes are mapped or executed.
static MSVCRT_EXPORTS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let names = include_str!("msvcrt_exports.txt")
        .lines()
        .collect::<Vec<_>>();
    assert!(!names.is_empty() && names.len() <= DIAGNOSTIC_EXPORT_NAME_CAP);
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(names.iter().all(|name| {
        !name.is_empty()
            && name.len() <= IMPORT_NAME_CAP
            && name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }));
    names
});

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

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|with_padding| with_padding & !(alignment - 1))
}

fn virtual_protect_page_range(address: u64, size: u64) -> Option<(u64, u64)> {
    if address == 0 || size == 0 {
        return None;
    }
    let page_size = u64::from(PAGE_SIZE);
    let base = address & !(page_size - 1);
    let end = align_up_u64(address.checked_add(size)?, page_size)?;
    let mapped_size = end.checked_sub(base)?;
    (mapped_size != 0).then_some((base, mapped_size))
}

fn page_protection_from_win32(value: u32) -> Option<PageProtection> {
    match value {
        PAGE_NOACCESS => Some(PageProtection::NoAccess),
        PAGE_READONLY => Some(PageProtection::ReadOnly),
        PAGE_READWRITE => Some(PageProtection::ReadWrite),
        PAGE_EXECUTE => Some(PageProtection::Execute),
        PAGE_EXECUTE_READ => Some(PageProtection::ExecuteRead),
        PAGE_EXECUTE_READWRITE => Some(PageProtection::ExecuteReadWrite),
        _ => None,
    }
}

fn page_protection_to_win32(value: PageProtection) -> u32 {
    match value {
        PageProtection::NoAccess => PAGE_NOACCESS,
        PageProtection::ReadOnly => PAGE_READONLY,
        PageProtection::ReadWrite => PAGE_READWRITE,
        PageProtection::Execute => PAGE_EXECUTE,
        PageProtection::ExecuteRead => PAGE_EXECUTE_READ,
        PageProtection::ExecuteReadWrite => PAGE_EXECUTE_READWRITE,
    }
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
struct VirtualAllocation {
    requested_size: u64,
    mapped_size: u64,
    allocation_type: u32,
    protection: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SidAllocation {
    sid_size: u64,
    mapped_size: u64,
    sub_authority_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelObject {
    Thread { thread_id: u32 },
    ProcessToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelHandle {
    object: KernelObject,
    desired_access: u32,
    inheritable: bool,
}

/// Immutable record created by the bounded `CreateThread` model.
///
/// Creation itself does not execute the record. The production cooperative
/// runner may later claim it once at a supported main-thread `Sleep`; raw trap
/// runs and diagnostics continue to leave it unscheduled. No lifecycle meaning
/// is assigned to the child's eventual control-transfer boundary.
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
    first: u32,
    handler: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingVectoredException {
    code: u32,
    flags: u32,
    handlers: Vec<u64>,
    next_handler_index: usize,
    current_handler: u64,
    exception_pointers: u64,
    exception_record: u64,
    context_record: u64,
    return_guard: u64,
    callback_rsp: u64,
    dispatcher_registers: [u64; EXCEPTION_DISPATCH_REGISTER_ORDER.len()],
    dispatcher_xmm_registers: [[u8; 16]; EXCEPTION_DISPATCH_XMM_REGISTERS.len()],
    dispatcher_x87_registers: [[u8; 10]; EXCEPTION_DISPATCH_X87_REGISTERS.len()],
    initial_context: Vec<u8>,
    thread_id: u32,
}

/// Frozen evidence for a VEH-mediated `CONTEXT.Rip` change.
///
/// This is not classified as a guest indirect transfer: the host context
/// restore has no guest predecessor instruction. The trap runner stops before
/// executing `continuation_rip`, preventing the OEP watch from silently
/// marking that target as already executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionContinuationObservation {
    pub thread_id: u32,
    pub exception_code: u32,
    /// Handler that returned `EXCEPTION_CONTINUE_EXECUTION`. An earlier
    /// continue-search handler may have authored the context mutation.
    pub continuing_handler: u64,
    pub original_rip: u64,
    pub continuation_rip: u64,
    pub context_record: u64,
    pub registers: Vec<(RegisterX86, u64)>,
    pub target_bytes: Vec<u8>,
    pub context_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VectoredExceptionReturn {
    Resume,
    ChangedContinuation,
    HandlersExhausted { code: u32 },
    Noncontinuable { code: u32 },
    InvalidDisposition { code: u32, disposition: u32 },
    InvalidContext { code: u32 },
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
    next_exception_dispatch_base: u64,
    pending_vectored_exceptions: BTreeMap<u32, PendingVectoredException>,
    changed_exception_continuation: Option<ExceptionContinuationObservation>,
    next_kernel_handle: u64,
    kernel_handles: BTreeMap<u64, KernelHandle>,
    next_thread_id: u64,
    created_threads: BTreeMap<u32, RunnableUnscheduledThread>,
    scheduled_thread_ids: BTreeSet<u32>,
    next_cooperative_runtime_base: u64,
    heap_cursor: u64,
    heap_allocations: BTreeMap<u64, HeapAllocation>,
    virtual_allocation_cursor: u64,
    virtual_allocations: BTreeMap<u64, VirtualAllocation>,
    sid_allocation_cursor: u64,
    sid_allocations: BTreeMap<u64, SidAllocation>,
    command_line_a_mapped: bool,
    modules: BTreeMap<String, u64>,
    next_base: u64,
    synthetic_modules: BTreeMap<String, SyntheticModule>,
    diagnostic_export_name_controls: BTreeMap<String, Vec<String>>,
    applied_diagnostic_export_name_controls: BTreeSet<String>,
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
            next_exception_dispatch_base: EXCEPTION_DISPATCH_ARENA_BASE,
            pending_vectored_exceptions: BTreeMap::new(),
            changed_exception_continuation: None,
            next_kernel_handle: KERNEL_HANDLE_BASE,
            kernel_handles: BTreeMap::new(),
            next_thread_id: CREATED_THREAD_ID_BASE,
            created_threads: BTreeMap::new(),
            scheduled_thread_ids: BTreeSet::new(),
            next_cooperative_runtime_base: COOPERATIVE_THREAD_RUNTIME_BASE,
            heap_cursor: HEAP_ARENA_BASE,
            heap_allocations: BTreeMap::new(),
            virtual_allocation_cursor: VIRTUAL_ALLOCATION_ARENA_BASE,
            virtual_allocations: BTreeMap::new(),
            sid_allocation_cursor: SID_ALLOCATION_ARENA_BASE,
            sid_allocations: BTreeMap::new(),
            command_line_a_mapped: false,
            modules: BTreeMap::new(),
            next_base: FAKE_MODULE_BASE_START,
            synthetic_modules: BTreeMap::new(),
            diagnostic_export_name_controls: BTreeMap::new(),
            applied_diagnostic_export_name_controls: BTreeSet::new(),
            proc_stubs: BTreeMap::new(),
            proc_stub_mapped_end: PROC_STUB_BASE,
            next_window_class_atom: WINDOW_CLASS_ATOM_BASE,
            window_classes_by_atom: BTreeMap::new(),
            window_class_atoms_by_name: BTreeMap::new(),
        }
    }

    /// Iterate over not-yet-claimed created-thread records in ascending
    /// thread-ID order. Observing these records does not schedule or execute
    /// them.
    pub fn runnable_unscheduled_threads(
        &self,
    ) -> impl Iterator<Item = (u32, &RunnableUnscheduledThread)> {
        self.created_threads
            .iter()
            .filter(|(thread_id, _)| !self.scheduled_thread_ids.contains(thread_id))
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

    /// Iterate over the window procedures owned by successfully registered
    /// ANSI classes, in atom order.
    ///
    /// This is a read-only diagnostic projection. It does not invoke a
    /// callback or model window/message lifecycle.
    pub fn registered_window_procedures(&self) -> impl Iterator<Item = (u16, u64)> + '_ {
        self.window_classes_by_atom
            .iter()
            .map(|(&atom, class)| (atom, class.window_procedure))
    }

    /// Iterate over registered vectored exception handlers in current dispatch
    /// order as `(order, token, first, handler)` tuples.
    ///
    /// This is a read-only diagnostic projection. It does not invoke handlers
    /// or assign removal, dispatch, exception, or lifecycle semantics.
    pub fn vectored_exception_handler_registrations(
        &self,
    ) -> impl Iterator<Item = (usize, u64, u32, u64)> + '_ {
        self.vectored_exception_handlers
            .iter()
            .enumerate()
            .map(|(order, registration)| {
                (
                    order,
                    registration.token,
                    registration.first,
                    registration.handler,
                )
            })
    }

    /// Return the first frozen host-mediated exception continuation whose RIP
    /// differs from the logical RaiseException return point.
    pub fn changed_exception_continuation(&self) -> Option<&ExceptionContinuationObservation> {
        self.changed_exception_continuation.as_ref()
    }

    /// Iterate over mapped synthetic module image ranges in normalized-name
    /// order. Stub arenas are excluded.
    ///
    /// This is a read-only diagnostic projection; it does not load a module.
    pub fn synthetic_module_image_ranges(&self) -> impl Iterator<Item = (&str, u64, u64)> {
        self.synthetic_modules.iter().filter_map(|(name, module)| {
            let size = u64::try_from(module.image.len()).ok()?;
            let end = module.base.checked_add(size)?;
            Some((name.as_str(), module.base, end))
        })
    }

    /// Override one not-yet-loaded synthetic module's export-name seed for a
    /// bounded diagnostic control.
    ///
    /// This changes names only: no provider implementation is mapped or run.
    /// Production callers do not configure controls. The override must be
    /// installed before the named module is loaded, and names must be strictly
    /// sorted, unique, printable, and bounded.
    pub fn configure_module_export_name_control(
        &mut self,
        module_name: &str,
        names: &[String],
    ) -> bool {
        let key = normalize_module_name(module_name).to_ascii_lowercase();
        if key.is_empty()
            || names.is_empty()
            || names.len() > DIAGNOSTIC_EXPORT_NAME_CAP
            || self.synthetic_modules.contains_key(&key)
            || self.diagnostic_export_name_controls.contains_key(&key)
            || names.windows(2).any(|pair| pair[0] >= pair[1])
            || names.iter().any(|name| {
                name.is_empty()
                    || name.len() > IMPORT_NAME_CAP
                    || !name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            })
        {
            return false;
        }

        self.diagnostic_export_name_controls
            .insert(key, names.to_vec());
        true
    }

    /// Report whether a configured names-only control supplied the export
    /// table used to map the normalized module.
    pub fn module_export_name_control_was_applied(&self, module_name: &str) -> bool {
        let key = normalize_module_name(module_name).to_ascii_lowercase();
        self.applied_diagnostic_export_name_controls.contains(&key)
    }

    fn add_vectored_exception_handler(&mut self, first: u32, handler: u64) -> u64 {
        // Registration records an opaque callback and Windows-compatible
        // insertion order. A RaiseException dispatch snapshots this ordered
        // list; concurrent mutation of an active dispatch remains outside the
        // model.
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

        let registration = VectoredExceptionHandlerRegistration {
            token,
            first,
            handler,
        };
        if first == 0 {
            self.vectored_exception_handlers.push(registration);
        } else {
            self.vectored_exception_handlers.insert(0, registration);
        }
        self.next_vectored_exception_handler_token = next_token;
        token
    }

    fn has_pending_vectored_exception(&self) -> bool {
        self.pending_vectored_exceptions
            .contains_key(&self.current_thread_id)
    }

    fn begin_vectored_exception_dispatch(
        &mut self,
        emu: &mut Emu,
        code: u32,
        flags: u32,
        argument_count: u32,
        arguments: u64,
    ) -> Result<bool, EmuError> {
        let thread_id = self.current_thread_id;
        if self.pending_vectored_exceptions.contains_key(&thread_id) {
            // Nested software exceptions need a bounded per-thread stack. Do
            // not overwrite the active dispatch until that behavior is
            // observed and modeled.
            return Ok(false);
        }

        let effective_count = if argument_count == 0 || arguments == 0 {
            0
        } else {
            usize::try_from(argument_count)
                .unwrap_or(usize::MAX)
                .min(EXCEPTION_MAXIMUM_PARAMETERS)
        };
        let information = if effective_count == 0 {
            Vec::new()
        } else {
            let byte_len = effective_count
                .checked_mul(std::mem::size_of::<u64>())
                .ok_or(EmuError::AddressRangeOverflow {
                    base: arguments,
                    size: u64::MAX,
                })?;
            emu.read_mem(arguments, byte_len)?
        };

        let (continuation_rip, continuation_rsp) = preflight_api_return(emu)?;
        let api_rsp = emu.read_reg(RegisterX86::RSP)?;
        let callback_rsp = api_rsp
            .checked_sub(EXCEPTION_CALLBACK_STACK_HEADROOM)
            .ok_or(EmuError::AddressRangeOverflow {
                base: api_rsp,
                size: EXCEPTION_CALLBACK_STACK_HEADROOM,
            })?;
        if callback_rsp & 0xf != 8 {
            return Ok(false);
        }
        // The callback receives a normal Win64 entry frame: one return cell
        // plus the caller-owned 32-byte home area.
        emu.preflight_write_mem(callback_rsp, 0x28)?;

        let dispatch_base = self.next_exception_dispatch_base;
        let Some(next_dispatch_base) = dispatch_base.checked_add(u64::from(PAGE_SIZE)) else {
            return Ok(false);
        };
        if !(EXCEPTION_DISPATCH_ARENA_BASE..EXCEPTION_DISPATCH_ARENA_END).contains(&dispatch_base)
            || !dispatch_base.is_multiple_of(u64::from(PAGE_SIZE))
            || next_dispatch_base > EXCEPTION_DISPATCH_ARENA_END
            || self
                .pending_vectored_exceptions
                .values()
                .any(|pending| pending.return_guard == dispatch_base)
        {
            return Ok(false);
        }

        let mut dispatcher_registers = [0u64; EXCEPTION_DISPATCH_REGISTER_ORDER.len()];
        for (slot, register) in dispatcher_registers
            .iter_mut()
            .zip(EXCEPTION_DISPATCH_REGISTER_ORDER)
        {
            *slot = emu.read_reg(register)?;
        }
        let mut dispatcher_xmm_registers = [[0u8; 16]; EXCEPTION_DISPATCH_XMM_REGISTERS.len()];
        for (slot, register) in dispatcher_xmm_registers
            .iter_mut()
            .zip(EXCEPTION_DISPATCH_XMM_REGISTERS)
        {
            *slot = emu.read_reg_128(register)?;
        }
        let mut dispatcher_x87_registers = [[0u8; 10]; EXCEPTION_DISPATCH_X87_REGISTERS.len()];
        for (slot, register) in dispatcher_x87_registers
            .iter_mut()
            .zip(EXCEPTION_DISPATCH_X87_REGISTERS)
        {
            *slot = emu.read_reg_80(register)?;
        }

        let exception_pointers = dispatch_base
            .checked_add(EXCEPTION_POINTERS_OFFSET as u64)
            .ok_or(EmuError::AddressRangeOverflow {
                base: dispatch_base,
                size: EXCEPTION_POINTERS_OFFSET as u64,
            })?;
        let exception_record = dispatch_base
            .checked_add(EXCEPTION_RECORD_OFFSET as u64)
            .ok_or(EmuError::AddressRangeOverflow {
                base: dispatch_base,
                size: EXCEPTION_RECORD_OFFSET as u64,
            })?;
        let context_record = dispatch_base
            .checked_add(AMD64_CONTEXT_OFFSET as u64)
            .ok_or(EmuError::AddressRangeOverflow {
                base: dispatch_base,
                size: AMD64_CONTEXT_OFFSET as u64,
            })?;

        let mut page = vec![0u8; PAGE_SIZE as usize];
        debug_assert!(AMD64_CONTEXT_OFFSET + AMD64_CONTEXT_SIZE <= page.len());
        write_u64(&mut page, EXCEPTION_POINTERS_OFFSET, exception_record);
        write_u64(
            &mut page,
            EXCEPTION_POINTERS_OFFSET + std::mem::size_of::<u64>(),
            context_record,
        );
        write_u32(&mut page, EXCEPTION_RECORD_OFFSET, code);
        // This bounded provider collapses kernel32!RaiseException and the
        // ntdll raise path into one host transition. The observed first VEH
        // ignores the structures, so expose only the integer/control fields
        // Midas can restore exactly. Native AMD64 providers capture additional
        // segment and FP state; the callback's live XMM/x87/control state is
        // nevertheless snapshotted separately below and restored on return.
        write_u32(
            &mut page,
            EXCEPTION_RECORD_OFFSET + 4,
            flags & EXCEPTION_NONCONTINUABLE,
        );
        write_u64(&mut page, EXCEPTION_RECORD_OFFSET + 0x10, continuation_rip);
        write_u32(
            &mut page,
            EXCEPTION_RECORD_OFFSET + 0x18,
            effective_count as u32,
        );
        write_bytes(&mut page, EXCEPTION_RECORD_OFFSET + 0x20, &information);

        write_u32(
            &mut page,
            AMD64_CONTEXT_OFFSET + AMD64_CONTEXT_FLAGS_OFFSET,
            CONTEXT_AMD64_CONTROL_INTEGER,
        );
        write_u32(
            &mut page,
            AMD64_CONTEXT_OFFSET + AMD64_CONTEXT_EFLAGS_OFFSET,
            snapshot_register_value(&dispatcher_registers, RegisterX86::EFLAGS) as u32,
        );
        for (register, offset) in amd64_context_integer_layout() {
            let value = match register {
                RegisterX86::RSP => continuation_rsp,
                RegisterX86::RIP => continuation_rip,
                _ => snapshot_register_value(&dispatcher_registers, register),
            };
            write_u64(&mut page, AMD64_CONTEXT_OFFSET + offset, value);
        }
        let initial_context =
            page[AMD64_CONTEXT_OFFSET..AMD64_CONTEXT_OFFSET + AMD64_CONTEXT_SIZE].to_vec();

        // All fallible reads and caller-stack validation are complete before
        // allocating or mutating environment-owned exception state.
        emu.map_zeroed_rw(dispatch_base, u64::from(PAGE_SIZE))?;
        if let Err(error) = emu.write_mem(dispatch_base, &page) {
            emu.unmap(dispatch_base, u64::from(PAGE_SIZE))?;
            return Err(error);
        }

        let handlers = self
            .vectored_exception_handlers
            .iter()
            .map(|registration| registration.handler)
            .collect::<Vec<_>>();
        let current_handler = handlers.first().copied().unwrap_or(0);
        let pending = PendingVectoredException {
            code,
            flags: flags & EXCEPTION_NONCONTINUABLE,
            next_handler_index: usize::from(!handlers.is_empty()),
            handlers,
            current_handler,
            exception_pointers,
            exception_record,
            context_record,
            return_guard: dispatch_base,
            callback_rsp,
            dispatcher_registers,
            dispatcher_xmm_registers,
            dispatcher_x87_registers,
            initial_context,
            thread_id,
        };
        let setup_result = if pending.handlers.is_empty() {
            install_empty_vectored_exception_guard(emu, &pending)
        } else {
            install_vectored_exception_callback(emu, &pending)
        };
        if let Err(error) = setup_result {
            // The dispatch page is not yet reachable through environment
            // state, so remove it before returning a late setup failure.
            emu.unmap(dispatch_base, u64::from(PAGE_SIZE))?;
            return Err(error);
        }
        self.next_exception_dispatch_base = next_dispatch_base;
        self.pending_vectored_exceptions.insert(thread_id, pending);
        Ok(true)
    }

    fn advance_vectored_exception_dispatch_on_guard(
        &mut self,
        emu: &mut Emu,
        address: u64,
    ) -> Result<Option<VectoredExceptionReturn>, EmuError> {
        let thread_id = self.current_thread_id;
        let Some(mut pending) = self.pending_vectored_exceptions.get(&thread_id).cloned() else {
            return Ok(None);
        };
        if pending.thread_id != thread_id
            || pending.return_guard != address
            || emu.read_reg(RegisterX86::RIP)? != address
            || pending.callback_rsp.checked_add(8) != Some(emu.read_reg(RegisterX86::RSP)?)
        {
            return Ok(None);
        }
        if pending.handlers.is_empty() {
            return Ok(Some(VectoredExceptionReturn::HandlersExhausted {
                code: pending.code,
            }));
        }

        let disposition = emu.read_reg(RegisterX86::RAX)? as u32;
        match disposition {
            0 => {
                let Some(&next_handler) = pending.handlers.get(pending.next_handler_index) else {
                    return Ok(Some(VectoredExceptionReturn::HandlersExhausted {
                        code: pending.code,
                    }));
                };
                pending.next_handler_index += 1;
                pending.current_handler = next_handler;
                install_vectored_exception_callback(emu, &pending)?;
                self.pending_vectored_exceptions.insert(thread_id, pending);
                Ok(Some(VectoredExceptionReturn::Resume))
            }
            EXCEPTION_CONTINUE_EXECUTION => {
                if pending.flags & EXCEPTION_NONCONTINUABLE != 0 {
                    return Ok(Some(VectoredExceptionReturn::Noncontinuable {
                        code: pending.code,
                    }));
                }
                let pointers = emu.read_mem(pending.exception_pointers, 16)?;
                if u64_from_bytes(&pointers, 0) != pending.exception_record
                    || u64_from_bytes(&pointers, 8) != pending.context_record
                {
                    return Ok(Some(VectoredExceptionReturn::InvalidContext {
                        code: pending.code,
                    }));
                }
                let context = emu.read_mem(pending.context_record, AMD64_CONTEXT_SIZE)?;
                if !valid_mutated_amd64_context(&pending.initial_context, &context) {
                    return Ok(Some(VectoredExceptionReturn::InvalidContext {
                        code: pending.code,
                    }));
                }
                let original_rip =
                    u64_from_bytes(&pending.initial_context, AMD64_CONTEXT_RIP_OFFSET);
                let continuation_rip = u64_from_bytes(&context, AMD64_CONTEXT_RIP_OFFSET);
                let changed_observation = if continuation_rip != original_rip {
                    if self.changed_exception_continuation.is_some() {
                        return Ok(Some(VectoredExceptionReturn::InvalidContext {
                            code: pending.code,
                        }));
                    }
                    Some(ExceptionContinuationObservation {
                        thread_id,
                        exception_code: pending.code,
                        continuing_handler: pending.current_handler,
                        original_rip,
                        continuation_rip,
                        context_record: pending.context_record,
                        registers: amd64_context_register_snapshot(&context),
                        target_bytes: freeze_exception_continuation_target(emu, continuation_rip)?,
                        context_bytes: context.clone(),
                    })
                } else {
                    None
                };
                restore_amd64_context(emu, &pending, &context)?;
                self.pending_vectored_exceptions.remove(&thread_id);
                if let Some(observation) = changed_observation {
                    self.changed_exception_continuation = Some(observation);
                    Ok(Some(VectoredExceptionReturn::ChangedContinuation))
                } else {
                    Ok(Some(VectoredExceptionReturn::Resume))
                }
            }
            _ => Ok(Some(VectoredExceptionReturn::InvalidDisposition {
                code: pending.code,
                disposition,
            })),
        }
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
        let thread_exists = thread_id == EMULATED_CURRENT_THREAD_ID
            || thread_id == self.current_thread_id
            || self.created_threads.contains_key(&thread_id);
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

    fn process_token_handle_candidate(&self, desired_access: u32) -> Option<(u64, u64)> {
        (desired_access == TOKEN_QUERY)
            .then(|| self.kernel_handle_candidate())
            .flatten()
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

    fn virtual_allocation_candidate(
        &self,
        requested_size: u64,
    ) -> Option<(u64, u64, VirtualAllocation)> {
        if requested_size == 0 {
            return None;
        }

        let mapped_size = align_up_u64(requested_size, u64::from(PAGE_SIZE))?;
        let allocation_base = self.virtual_allocation_cursor;
        let mapped_end = allocation_base.checked_add(mapped_size)?;
        let next_cursor = align_up_u64(mapped_end, VIRTUAL_ALLOCATION_GRANULARITY)?;
        if !(VIRTUAL_ALLOCATION_ARENA_BASE..VIRTUAL_ALLOCATION_ARENA_END).contains(&allocation_base)
            || !allocation_base.is_multiple_of(VIRTUAL_ALLOCATION_GRANULARITY)
            || mapped_end > VIRTUAL_ALLOCATION_ARENA_END
            || next_cursor > VIRTUAL_ALLOCATION_ARENA_END
            || self.virtual_allocations.contains_key(&allocation_base)
        {
            return None;
        }

        Some((
            allocation_base,
            next_cursor,
            VirtualAllocation {
                requested_size,
                mapped_size,
                allocation_type: MEM_COMMIT,
                protection: PAGE_READWRITE,
            },
        ))
    }

    fn commit_virtual_allocation(
        &mut self,
        allocation_base: u64,
        next_cursor: u64,
        allocation: VirtualAllocation,
    ) {
        let previous = self.virtual_allocations.insert(allocation_base, allocation);
        debug_assert!(previous.is_none());
        self.virtual_allocation_cursor = next_cursor;
    }

    fn sid_allocation_candidate(
        &self,
        sub_authority_count: u8,
    ) -> Option<(u64, u64, SidAllocation)> {
        if !(1..=SID_MAX_SUB_AUTHORITIES).contains(&sub_authority_count) {
            return None;
        }
        let sid_size = 8u64.checked_add(u64::from(sub_authority_count).checked_mul(4)?)?;
        let mapped_size = u64::from(PAGE_SIZE);
        let allocation_base = self.sid_allocation_cursor;
        let next_cursor = allocation_base.checked_add(mapped_size)?;
        if !(SID_ALLOCATION_ARENA_BASE..SID_ALLOCATION_ARENA_END).contains(&allocation_base)
            || !allocation_base.is_multiple_of(mapped_size)
            || next_cursor > SID_ALLOCATION_ARENA_END
            || self.sid_allocations.contains_key(&allocation_base)
        {
            return None;
        }
        Some((
            allocation_base,
            next_cursor,
            SidAllocation {
                sid_size,
                mapped_size,
                sub_authority_count,
            },
        ))
    }

    fn commit_sid_allocation(
        &mut self,
        allocation_base: u64,
        next_cursor: u64,
        allocation: SidAllocation,
    ) {
        let previous = self.sid_allocations.insert(allocation_base, allocation);
        debug_assert!(previous.is_none());
        self.sid_allocation_cursor = next_cursor;
    }

    fn can_free_heap(&self, heap_handle: u64, flags: u32, allocation_base: u64) -> bool {
        heap_handle == self.process_heap
            && flags & !HEAP_NO_SERIALIZE == 0
            && self.heap_allocations.contains_key(&allocation_base)
    }

    fn commit_heap_free(&mut self, allocation_base: u64) {
        // Logical free only: the bounded bump allocator does not reuse or
        // unmap pages. Removing the live-allocation record makes duplicate and
        // interior frees fail without assigning lifecycle to the guest mapping.
        let removed = self.heap_allocations.remove(&allocation_base);
        debug_assert!(removed.is_some());
    }

    fn ensure_command_line_a(&mut self, emu: &mut Emu) -> Result<u64, EmuError> {
        if !self.command_line_a_mapped {
            emu.map_readonly(EMULATED_COMMAND_LINE_A_BASE, EMULATED_COMMAND_LINE_A)?;
            self.command_line_a_mapped = true;
        }
        Ok(EMULATED_COMMAND_LINE_A_BASE)
    }

    fn registered_window_class_a(&self, instance: u64, class_name: &str) -> bool {
        self.window_class_atoms_by_name
            .contains_key(&(instance, class_name.to_ascii_lowercase()))
    }

    fn cooperative_runtime_candidate(&self) -> Option<(u64, u64)> {
        let base = self.next_cooperative_runtime_base;
        let next = base.checked_add(COOPERATIVE_THREAD_RUNTIME_SIZE)?;
        if base < COOPERATIVE_THREAD_RUNTIME_BASE
            || !base.is_multiple_of(u64::from(PAGE_SIZE))
            || next > STACK_BASE
        {
            return None;
        }
        Some((base, next))
    }

    fn claim_thread_for_cooperative_run(&mut self, thread_id: u32, next_runtime_base: u64) -> bool {
        if !self.created_threads.contains_key(&thread_id)
            || !self.scheduled_thread_ids.insert(thread_id)
        {
            return false;
        }
        self.next_cooperative_runtime_base = next_runtime_base;
        true
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
        self.ensure_loaded_module(emu, "kernel32.dll")
    }

    fn ensure_loaded_module(&mut self, emu: &mut Emu, name: &str) -> Result<u64, EmuError> {
        let normalized = normalize_module_name(name);
        let control_key = normalized.to_ascii_lowercase();
        if let Some(controlled_names) = self
            .diagnostic_export_name_controls
            .get(&control_key)
            .cloned()
        {
            let exports = controlled_names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let base = self.ensure_module(emu, &normalized, &exports)?;
            self.applied_diagnostic_export_name_controls
                .insert(control_key);
            return Ok(base);
        }
        let module_name = normalized
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(normalized.as_str());
        let exports: &[&str] = if module_name.eq_ignore_ascii_case("kernel32.dll") {
            KERNEL32_EXPORTS.as_slice()
        } else if module_name.eq_ignore_ascii_case("ntdll.dll") {
            NTDLL_EXPORTS
        } else if module_name.eq_ignore_ascii_case("user32.dll") {
            USER32_EXPORTS
        } else if module_name.eq_ignore_ascii_case("advapi32.dll") {
            ADVAPI32_EXPORTS
        } else if module_name.eq_ignore_ascii_case("msvcrt.dll") {
            MSVCRT_EXPORTS.as_slice()
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
        "VirtualAlloc" => {
            let requested_address = emu.read_reg(RegisterX86::RCX)?;
            let requested_size = emu.read_reg(RegisterX86::RDX)?;
            // Allocation type and protection are DWORD values on Win64, so
            // their dirty upper register halves do not participate.
            let allocation_type = emu.read_reg(RegisterX86::R8)? as u32;
            let protection = emu.read_reg(RegisterX86::R9)? as u32;

            // Bounded policy: the observed NULL-address, commit-only,
            // read/write allocation is supported for any nonzero size that
            // fits the finite arena. Address-selected allocations, reservation
            // state, modifiers, and other protections remain unmodeled.
            if requested_address != 0
                || allocation_type != MEM_COMMIT
                || protection != PAGE_READWRITE
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // Validate the return frame before mapping pages or consuming an
            // allocator cursor. A zero, overflowing, or exhausted request is a
            // handled allocation failure and returns NULL without state change.
            let return_state = preflight_api_return(emu)?;
            let ret = if let Some((allocation_base, next_cursor, allocation)) =
                env.virtual_allocation_candidate(requested_size)
            {
                emu.map_zeroed_rw(allocation_base, allocation.mapped_size)?;
                env.commit_virtual_allocation(allocation_base, next_cursor, allocation);
                allocation_base
            } else {
                0
            };
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "VirtualFree" => {
            let allocation_base = emu.read_reg(RegisterX86::RCX)?;
            let size = emu.read_reg(RegisterX86::RDX)?;
            let free_type = emu.read_reg(RegisterX86::R8)? as u32;
            if size != 0 || free_type != MEM_RELEASE {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let allocation = env.virtual_allocations.get(&allocation_base).copied();
            let return_state = preflight_api_return(emu)?;
            if let Some(allocation) = allocation {
                emu.unmap(allocation_base, allocation.mapped_size)?;
            }
            let ret = u64::from(allocation.is_some());
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            if allocation.is_some() {
                let removed = env.virtual_allocations.remove(&allocation_base);
                debug_assert!(removed.is_some());
            }
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "VirtualProtect" => {
            let address = emu.read_reg(RegisterX86::RCX)?;
            let size = emu.read_reg(RegisterX86::RDX)?;
            let new_protection = emu.read_reg(RegisterX86::R8)? as u32;
            let old_protection = emu.read_reg(RegisterX86::R9)?;
            let Some(new_protection) = page_protection_from_win32(new_protection) else {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            };
            if old_protection == 0 {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let page_range = virtual_protect_page_range(address, size);
            if page_range.is_some_and(|(page_base, mapped_size)| {
                ranges_overlap(
                    page_base,
                    mapped_size,
                    old_protection,
                    std::mem::size_of::<u32>() as u64,
                )
            }) {
                // Supporting an output inside the range requires rollback when
                // the new protection removes write access. Keep this bounded
                // model failure-atomic until that shape is observed.
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // Validate control before any page or output change. NULL, empty,
            // overflowing, and incompletely mapped ranges are deterministic
            // failures and do not access lpflOldProtect.
            let return_state = preflight_api_return(emu)?;
            let Some((page_base, mapped_size)) = page_range else {
                commit_api_return(emu, return_state)?;
                emu.write_reg(RegisterX86::RAX, 0)?;
                return Ok(ApiOutcome::Handled {
                    name: name.to_owned(),
                    ret: 0,
                });
            };
            let Some(previous) = emu.page_range_protection(page_base, mapped_size)? else {
                commit_api_return(emu, return_state)?;
                emu.write_reg(RegisterX86::RAX, 0)?;
                return Ok(ApiOutcome::Handled {
                    name: name.to_owned(),
                    ret: 0,
                });
            };

            // Both fallible guest writes are preflighted before changing page
            // permissions. The old-protection DWORD describes the first page,
            // as required when the range spans adjacent regions.
            emu.preflight_write_mem(old_protection, std::mem::size_of::<u32>())?;
            let Some(changed_from) = emu.protect_pages(page_base, mapped_size, new_protection)?
            else {
                commit_api_return(emu, return_state)?;
                emu.write_reg(RegisterX86::RAX, 0)?;
                return Ok(ApiOutcome::Handled {
                    name: name.to_owned(),
                    ret: 0,
                });
            };
            debug_assert_eq!(changed_from, previous);
            emu.write_mem(
                old_protection,
                &page_protection_to_win32(previous).to_le_bytes(),
            )?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, 1)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 1,
            })
        }
        "CloseHandle" => {
            let handle = emu.read_reg(RegisterX86::RCX)?;
            let tracked = env.kernel_handles.contains_key(&handle);
            let ret = u64::from(tracked);

            // Closing only removes a real registry-backed handle. Pseudo,
            // unknown, and already-closed values return FALSE without adding
            // last-error, reuse, signaling, or object-lifecycle semantics.
            // Validate and commit control/result before removing the record so
            // a bad return frame cannot consume a live handle.
            let return_state = preflight_api_return(emu)?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            if tracked {
                let removed = env.kernel_handles.remove(&handle);
                debug_assert!(removed.is_some());
            }
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "GetCurrentProcess" => handled_scalar_api_return(emu, name, CURRENT_PROCESS_PSEUDO_HANDLE),
        "GetCurrentThread" => handled_scalar_api_return(emu, name, CURRENT_THREAD_PSEUDO_HANDLE),
        "GetThreadContext" => {
            let thread = emu.read_reg(RegisterX86::RCX)?;
            if thread != CURRENT_THREAD_PSEUDO_HANDLE {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let context = emu.read_reg(RegisterX86::RDX)?;
            let flags_address = checked_context_field_address(
                context,
                AMD64_CONTEXT_FLAGS_OFFSET,
                std::mem::size_of::<u32>(),
            )?;
            let context_flags = read_u32_at(emu, flags_address)?;
            if context_flags != CONTEXT_AMD64_DEBUG_REGISTERS {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // The observed call asks for only the AMD64 debug-register group
            // on the current-thread pseudo handle. Windows documents the
            // current-thread form as successful but not a valid snapshot; the
            // bounded environment therefore returns deterministic no-debug
            // state. Preserve ContextFlags and every unrequested CONTEXT byte.
            let return_state = preflight_api_return(emu)?;
            let mut debug_register_addresses = [0u64; 6];
            for (address, offset) in debug_register_addresses
                .iter_mut()
                .zip(AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS)
            {
                *address =
                    checked_context_field_address(context, offset, std::mem::size_of::<u64>())?;
                emu.preflight_write_mem(*address, std::mem::size_of::<u64>())?;
            }
            for address in debug_register_addresses {
                emu.write_mem(address, &0u64.to_le_bytes())?;
            }
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, 1)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 1,
            })
        }
        "CheckRemoteDebuggerPresent" => {
            let process = emu.read_reg(RegisterX86::RCX)?;
            if process != CURRENT_PROCESS_PSEUDO_HANDLE {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            let debugger_present = emu.read_reg(RegisterX86::RDX)?;
            let return_state = preflight_api_return(emu)?;
            // The emulated process has no remote debugger. BOOL is four bytes;
            // preserve adjacent guest bytes and report a successful query.
            emu.write_mem(debugger_present, &0u32.to_le_bytes())?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, 1)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 1,
            })
        }
        "IsBadReadPtr" => {
            let pointer = emu.read_reg(RegisterX86::RCX)?;
            let size = emu.read_reg(RegisterX86::RDX)?;
            if size != std::mem::size_of::<u32>() as u64 {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // UINT_PTR is full-width on Win64. For the exact observed
            // four-byte probe, classify only the current bounded mapping:
            // readable is FALSE; an overflowing or Unicorn-unreadable range
            // is TRUE. This does not promise that a later guest access is safe.
            let ret = if pointer.checked_add(size - 1).is_none() {
                1
            } else {
                match emu.read_mem(pointer, size as usize) {
                    Ok(_) => 0,
                    Err(EmuError::ReadMem { .. }) => 1,
                    Err(error) => return Err(error),
                }
            };
            handled_scalar_api_return(emu, name, ret)
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
        "GetSystemFirmwareTable" => {
            let provider = emu.read_reg(RegisterX86::RCX)? as u32;
            let table_id = emu.read_reg(RegisterX86::RDX)? as u32;
            let buffer = emu.read_reg(RegisterX86::R8)?;
            let buffer_size = emu.read_reg(RegisterX86::R9)? as u32;
            if provider != FIRMWARE_PROVIDER_RSMB
                || table_id != 0
                || buffer != 0
                || buffer_size != 0
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // The bounded environment publishes no host firmware identity.
            // This exact size query therefore fails with zero and performs no
            // guest-memory access; last-error state remains outside the model.
            handled_scalar_api_return(emu, name, 0)
        }
        "GetCommandLineA" => {
            // Validate the return frame before the first lazy mapping. The
            // returned storage is process-owned, stable, host-independent, and
            // read-only under the bounded environment policy.
            let return_state = preflight_api_return(emu)?;
            let ret = env.ensure_command_line_a(emu)?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
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
        "IsUserAnAdmin" => {
            // The bounded environment exposes an empty supplementary-groups
            // token policy, so the emulated caller is not an administrator.
            handled_scalar_api_return(emu, name, 0)
        }
        "WideCharToMultiByte" => {
            // DWORD/UINT/int arguments consume only their low 32 bits. The
            // retained policy supports the observed CP_ACP, flags-zero,
            // null-terminated printable-ASCII size query and an exactly sized
            // output conversion. General code pages remain unmodeled.
            let code_page = emu.read_reg(RegisterX86::RCX)? as u32;
            let flags = emu.read_reg(RegisterX86::RDX)? as u32;
            let wide_string = emu.read_reg(RegisterX86::R8)?;
            let wide_count = emu.read_reg(RegisterX86::R9)? as u32 as i32;
            let rsp = emu.read_reg(RegisterX86::RSP)?;
            let output_address = checked_stack_argument_address(rsp, 0x28, 8)?;
            let output_size_address = checked_stack_argument_address(rsp, 0x30, 4)?;
            let default_character_address = checked_stack_argument_address(rsp, 0x38, 8)?;
            let used_default_address = checked_stack_argument_address(rsp, 0x40, 8)?;
            let output = read_u64_at(emu, output_address)?;
            let output_size = read_u32_at(emu, output_size_address)? as i32;
            let default_character = read_u64_at(emu, default_character_address)?;
            let used_default = read_u64_at(emu, used_default_address)?;

            if code_page != 0
                || flags != 0
                || wide_string == 0
                || wide_count != -1
                || default_character != 0
                || used_default != 0
                || (output == 0 && output_size != 0)
                || (output != 0 && output_size <= 0)
                || (output != 0 && output == wide_string)
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let units = match read_raw_utf16_z(emu, wide_string, WIDE_CHAR_TO_MULTI_BYTE_UNIT_CAP)?
            {
                RawUtf16Read::Terminated(units)
                    if units.iter().all(|unit| (0x20..=0x7e).contains(unit)) =>
                {
                    units
                }
                RawUtf16Read::Terminated(_) | RawUtf16Read::CapExhausted => {
                    return Ok(ApiOutcome::Unhandled {
                        name: name.to_owned(),
                    });
                }
            };
            let mut converted = units.into_iter().map(|unit| unit as u8).collect::<Vec<_>>();
            converted.push(0);
            let required_size =
                u32::try_from(converted.len()).map_err(|_| EmuError::CodeTooLarge)?;
            if output == 0 {
                return handled_scalar_api_return(emu, name, u64::from(required_size));
            }
            if output_size != required_size as i32 {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let return_state = preflight_api_return(emu)?;
            emu.write_mem(output, &converted)?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, u64::from(required_size))?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: u64::from(required_size),
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
        "FindWindowA" => {
            let class_name = emu.read_reg(RegisterX86::RCX)?;
            let window_name = emu.read_reg(RegisterX86::RDX)?;

            // The observed calls select by either class or title, never both.
            // Other Win32 shapes remain unmodeled and are rejected before
            // pointer or return-frame access.
            if (class_name == 0) == (window_name == 0) {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            let selector = if class_name != 0 {
                class_name
            } else {
                window_name
            };
            match read_raw_ansi_class_name(emu, selector, WINDOW_CLASS_NAME_BYTE_CAP)? {
                RawAnsiClassNameRead::Terminated(bytes) if !bytes.is_empty() => {}
                RawAnsiClassNameRead::Terminated(_)
                | RawAnsiClassNameRead::CapExhausted
                | RawAnsiClassNameRead::NonPrintable => {
                    return Ok(ApiOutcome::Unhandled {
                        name: name.to_owned(),
                    });
                }
            }

            // Midas owns no searchable external top-level-window state. A
            // bounded, valid lookup therefore has the native no-match result:
            // HWND NULL. No window/class registry state is mutated.
            handled_scalar_api_return(emu, name, 0)
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
        "CreateWindowExA" => {
            // DWORD/int arguments use their low 32 bits; pointer/handle
            // arguments retain full width. Geometry and styles are consumed but
            // have no stateful effect in this opaque-window model.
            let _extended_style = emu.read_reg(RegisterX86::RCX)? as u32;
            let class_name = emu.read_reg(RegisterX86::RDX)?;
            let window_name = emu.read_reg(RegisterX86::R8)?;
            let _style = emu.read_reg(RegisterX86::R9)? as u32;
            let rsp = emu.read_reg(RegisterX86::RSP)?;
            let _x = read_u32_at(emu, checked_stack_argument_address(rsp, 0x28, 4)?)? as i32;
            let _y = read_u32_at(emu, checked_stack_argument_address(rsp, 0x30, 4)?)? as i32;
            let width = read_u32_at(emu, checked_stack_argument_address(rsp, 0x38, 4)?)? as i32;
            let height = read_u32_at(emu, checked_stack_argument_address(rsp, 0x40, 4)?)? as i32;
            let parent = read_u64_at(emu, checked_stack_argument_address(rsp, 0x48, 8)?)?;
            let menu = read_u64_at(emu, checked_stack_argument_address(rsp, 0x50, 8)?)?;
            let instance = read_u64_at(emu, checked_stack_argument_address(rsp, 0x58, 8)?)?;
            let parameter = read_u64_at(emu, checked_stack_argument_address(rsp, 0x60, 8)?)?;

            // The observed loader asks for a top-level, untitled ANSI window
            // using an already registered string class. Other valid USER32
            // shapes remain unmodeled without dereferencing their pointers.
            if window_name != 0
                || parent != 0
                || menu != 0
                || parameter != 0
                || width <= 0
                || height <= 0
                || class_name < 0x1_0000
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            let class_name =
                match read_raw_ansi_class_name(emu, class_name, WINDOW_CLASS_NAME_BYTE_CAP)? {
                    RawAnsiClassNameRead::Terminated(bytes) if !bytes.is_empty() => {
                        bytes.into_iter().map(char::from).collect::<String>()
                    }
                    RawAnsiClassNameRead::Terminated(_)
                    | RawAnsiClassNameRead::CapExhausted
                    | RawAnsiClassNameRead::NonPrintable => {
                        return Ok(ApiOutcome::Unhandled {
                            name: name.to_owned(),
                        });
                    }
                };
            let ret = if env.registered_window_class_a(instance, &class_name) {
                EMULATED_WINDOW_HANDLE
            } else {
                0
            };

            // Return only a stable opaque handle. No window record is created,
            // and the registered WndProc is never invoked.
            handled_scalar_api_return(emu, name, ret)
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
        "AllocateAndInitializeSid" => {
            let authority_address = emu.read_reg(RegisterX86::RCX)?;
            // BYTE consumes only the low eight bits on Win64.
            let sub_authority_count = emu.read_reg(RegisterX86::RDX)? as u8;
            if !(1..=SID_MAX_SUB_AUTHORITIES).contains(&sub_authority_count) {
                return handled_scalar_api_return(emu, name, 0);
            }
            let Some((allocation_base, next_cursor, allocation)) =
                env.sid_allocation_candidate(sub_authority_count)
            else {
                return handled_scalar_api_return(emu, name, 0);
            };

            let authority = emu.read_mem(authority_address, SID_IDENTIFIER_AUTHORITY_SIZE)?;
            let mut sub_authorities = Vec::with_capacity(usize::from(sub_authority_count));
            sub_authorities.push(emu.read_reg(RegisterX86::R8)? as u32);
            if sub_authority_count >= 2 {
                sub_authorities.push(emu.read_reg(RegisterX86::R9)? as u32);
            }
            let rsp = emu.read_reg(RegisterX86::RSP)?;
            for index in 2..usize::from(sub_authority_count) {
                let offset = 0x28 + (index as u64 - 2) * 8;
                let address = checked_stack_argument_address(rsp, offset, 4)?;
                sub_authorities.push(read_u32_at(emu, address)?);
            }
            let output_slot = checked_stack_argument_address(rsp, 0x58, 8)?;
            let output = read_u64_at(emu, output_slot)?;

            let return_state = preflight_api_return(emu)?;
            emu.preflight_write_mem(output, std::mem::size_of::<u64>())?;

            let mut sid = Vec::with_capacity(allocation.sid_size as usize);
            sid.push(SID_REVISION);
            sid.push(sub_authority_count);
            sid.extend_from_slice(&authority);
            for sub_authority in sub_authorities {
                sid.extend_from_slice(&sub_authority.to_le_bytes());
            }
            debug_assert_eq!(sid.len(), allocation.sid_size as usize);

            emu.map_zeroed_rw(allocation_base, allocation.mapped_size)?;
            emu.write_mem(allocation_base, &sid)?;
            emu.write_mem(output, &allocation_base.to_le_bytes())?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, 1)?;
            env.commit_sid_allocation(allocation_base, next_cursor, allocation);
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 1,
            })
        }
        "FreeSid" => {
            let sid = emu.read_reg(RegisterX86::RCX)?;
            let live = env.sid_allocations.contains_key(&sid);
            let ret = if live { 0 } else { sid };

            // The bounded arena never unmaps or reuses pages. Only an exact
            // live allocation base is logically freed; interior, unknown, and
            // duplicate values are returned unchanged. Commit control/result
            // before removing metadata so a bad return cannot consume a SID.
            let return_state = preflight_api_return(emu)?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            if live {
                let removed = env.sid_allocations.remove(&sid);
                debug_assert!(removed.is_some());
            }
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "RegOpenKeyA" => {
            let root = emu.read_reg(RegisterX86::RCX)?;
            let subkey = emu.read_reg(RegisterX86::RDX)?;
            let output = emu.read_reg(RegisterX86::R8)?;
            if root != HKEY_LOCAL_MACHINE || subkey == 0 || output == 0 {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            match read_raw_ansi_class_name(emu, subkey, REGISTRY_SUBKEY_BYTE_CAP)? {
                RawAnsiClassNameRead::Terminated(bytes) if !bytes.is_empty() => {}
                RawAnsiClassNameRead::Terminated(_)
                | RawAnsiClassNameRead::CapExhausted
                | RawAnsiClassNameRead::NonPrintable => {
                    return Ok(ApiOutcome::Unhandled {
                        name: name.to_owned(),
                    });
                }
            }

            // The bounded environment owns no registry keys. Return the
            // deterministic native not-found status without reading or
            // changing phkResult; callers retain every output byte.
            handled_scalar_api_return(emu, name, u64::from(ERROR_FILE_NOT_FOUND))
        }
        "OpenProcessToken" => {
            let process = emu.read_reg(RegisterX86::RCX)?;
            let desired_access = emu.read_reg(RegisterX86::RDX)? as u32;
            if process != CURRENT_PROCESS_PSEUDO_HANDLE || desired_access != TOKEN_QUERY {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            let token_output = emu.read_reg(RegisterX86::R8)?;
            let Some((handle, next_handle)) = env.process_token_handle_candidate(desired_access)
            else {
                return handled_scalar_api_return(emu, name, 0);
            };
            let return_state = preflight_api_return(emu)?;
            emu.write_mem(token_output, &handle.to_le_bytes())?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, 1)?;
            env.insert_kernel_handle(
                handle,
                next_handle,
                KernelHandle {
                    object: KernelObject::ProcessToken,
                    desired_access,
                    inheritable: false,
                },
            );
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 1,
            })
        }
        "GetTokenInformation" => {
            let token = emu.read_reg(RegisterX86::RCX)?;
            let information_class = emu.read_reg(RegisterX86::RDX)? as u32;
            let information = emu.read_reg(RegisterX86::R8)?;
            let information_length = emu.read_reg(RegisterX86::R9)? as u32;
            let valid_token = matches!(
                env.kernel_handles.get(&token),
                Some(KernelHandle {
                    object: KernelObject::ProcessToken,
                    desired_access: TOKEN_QUERY,
                    ..
                })
            );
            if !valid_token || information_class != TOKEN_INFORMATION_CLASS_GROUPS {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            let is_size_query = information == 0 && information_length == 0;
            let is_empty_groups_read =
                information != 0 && information_length == EMPTY_TOKEN_GROUPS_SIZE;
            if !is_size_query && !is_empty_groups_read {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let rsp = emu.read_reg(RegisterX86::RSP)?;
            let return_length_slot = checked_stack_argument_address(rsp, 0x28, 8)?;
            let return_length = read_u64_at(emu, return_length_slot)?;
            if is_empty_groups_read
                && equal_sized_ranges_overlap(
                    information,
                    return_length,
                    u64::from(EMPTY_TOKEN_GROUPS_SIZE),
                )
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let return_state = preflight_api_return(emu)?;
            if is_empty_groups_read {
                emu.preflight_write_mem(information, EMPTY_TOKEN_GROUPS_SIZE as usize)?;
            }
            emu.preflight_write_mem(return_length, EMPTY_TOKEN_GROUPS_SIZE as usize)?;

            // The bounded environment exposes no supplementary token groups.
            // A NULL/zero size query returns FALSE and publishes the required
            // four bytes. The matching retrieval writes GroupCount=0 and the
            // same required length, then returns TRUE.
            if is_empty_groups_read {
                emu.write_mem(information, &0u32.to_le_bytes())?;
            }
            emu.write_mem(return_length, &EMPTY_TOKEN_GROUPS_SIZE.to_le_bytes())?;
            commit_api_return(emu, return_state)?;
            let ret = u64::from(is_empty_groups_read);
            emu.write_reg(RegisterX86::RAX, ret)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "OpenThreadToken" => {
            let thread = emu.read_reg(RegisterX86::RCX)?;
            let desired_access = emu.read_reg(RegisterX86::RDX)? as u32;
            let open_as_self = (emu.read_reg(RegisterX86::R8)? as u32) != 0;
            if thread != CURRENT_THREAD_PSEUDO_HANDLE
                || desired_access != TOKEN_QUERY
                || !open_as_self
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // No emulated thread impersonates a client, so it has no thread
            // token to open. The output pointer is deliberately not probed or
            // changed on this deterministic failure path. Last-error state is
            // not modeled by the current environment.
            handled_scalar_api_return(emu, name, 0)
        }
        "NtQuerySystemInformation" => {
            let information_class = emu.read_reg(RegisterX86::RCX)? as u32;
            let information = emu.read_reg(RegisterX86::RDX)?;
            let information_length = emu.read_reg(RegisterX86::R8)? as u32;
            let return_length = emu.read_reg(RegisterX86::R9)?;
            if information_class != SYSTEM_INFORMATION_CLASS_MODULE_INFORMATION
                || return_length != 0
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            // A short buffer cannot hold even NumberOfModules. Report the
            // native length-mismatch status without probing or changing the
            // caller's buffer. ReturnLength remains unsupported until an
            // observed non-NULL form establishes its contract here.
            if information_length < SYSTEM_MODULE_INFORMATION_COUNT_SIZE {
                return handled_scalar_api_return(
                    emu,
                    name,
                    u64::from(STATUS_INFO_LENGTH_MISMATCH),
                );
            }

            // The bounded environment exposes no modeled kernel modules.
            // Validate both control flow and the exact DWORD output before
            // writing NumberOfModules=0; every suffix byte remains guest-owned.
            let return_state = preflight_api_return(emu)?;
            emu.preflight_write_mem(information, SYSTEM_MODULE_INFORMATION_COUNT_SIZE as usize)?;
            emu.write_mem(information, &0u32.to_le_bytes())?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, 0)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: 0,
            })
        }
        "ZwQueryInformationProcess" => {
            let process = emu.read_reg(RegisterX86::RCX)?;
            let information_class = emu.read_reg(RegisterX86::RDX)? as u32;
            let information = emu.read_reg(RegisterX86::R8)?;
            let information_length = emu.read_reg(RegisterX86::R9)? as u32;
            let status = match information_class {
                PROCESS_INFORMATION_CLASS_DEBUG_PORT => 0,
                PROCESS_INFORMATION_CLASS_DEBUG_OBJECT_HANDLE => STATUS_PORT_NOT_SET,
                _ => {
                    return Ok(ApiOutcome::Unhandled {
                        name: name.to_owned(),
                    });
                }
            };
            if process != CURRENT_PROCESS_PSEUDO_HANDLE
                || information_length != std::mem::size_of::<u64>() as u32
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let rsp = emu.read_reg(RegisterX86::RSP)?;
            let return_length_slot = checked_stack_argument_address(rsp, 0x28, 8)?;
            let return_length = read_u64_at(emu, return_length_slot)?;
            if return_length != 0 {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }

            let return_state = preflight_api_return(emu)?;
            emu.preflight_write_mem(information, std::mem::size_of::<u64>())?;
            emu.write_mem(information, &0u64.to_le_bytes())?;
            commit_api_return(emu, return_state)?;
            let ret = u64::from(status);
            emu.write_reg(RegisterX86::RAX, ret)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "ZwSetInformationThread" => {
            let thread = emu.read_reg(RegisterX86::RCX)?;
            let information_class = emu.read_reg(RegisterX86::RDX)? as u32;
            let information = emu.read_reg(RegisterX86::R8)?;
            let information_length = emu.read_reg(RegisterX86::R9)? as u32;
            if thread != CURRENT_THREAD_PSEUDO_HANDLE
                || information_class != THREAD_INFORMATION_CLASS_HIDE_FROM_DEBUGGER
                || information != 0
                || information_length != 0
            {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            handled_scalar_api_return(emu, name, 0)
        }
        "RaiseException" => {
            // DWORD arguments consume the low halves; the exception argument
            // array remains a full-width pointer. The dispatcher builds a
            // guest-visible record/context and leaves RIP at the first VEH.
            let code = emu.read_reg(RegisterX86::RCX)? as u32;
            let flags = emu.read_reg(RegisterX86::RDX)? as u32;
            let argument_count = emu.read_reg(RegisterX86::R8)? as u32;
            let arguments = emu.read_reg(RegisterX86::R9)?;
            if !env.begin_vectored_exception_dispatch(
                emu,
                code,
                flags,
                argument_count,
                arguments,
            )? {
                return Ok(ApiOutcome::Unhandled {
                    name: name.to_owned(),
                });
            }
            Ok(ApiOutcome::HandledVoid {
                name: name.to_owned(),
            })
        }
        "RtlAddVectoredExceptionHandler" => {
            // First is ULONG and consumes only ECX. Handler is a pointer and
            // retains the full RDX value, including NULL or an unmapped value.
            let first = emu.read_reg(RegisterX86::RCX)? as u32;
            let handler = emu.read_reg(RegisterX86::RDX)?;
            let return_state = preflight_api_return(emu)?;
            let ret = env.add_vectored_exception_handler(first, handler);
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret,
            })
        }
        "RtlRemoveVectoredExceptionHandler" => {
            let token = emu.read_reg(RegisterX86::RCX)?;
            let registration_index = env
                .vectored_exception_handlers
                .iter()
                .position(|registration| registration.token == token);
            let ret = u64::from(registration_index.is_some());
            let return_state = preflight_api_return(emu)?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            if let Some(index) = registration_index {
                env.vectored_exception_handlers.remove(index);
            }
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
        "RtlFreeHeap" => {
            let heap_handle = emu.read_reg(RegisterX86::RCX)?;
            // Flags is ULONG, so only EDX participates in the Win64 ABI.
            let flags = emu.read_reg(RegisterX86::RDX)? as u32;
            let allocation_base = emu.read_reg(RegisterX86::R8)?;
            let can_free = env.can_free_heap(heap_handle, flags, allocation_base);
            let ret = u64::from(can_free);

            // A bad return frame must not consume a live allocation. Commit
            // control and the scalar result before changing allocator metadata.
            let return_state = preflight_api_return(emu)?;
            commit_api_return(emu, return_state)?;
            emu.write_reg(RegisterX86::RAX, ret)?;
            if can_free {
                env.commit_heap_free(allocation_base);
            }
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

fn amd64_context_integer_layout() -> [(RegisterX86, usize); 17] {
    [
        (RegisterX86::RAX, AMD64_CONTEXT_RAX_OFFSET),
        (RegisterX86::RCX, AMD64_CONTEXT_RCX_OFFSET),
        (RegisterX86::RDX, AMD64_CONTEXT_RDX_OFFSET),
        (RegisterX86::RBX, AMD64_CONTEXT_RBX_OFFSET),
        (RegisterX86::RSP, AMD64_CONTEXT_RSP_OFFSET),
        (RegisterX86::RBP, AMD64_CONTEXT_RBP_OFFSET),
        (RegisterX86::RSI, AMD64_CONTEXT_RSI_OFFSET),
        (RegisterX86::RDI, AMD64_CONTEXT_RDI_OFFSET),
        (RegisterX86::R8, AMD64_CONTEXT_R8_OFFSET),
        (RegisterX86::R9, AMD64_CONTEXT_R9_OFFSET),
        (RegisterX86::R10, AMD64_CONTEXT_R10_OFFSET),
        (RegisterX86::R11, AMD64_CONTEXT_R11_OFFSET),
        (RegisterX86::R12, AMD64_CONTEXT_R12_OFFSET),
        (RegisterX86::R13, AMD64_CONTEXT_R13_OFFSET),
        (RegisterX86::R14, AMD64_CONTEXT_R14_OFFSET),
        (RegisterX86::R15, AMD64_CONTEXT_R15_OFFSET),
        (RegisterX86::RIP, AMD64_CONTEXT_RIP_OFFSET),
    ]
}

fn snapshot_register_value(
    snapshot: &[u64; EXCEPTION_DISPATCH_REGISTER_ORDER.len()],
    register: RegisterX86,
) -> u64 {
    EXCEPTION_DISPATCH_REGISTER_ORDER
        .iter()
        .position(|candidate| *candidate == register)
        .map_or(0, |index| snapshot[index])
}

fn restore_exception_dispatcher_registers(
    emu: &mut Emu,
    pending: &PendingVectoredException,
) -> Result<(), EmuError> {
    let rollback = emu.capture_cpu_context()?;
    for (register, value) in EXCEPTION_DISPATCH_REGISTER_ORDER
        .into_iter()
        .zip(pending.dispatcher_registers)
    {
        if let Err(error) = emu.write_reg(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    for (register, value) in EXCEPTION_DISPATCH_XMM_REGISTERS
        .into_iter()
        .zip(&pending.dispatcher_xmm_registers)
    {
        if let Err(error) = emu.write_reg_128(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    for (register, value) in EXCEPTION_DISPATCH_X87_REGISTERS
        .into_iter()
        .zip(&pending.dispatcher_x87_registers)
    {
        if let Err(error) = emu.write_reg_80(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    Ok(())
}

fn install_empty_vectored_exception_guard(
    emu: &mut Emu,
    pending: &PendingVectoredException,
) -> Result<(), EmuError> {
    let rollback = emu.capture_cpu_context()?;
    if let Err(error) = (|| {
        restore_exception_dispatcher_registers(emu, pending)?;
        let consumed_rsp =
            pending
                .callback_rsp
                .checked_add(8)
                .ok_or(EmuError::AddressRangeOverflow {
                    base: pending.callback_rsp,
                    size: 8,
                })?;
        emu.write_reg(RegisterX86::RSP, consumed_rsp)?;
        emu.write_reg(RegisterX86::RIP, pending.return_guard)
    })() {
        emu.restore_cpu_context(&rollback)?;
        return Err(error);
    }
    Ok(())
}

fn install_vectored_exception_callback(
    emu: &mut Emu,
    pending: &PendingVectoredException,
) -> Result<(), EmuError> {
    emu.preflight_write_mem(pending.callback_rsp, 0x28)?;
    let return_cell_before = emu.read_mem(pending.callback_rsp, std::mem::size_of::<u64>())?;
    let rollback = emu.capture_cpu_context()?;
    if let Err(error) = (|| {
        write_guest_u64(emu, pending.callback_rsp, pending.return_guard)?;
        restore_exception_dispatcher_registers(emu, pending)?;
        emu.write_reg(RegisterX86::RCX, pending.exception_pointers)?;
        // Wine's x64 call wrapper passes the callback as its second argument,
        // so RDX still contains the handler value at guest callback entry.
        emu.write_reg(RegisterX86::RDX, pending.current_handler)?;
        emu.write_reg(RegisterX86::RSP, pending.callback_rsp)?;
        emu.write_reg(RegisterX86::RIP, pending.current_handler)
    })() {
        emu.restore_cpu_context(&rollback)?;
        emu.write_mem(pending.callback_rsp, &return_cell_before)?;
        return Err(error);
    }
    Ok(())
}

fn amd64_context_register_snapshot(context: &[u8]) -> Vec<(RegisterX86, u64)> {
    let ordered = [
        (RegisterX86::RAX, AMD64_CONTEXT_RAX_OFFSET),
        (RegisterX86::RBX, AMD64_CONTEXT_RBX_OFFSET),
        (RegisterX86::RCX, AMD64_CONTEXT_RCX_OFFSET),
        (RegisterX86::RDX, AMD64_CONTEXT_RDX_OFFSET),
        (RegisterX86::RSI, AMD64_CONTEXT_RSI_OFFSET),
        (RegisterX86::RDI, AMD64_CONTEXT_RDI_OFFSET),
        (RegisterX86::RBP, AMD64_CONTEXT_RBP_OFFSET),
        (RegisterX86::RSP, AMD64_CONTEXT_RSP_OFFSET),
        (RegisterX86::R8, AMD64_CONTEXT_R8_OFFSET),
        (RegisterX86::R9, AMD64_CONTEXT_R9_OFFSET),
        (RegisterX86::R10, AMD64_CONTEXT_R10_OFFSET),
        (RegisterX86::R11, AMD64_CONTEXT_R11_OFFSET),
        (RegisterX86::R12, AMD64_CONTEXT_R12_OFFSET),
        (RegisterX86::R13, AMD64_CONTEXT_R13_OFFSET),
        (RegisterX86::R14, AMD64_CONTEXT_R14_OFFSET),
        (RegisterX86::R15, AMD64_CONTEXT_R15_OFFSET),
        (RegisterX86::RIP, AMD64_CONTEXT_RIP_OFFSET),
    ];
    let mut registers = ordered
        .into_iter()
        .map(|(register, offset)| (register, u64_from_bytes(context, offset)))
        .collect::<Vec<_>>();
    registers.push((
        RegisterX86::EFLAGS,
        u64::from(u32_from_bytes(context, AMD64_CONTEXT_EFLAGS_OFFSET)),
    ));
    registers
}

fn freeze_exception_continuation_target(emu: &Emu, target: u64) -> Result<Vec<u8>, EmuError> {
    let mut bytes = Vec::with_capacity(64);
    for offset in 0..64u64 {
        let address = target
            .checked_add(offset)
            .ok_or(EmuError::AddressRangeOverflow {
                base: target,
                size: offset,
            })?;
        match emu.read_mem(address, 1) {
            Ok(byte) => bytes.push(byte[0]),
            Err(error) if bytes.is_empty() => return Err(error),
            Err(_) => break,
        }
    }
    Ok(bytes)
}

fn is_mutable_amd64_context_byte(index: usize) -> bool {
    let in_range = |offset: usize, size: usize| (offset..offset + size).contains(&index);
    in_range(AMD64_CONTEXT_EFLAGS_OFFSET, 4)
        || amd64_context_integer_layout()
            .into_iter()
            .any(|(_register, offset)| in_range(offset, 8))
}

fn valid_mutated_amd64_context(initial: &[u8], current: &[u8]) -> bool {
    if initial.len() != AMD64_CONTEXT_SIZE
        || current.len() != AMD64_CONTEXT_SIZE
        || u32_from_bytes(current, AMD64_CONTEXT_FLAGS_OFFSET) != CONTEXT_AMD64_CONTROL_INTEGER
    {
        return false;
    }
    initial
        .iter()
        .zip(current)
        .enumerate()
        .all(|(index, (before, after))| is_mutable_amd64_context_byte(index) || before == after)
}

fn restore_amd64_context(
    emu: &mut Emu,
    pending: &PendingVectoredException,
    context: &[u8],
) -> Result<(), EmuError> {
    let mut registers = amd64_context_integer_layout()
        .into_iter()
        .map(|(register, offset)| (register, u64_from_bytes(context, offset)))
        .collect::<Vec<_>>();
    registers.push((
        RegisterX86::EFLAGS,
        u64::from(u32_from_bytes(context, AMD64_CONTEXT_EFLAGS_OFFSET)),
    ));
    registers.push((
        RegisterX86::FS_BASE,
        snapshot_register_value(&pending.dispatcher_registers, RegisterX86::FS_BASE),
    ));
    registers.push((
        RegisterX86::GS_BASE,
        snapshot_register_value(&pending.dispatcher_registers, RegisterX86::GS_BASE),
    ));

    let rollback = emu.capture_cpu_context()?;
    for (register, value) in registers {
        if let Err(error) = emu.write_reg(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    for register in EXCEPTION_DISPATCH_FP_CONTROL_REGISTERS {
        let value = snapshot_register_value(&pending.dispatcher_registers, register);
        if let Err(error) = emu.write_reg(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    for (register, value) in EXCEPTION_DISPATCH_XMM_REGISTERS
        .into_iter()
        .zip(&pending.dispatcher_xmm_registers)
    {
        if let Err(error) = emu.write_reg_128(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    for (register, value) in EXCEPTION_DISPATCH_X87_REGISTERS
        .into_iter()
        .zip(&pending.dispatcher_x87_registers)
    {
        if let Err(error) = emu.write_reg_80(register, value) {
            emu.restore_cpu_context(&rollback)?;
            return Err(error);
        }
    }
    Ok(())
}

fn equal_sized_ranges_overlap(first: u64, second: u64, size: u64) -> bool {
    size != 0 && first.abs_diff(second) < size
}

fn ranges_overlap(first: u64, first_size: u64, second: u64, second_size: u64) -> bool {
    if first_size == 0 || second_size == 0 {
        return false;
    }
    let Some(first_end) = first.checked_add(first_size) else {
        return true;
    };
    let Some(second_end) = second.checked_add(second_size) else {
        return true;
    };
    first < second_end && second < first_end
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

fn checked_context_field_address(
    context: u64,
    offset: usize,
    size: usize,
) -> Result<u64, EmuError> {
    debug_assert!(size > 0);
    let offset = u64::try_from(offset).map_err(|_| EmuError::CodeTooLarge)?;
    let size = u64::try_from(size).map_err(|_| EmuError::CodeTooLarge)?;
    let address = context
        .checked_add(offset)
        .ok_or(EmuError::AddressRangeOverflow {
            base: context,
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

fn preflight_api_return(emu: &Emu) -> Result<(u64, u64), EmuError> {
    let rsp = emu.read_reg(RegisterX86::RSP)?;
    let ret = read_u64_at(emu, rsp)?;
    let new_rsp = rsp
        .checked_add(8)
        .ok_or(EmuError::AddressRangeOverflow { base: rsp, size: 8 })?;
    Ok((ret, new_rsp))
}

fn commit_api_return(emu: &mut Emu, (ret, new_rsp): (u64, u64)) -> Result<(), EmuError> {
    emu.write_reg(RegisterX86::RIP, ret)?;
    emu.write_reg(RegisterX86::RSP, new_rsp)
}

fn api_return(emu: &mut Emu) -> Result<(), EmuError> {
    let return_state = preflight_api_return(emu)?;
    commit_api_return(emu, return_state)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapStop {
    UnhandledApi { name: String, rva: u32 },
    UnhandledSoftwareException { code: u32 },
    NoncontinuableContinuationAttempt { code: u32 },
    InvalidVectoredExceptionDisposition { code: u32, disposition: u32 },
    InvalidVectoredExceptionContext { code: u32 },
    ExceptionContinuationObserved,
    IncompleteVectoredExceptionDispatch { thread_id: u32 },
    UnexpectedFault { address: u64 },
    InstructionCap,
    IndirectTransferObserved,
    IndirectTransferCaptureFailed,
    IndirectTransferStopFailed,
    NullControlTransfer,
    Other(String),
}

/// CPU owner at a watched indirect-transfer boundary.
///
/// The observing scheduler reports this while the named CPU context is still
/// live. In particular, a child observation is delivered before the bounded
/// cooperative switch restores the main context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndirectTransferExecutionContext {
    Main,
    Child { thread_id: u32 },
}

/// Explicit caller disposition for one complete watched transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndirectTransferDisposition {
    /// Preserve the observation and return it as the current run boundary.
    Stop,
    /// The caller has independently adjudicated this exact payload as a false
    /// OEP candidate. Preserve coverage, clear only this observation, and
    /// continue at its still-unexecuted target.
    ResumeAdjudicatedRefutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapRun {
    pub handled: Vec<String>,
    pub stop: TrapStop,
}

/// Boundary at which one coarse cooperative child run stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooperativeThreadStop {
    /// The child reached its per-runtime non-executable return guard with the
    /// stack transition expected after consuming the entry return cell.
    ReachedReturnGuard,
    /// The child completed a supported `Sleep` call and yielded its CPU turn.
    BlockedOnSleep,
    /// The raw trap runner reached another bounded stop.
    Trap(TrapStop),
}

/// Read-only evidence from one production cooperative yield.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeYield {
    pub thread_id: u32,
    pub stack_base: u64,
    pub stack_size: u64,
    pub teb_base: u64,
    pub entry_rsp: u64,
    pub handled: Vec<String>,
    pub stop: CooperativeThreadStop,
    pub instructions_executed: u64,
}

/// Production trap result with coarse `Sleep`-as-yield observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeTrapRun {
    pub handled: Vec<String>,
    pub cooperative_yields: Vec<CooperativeYield>,
    pub main_instructions_after_first_yield: u64,
    pub stop: TrapStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CooperativeRuntime {
    stack_base: u64,
    teb_base: u64,
    entry_rsp: u64,
    return_guard: u64,
}

fn pending_api_at(
    env: &Win64Env,
    emu: &Emu,
    image: &pe::PeImage,
    address: u64,
) -> Option<(String, u32)> {
    env.stub_export_at(address)
        .or_else(|| env.proc_stub_at(address))
        .or_else(|| {
            (address < u64::from(image.size_of_image))
                .then(|| {
                    read_import_by_name(emu, image.image_base, image.size_of_image, address as u32)
                        .map(|name| (name, address as u32))
                })
                .flatten()
        })
}

fn is_call_bound_stop(stop: &TrapStop) -> bool {
    matches!(stop, TrapStop::Other(message) if message == "max_calls reached")
}

fn write_guest_u64(emu: &mut Emu, address: u64, value: u64) -> Result<(), EmuError> {
    emu.write_mem(address, &value.to_le_bytes())
}

fn configure_cooperative_runtime(
    env: &mut Win64Env,
    emu: &mut Emu,
    thread_id: u32,
    thread: RunnableUnscheduledThread,
) -> Result<CooperativeRuntime, EmuError> {
    let (runtime_base, next_runtime_base) =
        env.cooperative_runtime_candidate()
            .ok_or(EmuError::AddressRangeOverflow {
                base: env.next_cooperative_runtime_base,
                size: COOPERATIVE_THREAD_RUNTIME_SIZE,
            })?;
    let stack_end = runtime_base
        .checked_add(STACK_SIZE)
        .ok_or(EmuError::AddressRangeOverflow {
            base: runtime_base,
            size: STACK_SIZE,
        })?;
    let teb_base = stack_end;
    let entry_rsp = stack_end
        .checked_sub(COOPERATIVE_THREAD_ENTRY_HEADROOM + 8)
        .ok_or(EmuError::AddressRangeOverflow {
            base: runtime_base,
            size: STACK_SIZE,
        })?;
    if entry_rsp & 0xf != 8 {
        return Err(EmuError::AddressRangeOverflow {
            base: entry_rsp,
            size: 8,
        });
    }

    // One mapping makes each selected child stack + TEB fresh and zeroed.
    emu.map_zeroed_rw(runtime_base, COOPERATIVE_THREAD_RUNTIME_SIZE)?;
    if !env.claim_thread_for_cooperative_run(thread_id, next_runtime_base) {
        return Err(EmuError::AddressRangeOverflow {
            base: runtime_base,
            size: COOPERATIVE_THREAD_RUNTIME_SIZE,
        });
    }

    // The TEB is already mapped RW/NX. Reuse its base as a per-runtime return
    // guard so the entry return target is both nonzero and reserved.
    let return_guard = teb_base;
    write_guest_u64(emu, entry_rsp, return_guard)?;
    write_guest_u64(emu, teb_base + TEB_STACKBASE_OFFSET, stack_end)?;
    write_guest_u64(emu, teb_base + TEB_STACKLIMIT_OFFSET, runtime_base)?;
    write_guest_u64(emu, teb_base + TEB_SELF_OFFSET, teb_base)?;
    write_guest_u64(emu, teb_base + TEB_PEB_OFFSET, PEB_BASE)?;

    for register in [
        RegisterX86::RAX,
        RegisterX86::RBX,
        RegisterX86::RCX,
        RegisterX86::RDX,
        RegisterX86::RSI,
        RegisterX86::RDI,
        RegisterX86::RBP,
        RegisterX86::R8,
        RegisterX86::R9,
        RegisterX86::R10,
        RegisterX86::R11,
        RegisterX86::R12,
        RegisterX86::R13,
        RegisterX86::R14,
        RegisterX86::R15,
        RegisterX86::FS_BASE,
    ] {
        emu.write_reg(register, 0)?;
    }
    emu.write_reg(RegisterX86::RCX, thread.parameter)?;
    emu.write_reg(RegisterX86::RSP, entry_rsp)?;
    emu.write_reg(RegisterX86::RIP, thread.start_address)?;
    emu.write_reg(RegisterX86::GS_BASE, teb_base)?;
    emu.write_reg(RegisterX86::EFLAGS, 2)?;

    Ok(CooperativeRuntime {
        stack_base: runtime_base,
        teb_base,
        entry_rsp,
        return_guard,
    })
}

fn disposition_allows_resume<F>(
    emu: &mut Emu,
    context: IndirectTransferExecutionContext,
    on_transfer: &mut F,
) -> Result<bool, EmuError>
where
    F: FnMut(
        IndirectTransferExecutionContext,
        &IndirectTransferObservation,
    ) -> IndirectTransferDisposition,
{
    let observation = emu
        .indirect_transfer_observation()
        .ok_or(EmuError::IndirectTransferWatchNotLatched)?;
    match on_transfer(context, &observation) {
        IndirectTransferDisposition::Stop => Ok(false),
        IndirectTransferDisposition::ResumeAdjudicatedRefutation => {
            emu.rearm_indirect_transfer_watch_after_refuted(&observation)?;
            Ok(true)
        }
    }
}

fn run_cooperative_child<F>(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &pe::PeImage,
    thread_id: u32,
    begin: u64,
    runtime: CooperativeRuntime,
    on_transfer: &mut F,
) -> Result<(Vec<String>, CooperativeThreadStop, u64), EmuError>
where
    F: FnMut(
        IndirectTransferExecutionContext,
        &IndirectTransferObservation,
    ) -> IndirectTransferDisposition,
{
    let start_count = emu.total_instructions_executed();
    let mut handled = Vec::new();
    let mut next = begin;

    loop {
        let elapsed = emu
            .total_instructions_executed()
            .saturating_sub(start_count);
        let Some(remaining) = COOPERATIVE_CHILD_INSTRUCTION_CAP.checked_sub(elapsed) else {
            return Ok((
                handled,
                CooperativeThreadStop::Trap(TrapStop::InstructionCap),
                elapsed,
            ));
        };
        if remaining == 0 {
            return Ok((
                handled,
                CooperativeThreadStop::Trap(TrapStop::InstructionCap),
                elapsed,
            ));
        }

        // A zero API budget turns the raw runner into a bounded execution leg
        // that stops immediately before the next recognized call boundary.
        let leg = run_with_import_trap(env, emu, image, next, remaining, 0)?;
        debug_assert!(leg.handled.is_empty());
        if !is_call_bound_stop(&leg.stop) {
            if leg.stop == TrapStop::IndirectTransferObserved
                && disposition_allows_resume(
                    emu,
                    IndirectTransferExecutionContext::Child { thread_id },
                    on_transfer,
                )?
            {
                next = emu.read_reg(RegisterX86::RIP)?;
                continue;
            }
            let final_rip = emu.read_reg(RegisterX86::RIP)?;
            let final_rsp = emu.read_reg(RegisterX86::RSP)?;
            let stop = if matches!(
                leg.stop,
                TrapStop::UnexpectedFault {
                    address
                } if address == runtime.return_guard
            ) && final_rip == runtime.return_guard
                && runtime.entry_rsp.checked_add(8) == Some(final_rsp)
            {
                CooperativeThreadStop::ReachedReturnGuard
            } else {
                CooperativeThreadStop::Trap(leg.stop)
            };
            let elapsed = emu
                .total_instructions_executed()
                .saturating_sub(start_count);
            return Ok((handled, stop, elapsed));
        }

        next = emu.read_reg(RegisterX86::RIP)?;
        let Some((name, rva)) = pending_api_at(env, emu, image, next) else {
            return Ok((
                handled,
                CooperativeThreadStop::Trap(TrapStop::UnexpectedFault { address: next }),
                emu.total_instructions_executed()
                    .saturating_sub(start_count),
            ));
        };
        if handled.len() >= COOPERATIVE_CHILD_API_CAP {
            return Ok((
                handled,
                CooperativeThreadStop::Trap(TrapStop::Other(
                    "cooperative child API cap reached".to_owned(),
                )),
                emu.total_instructions_executed()
                    .saturating_sub(start_count),
            ));
        }

        match dispatch(env, emu, &name)? {
            ApiOutcome::Handled { name, .. } | ApiOutcome::HandledVoid { name } => {
                let blocked = name == "Sleep" && !env.has_pending_vectored_exception();
                handled.push(name);
                if blocked {
                    return Ok((
                        handled,
                        CooperativeThreadStop::BlockedOnSleep,
                        emu.total_instructions_executed()
                            .saturating_sub(start_count),
                    ));
                }
                next = emu.read_reg(RegisterX86::RIP)?;
            }
            ApiOutcome::Unhandled { name } => {
                return Ok((
                    handled,
                    CooperativeThreadStop::Trap(TrapStop::UnhandledApi { name, rva }),
                    emu.total_instructions_executed()
                        .saturating_sub(start_count),
                ));
            }
        }
    }
}

fn yield_to_next_runnable_thread<F>(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &pe::PeImage,
    on_transfer: &mut F,
) -> Result<Option<CooperativeYield>, EmuError>
where
    F: FnMut(
        IndirectTransferExecutionContext,
        &IndirectTransferObservation,
    ) -> IndirectTransferDisposition,
{
    let next_thread = env
        .runnable_unscheduled_threads()
        .next()
        .map(|(thread_id, &thread)| (thread_id, thread));
    let Some((thread_id, thread)) = next_thread else {
        return Ok(None);
    };

    // CPU-only context capture is the switch primitive. Guest memory, module
    // state, heap metadata, and Win64Env remain live while the child runs.
    let main_context = emu.capture_cpu_context()?;
    let previous_thread_id = env.current_thread_id;
    let child_result = (|| {
        let runtime = configure_cooperative_runtime(env, emu, thread_id, thread)?;
        env.current_thread_id = thread_id;
        let (handled, stop, instructions_executed) = run_cooperative_child(
            env,
            emu,
            image,
            thread_id,
            thread.start_address,
            runtime,
            on_transfer,
        )?;
        Ok(CooperativeYield {
            thread_id,
            stack_base: runtime.stack_base,
            stack_size: STACK_SIZE,
            teb_base: runtime.teb_base,
            entry_rsp: runtime.entry_rsp,
            handled,
            stop,
            instructions_executed,
        })
    })();
    env.current_thread_id = previous_thread_id;
    let restore_result = emu.restore_cpu_context(&main_context);
    restore_result?;
    child_result.map(Some)
}

/// Run the loader with one bounded cooperative policy: a supported main-thread
/// `Sleep` yields once to the lowest-ID runnable-unscheduled child, if present.
///
/// The child runs coarsely until it returns, completes its own `Sleep`, reaches
/// an API/fault wall, or exhausts an independent instruction/API cap. Its CPU
/// state is then discarded, the main CPU context is restored, and all guest
/// memory and environment writes remain live. This is not general scheduling
/// or a thread-lifecycle model.
pub fn run_with_cooperative_scheduler(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &pe::PeImage,
    begin: u64,
    per_run_cap: u64,
    max_calls: usize,
) -> Result<CooperativeTrapRun, EmuError> {
    run_with_cooperative_scheduler_observing(
        env,
        emu,
        image,
        begin,
        per_run_cap,
        max_calls,
        |_: IndirectTransferExecutionContext, _: &IndirectTransferObservation| {
            IndirectTransferDisposition::Stop
        },
    )
}

/// Run the bounded cooperative scheduler while allowing a caller to dispose
/// each complete watched indirect transfer synchronously.
///
/// The callback runs before any child CPU context is discarded. Returning
/// [`IndirectTransferDisposition::ResumeAdjudicatedRefutation`] invokes the
/// coverage-preserving exact-observation rearm transition and resumes at the
/// frozen, not-yet-executed target. Capture failures and emulator stop failures
/// never reach the callback and remain fail-closed run boundaries.
#[allow(clippy::too_many_arguments)]
pub fn run_with_cooperative_scheduler_observing<F>(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &pe::PeImage,
    begin: u64,
    per_run_cap: u64,
    max_calls: usize,
    mut on_transfer: F,
) -> Result<CooperativeTrapRun, EmuError>
where
    F: FnMut(
        IndirectTransferExecutionContext,
        &IndirectTransferObservation,
    ) -> IndirectTransferDisposition,
{
    let mut handled = Vec::new();
    let mut cooperative_yields = Vec::new();
    let mut main_instructions_after_first_yield = 0u64;
    let mut has_yielded = false;
    let mut next = begin;

    loop {
        let before = emu.total_instructions_executed();
        let leg = run_with_import_trap(env, emu, image, next, per_run_cap, 0)?;
        let main_delta = emu.total_instructions_executed().saturating_sub(before);
        if has_yielded {
            main_instructions_after_first_yield =
                main_instructions_after_first_yield.saturating_add(main_delta);
        }
        debug_assert!(leg.handled.is_empty());
        if !is_call_bound_stop(&leg.stop) {
            if leg.stop == TrapStop::IndirectTransferObserved
                && disposition_allows_resume(
                    emu,
                    IndirectTransferExecutionContext::Main,
                    &mut on_transfer,
                )?
            {
                next = emu.read_reg(RegisterX86::RIP)?;
                continue;
            }
            return Ok(CooperativeTrapRun {
                handled,
                cooperative_yields,
                main_instructions_after_first_yield,
                stop: leg.stop,
            });
        }

        next = emu.read_reg(RegisterX86::RIP)?;
        let Some((name, rva)) = pending_api_at(env, emu, image, next) else {
            return Ok(CooperativeTrapRun {
                handled,
                cooperative_yields,
                main_instructions_after_first_yield,
                stop: TrapStop::UnexpectedFault { address: next },
            });
        };
        if handled.len() >= max_calls {
            return Ok(CooperativeTrapRun {
                handled,
                cooperative_yields,
                main_instructions_after_first_yield,
                stop: TrapStop::Other("max_calls reached".to_owned()),
            });
        }

        match dispatch(env, emu, &name)? {
            ApiOutcome::Handled { name, .. } | ApiOutcome::HandledVoid { name } => {
                let should_yield = name == "Sleep"
                    && !env.has_pending_vectored_exception()
                    && env.runnable_unscheduled_threads().next().is_some();
                handled.push(name);
                next = emu.read_reg(RegisterX86::RIP)?;
                if should_yield {
                    if let Some(yielded) =
                        yield_to_next_runnable_thread(env, emu, image, &mut on_transfer)?
                    {
                        let propagated_watch_stop = match &yielded.stop {
                            CooperativeThreadStop::Trap(
                                stop @ (TrapStop::IndirectTransferObserved
                                | TrapStop::IndirectTransferCaptureFailed
                                | TrapStop::IndirectTransferStopFailed
                                | TrapStop::ExceptionContinuationObserved
                                | TrapStop::UnhandledSoftwareException { .. }
                                | TrapStop::NoncontinuableContinuationAttempt { .. }
                                | TrapStop::InvalidVectoredExceptionDisposition { .. }
                                | TrapStop::InvalidVectoredExceptionContext { .. }),
                            ) => Some(stop.clone()),
                            _ if env
                                .pending_vectored_exceptions
                                .contains_key(&yielded.thread_id) =>
                            {
                                Some(TrapStop::IncompleteVectoredExceptionDispatch {
                                    thread_id: yielded.thread_id,
                                })
                            }
                            _ => None,
                        };
                        cooperative_yields.push(yielded);
                        has_yielded = true;
                        next = emu.read_reg(RegisterX86::RIP)?;
                        if let Some(stop) = propagated_watch_stop {
                            return Ok(CooperativeTrapRun {
                                handled,
                                cooperative_yields,
                                main_instructions_after_first_yield,
                                stop,
                            });
                        }
                    }
                }
            }
            ApiOutcome::Unhandled { name } => {
                return Ok(CooperativeTrapRun {
                    handled,
                    cooperative_yields,
                    main_instructions_after_first_yield,
                    stop: TrapStop::UnhandledApi { name, rva },
                });
            }
        }
    }
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
    if env.changed_exception_continuation.is_some() {
        return Ok(TrapRun {
            handled,
            stop: TrapStop::ExceptionContinuationObserved,
        });
    }
    let mut rip = begin;

    loop {
        let report = emu.resume(rip, per_run_cap)?;
        match report.stop_reason {
            StopReason::MemoryFault(fault)
                if matches!(fault.kind, FaultKind::FetchUnmapped | FaultKind::FetchProt) =>
            {
                if let Some(transition) =
                    env.advance_vectored_exception_dispatch_on_guard(emu, fault.address)?
                {
                    match transition {
                        VectoredExceptionReturn::Resume => {
                            rip = emu.read_reg(RegisterX86::RIP)?;
                            continue;
                        }
                        VectoredExceptionReturn::ChangedContinuation => {
                            return Ok(TrapRun {
                                handled,
                                stop: TrapStop::ExceptionContinuationObserved,
                            });
                        }
                        VectoredExceptionReturn::HandlersExhausted { code } => {
                            return Ok(TrapRun {
                                handled,
                                stop: TrapStop::UnhandledSoftwareException { code },
                            });
                        }
                        VectoredExceptionReturn::Noncontinuable { code } => {
                            return Ok(TrapRun {
                                handled,
                                stop: TrapStop::NoncontinuableContinuationAttempt { code },
                            });
                        }
                        VectoredExceptionReturn::InvalidDisposition { code, disposition } => {
                            return Ok(TrapRun {
                                handled,
                                stop: TrapStop::InvalidVectoredExceptionDisposition {
                                    code,
                                    disposition,
                                },
                            });
                        }
                        VectoredExceptionReturn::InvalidContext { code } => {
                            return Ok(TrapRun {
                                handled,
                                stop: TrapStop::InvalidVectoredExceptionContext { code },
                            });
                        }
                    }
                }

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
            StopReason::IndirectTransferObserved => {
                return Ok(TrapRun {
                    handled,
                    stop: TrapStop::IndirectTransferObserved,
                });
            }
            StopReason::IndirectTransferCaptureFailed => {
                return Ok(TrapRun {
                    handled,
                    stop: TrapStop::IndirectTransferCaptureFailed,
                });
            }
            StopReason::IndirectTransferStopFailed => {
                return Ok(TrapRun {
                    handled,
                    stop: TrapStop::IndirectTransferStopFailed,
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
    use sha2::{Digest, Sha256};

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
            base_of_code: CODE_RVA,
            size_of_code: 0x1000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
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

    fn observed_register(observation: &IndirectTransferObservation, register: RegisterX86) -> u64 {
        observation
            .registers
            .iter()
            .find_map(|(observed, value)| (*observed == register).then_some(*value))
            .unwrap_or_else(|| panic!("missing {register:?} from indirect-transfer snapshot"))
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
    const WIDE_STRING_ADDRESS: u64 = crate::emu::STACK_BASE + 0x6000;
    const WINDOW_PROCEDURE_SENTINEL: u64 = 0x0000_0001_5000_1230;
    const ALTERNATE_WINDOW_PROCEDURE_SENTINEL: u64 = 0x0000_0001_5000_1240;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct WideCharToMultiByteArgs {
        code_page: u64,
        flags: u64,
        wide_string: u64,
        wide_count: u64,
        output: u64,
        output_size_slot: u64,
        default_character: u64,
        used_default: u64,
    }

    impl WideCharToMultiByteArgs {
        fn observed(wide_string: u64) -> Self {
            Self {
                code_page: 0xaaaa_bbbb_0000_0000,
                flags: 0xcccc_dddd_0000_0000,
                wide_string,
                wide_count: 0x1234_5678_ffff_ffff,
                output: 0,
                output_size_slot: 0xeeee_ffff_0000_0000,
                default_character: 0,
                used_default: 0,
            }
        }
    }

    fn prepare_wide_char_to_multi_byte_call(
        emu: &mut Emu,
        args: WideCharToMultiByteArgs,
        rsp: u64,
        return_address: Option<u64>,
    ) {
        if let Some(return_address) = return_address {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        }
        for (offset, value) in [
            (0x28, args.output),
            (0x30, args.output_size_slot),
            (0x38, args.default_character),
            (0x40, args.used_default),
        ] {
            emu.write_mem(rsp + offset, &value.to_le_bytes()).unwrap();
        }
        seed_sleep_machine_state(emu, args.code_page, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, args.flags).unwrap();
        emu.write_reg(RegisterX86::R8, args.wide_string).unwrap();
        emu.write_reg(RegisterX86::R9, args.wide_count).unwrap();
    }

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CreateWindowExAArgs {
        extended_style: u64,
        class_name: u64,
        window_name: u64,
        style: u64,
        x: u64,
        y: u64,
        width: u64,
        height: u64,
        parent: u64,
        menu: u64,
        instance: u64,
        parameter: u64,
    }

    impl CreateWindowExAArgs {
        fn observed(class_name: u64) -> Self {
            Self {
                extended_style: 0xaaaa_bbbb_0000_0008,
                class_name,
                window_name: 0,
                style: 0xcccc_dddd_9000_0000,
                x: 0x1111_2222_0000_8000,
                y: 0x3333_4444_0000_8000,
                width: 0x5555_6666_0000_0237,
                height: 0x7777_8888_0000_012b,
                parent: 0,
                menu: 0,
                instance: IMAGE_BASE,
                parameter: 0,
            }
        }
    }

    fn prepare_create_window_ex_a_call(
        emu: &mut Emu,
        args: CreateWindowExAArgs,
        rsp: u64,
        return_address: Option<u64>,
    ) {
        if let Some(return_address) = return_address {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        }
        for (offset, value) in [
            (0x28, args.x),
            (0x30, args.y),
            (0x38, args.width),
            (0x40, args.height),
            (0x48, args.parent),
            (0x50, args.menu),
            (0x58, args.instance),
            (0x60, args.parameter),
        ] {
            emu.write_mem(rsp + offset, &value.to_le_bytes()).unwrap();
        }
        seed_sleep_machine_state(emu, args.extended_style, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, args.class_name).unwrap();
        emu.write_reg(RegisterX86::R8, args.window_name).unwrap();
        emu.write_reg(RegisterX86::R9, args.style).unwrap();
    }

    fn call_create_window_ex_a(
        env: &mut Win64Env,
        emu: &mut Emu,
        args: CreateWindowExAArgs,
        rsp: u64,
        return_address: u64,
    ) -> ApiOutcome {
        prepare_create_window_ex_a_call(emu, args, rsp, Some(return_address));
        dispatch(env, emu, "CreateWindowExA").unwrap()
    }

    fn register_test_window_class(env: &mut Win64Env, emu: &mut Emu, rsp: u64) {
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"MidasTestClass\0")
            .unwrap();
        let ret = call_register_class_ex_a(
            env,
            emu,
            RegisterClassExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            b"MidasTestClass\0",
            rsp,
            0x1357_2468_ace0_bdf1,
        );
        assert_ne!(ret, 0);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct VirtualAllocArgs {
        requested_address: u64,
        requested_size: u64,
        allocation_type: u64,
        protection: u64,
    }

    impl VirtualAllocArgs {
        fn observed(requested_size: u64) -> Self {
            Self {
                requested_address: 0,
                requested_size,
                allocation_type: u64::from(MEM_COMMIT),
                protection: u64::from(PAGE_READWRITE),
            }
        }
    }

    fn prepare_virtual_alloc_call(
        emu: &mut Emu,
        args: VirtualAllocArgs,
        rsp: u64,
        return_address: Option<u64>,
    ) {
        if let Some(return_address) = return_address {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        }
        seed_sleep_machine_state(emu, args.requested_address, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, args.requested_size)
            .unwrap();
        emu.write_reg(RegisterX86::R8, args.allocation_type)
            .unwrap();
        emu.write_reg(RegisterX86::R9, args.protection).unwrap();
    }

    fn call_virtual_alloc(
        env: &mut Win64Env,
        emu: &mut Emu,
        args: VirtualAllocArgs,
        rsp: u64,
        return_address: u64,
    ) -> u64 {
        prepare_virtual_alloc_call(emu, args, rsp, Some(return_address));
        let outcome = dispatch(env, emu, "VirtualAlloc").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected VirtualAlloc to be handled");
        };
        assert_eq!(name, "VirtualAlloc");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    fn prepare_virtual_free_call(
        emu: &mut Emu,
        allocation_base: u64,
        size: u64,
        free_type: u64,
        rsp: u64,
        return_address: Option<u64>,
    ) {
        if let Some(return_address) = return_address {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        }
        emu.write_reg(RegisterX86::RCX, allocation_base).unwrap();
        emu.write_reg(RegisterX86::RDX, size).unwrap();
        emu.write_reg(RegisterX86::R8, free_type).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
    }

    fn call_virtual_free(
        env: &mut Win64Env,
        emu: &mut Emu,
        allocation_base: u64,
        free_type: u64,
    ) -> u64 {
        let rsp = STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0u64;
        prepare_virtual_free_call(
            emu,
            allocation_base,
            0,
            free_type,
            rsp,
            Some(return_address),
        );
        let outcome = dispatch(env, emu, "VirtualFree").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected VirtualFree to be handled");
        };
        assert_eq!(name, "VirtualFree");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
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

    fn call_rtl_free_heap(
        env: &mut Win64Env,
        emu: &mut Emu,
        heap_handle: u64,
        flags: u64,
        allocation_base: u64,
        rsp: u64,
        return_address: u64,
    ) -> u64 {
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, heap_handle).unwrap();
        emu.write_reg(RegisterX86::RDX, flags).unwrap();
        emu.write_reg(RegisterX86::R8, allocation_base).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "RtlFreeHeap").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected RtlFreeHeap to be handled");
        };
        assert_eq!(name, "RtlFreeHeap");
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestRaiseExceptionArgs {
        code: u64,
        flags: u64,
        argument_count: u64,
        arguments: u64,
        rsp: u64,
        return_address: u64,
    }

    fn begin_test_raise_exception(
        env: &mut Win64Env,
        emu: &mut Emu,
        args: TestRaiseExceptionArgs,
    ) -> ApiOutcome {
        emu.write_mem(args.rsp, &args.return_address.to_le_bytes())
            .unwrap();
        seed_sleep_machine_state(emu, args.code, args.rsp, 0x0000_7fff_1234_5000);
        emu.write_reg(RegisterX86::RDX, args.flags).unwrap();
        emu.write_reg(RegisterX86::R8, args.argument_count).unwrap();
        emu.write_reg(RegisterX86::R9, args.arguments).unwrap();
        dispatch(env, emu, "RaiseException").unwrap()
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

    fn call_close_handle(env: &mut Win64Env, emu: &mut Emu, handle: u64) -> u64 {
        let rsp = STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, handle).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let outcome = dispatch(env, emu, "CloseHandle").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected CloseHandle to be handled");
        };
        assert_eq!(name, "CloseHandle");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        ret
    }

    fn prepare_allocate_sid_call(
        emu: &mut Emu,
        authority: u64,
        count: u64,
        sub_authorities: [u64; 8],
        output: u64,
        rsp: u64,
        return_address: Option<u64>,
    ) {
        if let Some(return_address) = return_address {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        }
        for (index, value) in sub_authorities[2..].iter().enumerate() {
            emu.write_mem(rsp + 0x28 + index as u64 * 8, &value.to_le_bytes())
                .unwrap();
        }
        emu.write_mem(rsp + 0x58, &output.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, authority).unwrap();
        emu.write_reg(RegisterX86::RDX, count).unwrap();
        emu.write_reg(RegisterX86::R8, sub_authorities[0]).unwrap();
        emu.write_reg(RegisterX86::R9, sub_authorities[1]).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
    }

    fn call_free_sid(env: &mut Win64Env, emu: &mut Emu, sid: u64) -> u64 {
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, sid).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let outcome = dispatch(env, emu, "FreeSid").unwrap();
        let ApiOutcome::Handled { name, ret } = outcome else {
            panic!("expected FreeSid to be handled");
        };
        assert_eq!(name, "FreeSid");
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
        let module = SyntheticModule::build(
            FAKE_MODULE_BASE_START,
            "kernel32.dll",
            KERNEL32_EXPORTS.as_slice(),
        );
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
    fn kernel32_export_name_snapshot_is_content_addressed() {
        let bytes = include_bytes!("kernel32_exports.txt");
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(KERNEL32_EXPORTS.len(), 1_664);
        assert_eq!(bytes.len(), 34_362);
        assert_eq!(
            digest,
            "1e76115f6f88c0acc5ec0dcb985600d7cba525b5dcf64aa20de262e1728c21a3"
        );
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
    fn diagnostic_export_name_control_is_bounded_preload_only_and_projects_range() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let names = vec!["Alpha".to_owned(), "Beta".to_owned()];

        assert!(env.configure_module_export_name_control("Controlled", &names));
        assert!(!env.module_export_name_control_was_applied("controlled.dll"));
        assert!(!env
            .configure_module_export_name_control("controlled.dll", &["Replacement".to_owned()]));
        let base = env
            .ensure_loaded_module(&mut emu, "controlled.dll")
            .unwrap();
        let module = env.synthetic_modules.get("controlled.dll").unwrap();
        assert_eq!(module.exports.keys().cloned().collect::<Vec<_>>(), names);
        let image_len = module.image.len() as u64;
        assert!(env.module_export_name_control_was_applied("CONTROLLED"));
        assert!(!env.configure_module_export_name_control("controlled.dll", &["Gamma".to_owned()]));

        let ranges = env.synthetic_module_image_ranges().collect::<Vec<_>>();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0, "controlled.dll");
        assert_eq!(ranges[0].1, base);
        assert_eq!(ranges[0].2, base + image_len);

        let mut fresh = Win64Env::new(IMAGE_BASE);
        assert!(!fresh.configure_module_export_name_control("", &names));
        assert!(!fresh.configure_module_export_name_control(
            "dup.dll",
            &["Same".to_owned(), "Same".to_owned()]
        ));
        assert!(!fresh.configure_module_export_name_control(
            "unsorted.dll",
            &["Beta".to_owned(), "Alpha".to_owned()]
        ));
        assert!(!fresh.configure_module_export_name_control("bad.dll", &["has space".to_owned()]));
        assert!(!fresh
            .configure_module_export_name_control("long.dll", &["A".repeat(IMPORT_NAME_CAP + 1)]));
        assert!(!fresh.configure_module_export_name_control(
            "many.dll",
            &vec!["Name".to_owned(); DIAGNOSTIC_EXPORT_NAME_CAP + 1]
        ));

        let mut kernel_emu = Emu::new().unwrap();
        let mut kernel_env = Win64Env::new(IMAGE_BASE);
        let kernel_names = vec!["OnlyDiagnosticName".to_owned()];
        assert!(kernel_env.configure_module_export_name_control("kernel32", &kernel_names));
        kernel_env.ensure_kernel32(&mut kernel_emu).unwrap();
        assert!(kernel_env.module_export_name_control_was_applied("KERNEL32.DLL"));
        assert_eq!(
            kernel_env
                .synthetic_modules
                .get("kernel32.dll")
                .unwrap()
                .exports
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            kernel_names
        );
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
        let mut expected = NTDLL_EXPORTS.to_vec();
        expected.sort_unstable();
        assert_eq!(names, expected);
    }

    #[test]
    fn msvcrt_catalog_exposes_declared_bootstrap_handler() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let base = env.ensure_loaded_module(&mut emu, "msvcrt.dll").unwrap();
        let module = env.synthetic_modules.get("msvcrt.dll").unwrap();

        assert_eq!(module.base, base);
        assert_eq!(module.exports.len(), 26);
        let handler = module.export_stub("__C_specific_handler").unwrap();
        assert_eq!(
            env.callable_stub_name_at(handler).as_deref(),
            Some("__C_specific_handler")
        );
        assert!(emu
            .read_mem(handler, SYNTHETIC_STUB_STRIDE as usize)
            .is_ok());
    }

    #[test]
    fn msvcrt_export_name_snapshot_is_content_addressed() {
        let bytes = include_bytes!("msvcrt_exports.txt");
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(MSVCRT_EXPORTS.len(), 26);
        assert_eq!(bytes.len(), 244);
        assert_eq!(
            digest,
            "f69340427263b932fb80b908063a026e469ce91300485e1ff335238d719f9fc9"
        );
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
        assert_eq!(count as usize, NTDLL_EXPORTS.len());
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
        let mut expected = NTDLL_EXPORTS.to_vec();
        expected.sort_unstable();
        assert_eq!(names, expected);
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
    fn current_process_and_thread_return_full_width_pseudo_handles() {
        for (name, expected) in [
            ("GetCurrentProcess", CURRENT_PROCESS_PSEUDO_HANDLE),
            ("GetCurrentThread", CURRENT_THREAD_PSEUDO_HANDLE),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let rsp = crate::emu::STACK_BASE + 0x400;
            let return_address = 0x1234_5678_9abc_def0_u64;
            let rcx = 0x1111_2222_3333_4444;
            let rdx = 0x5555_6666_7777_8888;
            let r8 = 0x9999_aaaa_bbbb_cccc;
            let r9 = 0xdddd_eeee_ffff_0000;
            let flags = 0x246;
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            emu.write_reg(RegisterX86::RAX, 0).unwrap();
            emu.write_reg(RegisterX86::RCX, rcx).unwrap();
            emu.write_reg(RegisterX86::RDX, rdx).unwrap();
            emu.write_reg(RegisterX86::R8, r8).unwrap();
            emu.write_reg(RegisterX86::R9, r9).unwrap();
            emu.write_reg(RegisterX86::EFLAGS, flags).unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();

            assert_eq!(
                dispatch(&mut env, &mut emu, name).unwrap(),
                ApiOutcome::Handled {
                    name: name.to_owned(),
                    ret: expected,
                }
            );
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
            assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), rcx);
            assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), rdx);
            assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), r8);
            assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), r9);
            assert_eq!(emu.read_reg(RegisterX86::EFLAGS).unwrap(), flags);
        }
    }

    #[test]
    fn current_pseudo_handles_preflight_return_before_changing_rax() {
        for name in ["GetCurrentProcess", "GetCurrentThread"] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let invalid_rsp = 0x0000_0000_dead_0000;
            let rax = 0x0123_4567_89ab_cdef;
            let rip = 0xfedc_ba98_7654_3210;
            emu.write_reg(RegisterX86::RAX, rax).unwrap();
            emu.write_reg(RegisterX86::RIP, rip).unwrap();
            emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();

            assert!(dispatch(&mut env, &mut emu, name).is_err());
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), rax);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), rip);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), invalid_rsp);
        }
    }

    #[test]
    fn get_thread_context_zeroes_only_requested_debug_registers() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let context = VIRTUAL_ALLOCATION_ARENA_BASE;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        let mut expected = vec![0xa5; AMD64_CONTEXT_SIZE];
        expected[AMD64_CONTEXT_FLAGS_OFFSET..AMD64_CONTEXT_FLAGS_OFFSET + 4]
            .copy_from_slice(&CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes());
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS {
            expected[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
        }

        emu.map_zeroed_rw(context, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(context, &vec![0xa5; AMD64_CONTEXT_SIZE])
            .unwrap();
        emu.write_mem(
            context + AMD64_CONTEXT_FLAGS_OFFSET as u64,
            &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
        )
        .unwrap();
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, context).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "GetThreadContext").unwrap(),
            ApiOutcome::Handled {
                name: "GetThreadContext".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(emu.read_mem(context, AMD64_CONTEXT_SIZE).unwrap(), expected);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), u64::MAX - 1);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), context);
    }

    #[test]
    fn get_thread_context_rejects_unobserved_inputs_before_mutation() {
        let mut bad_handle_emu = Emu::new().unwrap();
        let mut bad_handle_env = Win64Env::new(IMAGE_BASE);
        bad_handle_emu.write_reg(RegisterX86::RCX, 7).unwrap();
        bad_handle_emu
            .write_reg(RegisterX86::RDX, 0x0000_0000_dead_1000)
            .unwrap();
        bad_handle_emu
            .write_reg(RegisterX86::RSP, 0x0000_0000_dead_2000)
            .unwrap();
        assert_eq!(
            dispatch(&mut bad_handle_env, &mut bad_handle_emu, "GetThreadContext").unwrap(),
            ApiOutcome::Unhandled {
                name: "GetThreadContext".to_owned(),
            }
        );

        let mut bad_flags_emu = Emu::new().unwrap();
        let mut bad_flags_env = Win64Env::new(IMAGE_BASE);
        let context = VIRTUAL_ALLOCATION_ARENA_BASE;
        let before = vec![0xa5; AMD64_CONTEXT_SIZE];
        bad_flags_emu
            .map_zeroed_rw(context, u64::from(PAGE_SIZE))
            .unwrap();
        bad_flags_emu.write_mem(context, &before).unwrap();
        bad_flags_emu
            .write_mem(
                context + AMD64_CONTEXT_FLAGS_OFFSET as u64,
                &CONTEXT_AMD64_CONTROL_INTEGER.to_le_bytes(),
            )
            .unwrap();
        bad_flags_emu
            .write_reg(RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd)
            .unwrap();
        bad_flags_emu
            .write_reg(RegisterX86::RIP, 0x1111_2222_3333_4444)
            .unwrap();
        bad_flags_emu
            .write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        bad_flags_emu.write_reg(RegisterX86::RDX, context).unwrap();
        bad_flags_emu
            .write_reg(RegisterX86::RSP, 0x0000_0000_dead_2000)
            .unwrap();
        assert_eq!(
            dispatch(&mut bad_flags_env, &mut bad_flags_emu, "GetThreadContext").unwrap(),
            ApiOutcome::Unhandled {
                name: "GetThreadContext".to_owned(),
            }
        );
        let mut expected = before;
        expected[AMD64_CONTEXT_FLAGS_OFFSET..AMD64_CONTEXT_FLAGS_OFFSET + 4]
            .copy_from_slice(&CONTEXT_AMD64_CONTROL_INTEGER.to_le_bytes());
        assert_eq!(
            bad_flags_emu.read_mem(context, AMD64_CONTEXT_SIZE).unwrap(),
            expected
        );
        assert_eq!(
            bad_flags_emu.read_reg(RegisterX86::RAX).unwrap(),
            0xaaaa_bbbb_cccc_dddd
        );
        assert_eq!(
            bad_flags_emu.read_reg(RegisterX86::RIP).unwrap(),
            0x1111_2222_3333_4444
        );
        assert_eq!(
            bad_flags_emu.read_reg(RegisterX86::RSP).unwrap(),
            0x0000_0000_dead_2000
        );
    }

    #[test]
    fn get_thread_context_preflights_all_outputs_and_return() {
        let context_page = VIRTUAL_ALLOCATION_ARENA_BASE;
        let context = context_page + u64::from(PAGE_SIZE) - 0x70;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        let debug_sentinel = 0xfeed_face_cafe_beef_u64;

        let mut protected_emu = Emu::new().unwrap();
        let mut protected_env = Win64Env::new(IMAGE_BASE);
        protected_emu
            .map_zeroed_rw(context_page, u64::from(PAGE_SIZE))
            .unwrap();
        protected_emu
            .map_code(
                context_page + u64::from(PAGE_SIZE),
                &debug_sentinel.to_le_bytes(),
            )
            .unwrap();
        protected_emu
            .write_mem(
                context + AMD64_CONTEXT_FLAGS_OFFSET as u64,
                &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
            )
            .unwrap();
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS[..5] {
            protected_emu
                .write_mem(context + offset as u64, &debug_sentinel.to_le_bytes())
                .unwrap();
        }
        protected_emu
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        protected_emu
            .write_reg(RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd)
            .unwrap();
        protected_emu
            .write_reg(RegisterX86::RIP, 0x1111_2222_3333_4444)
            .unwrap();
        protected_emu
            .write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        protected_emu.write_reg(RegisterX86::RDX, context).unwrap();
        protected_emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert!(dispatch(&mut protected_env, &mut protected_emu, "GetThreadContext").is_err());
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS {
            assert_eq!(
                read_u64_at(&protected_emu, context + offset as u64).unwrap(),
                debug_sentinel
            );
        }
        assert_eq!(
            protected_emu.read_reg(RegisterX86::RAX).unwrap(),
            0xaaaa_bbbb_cccc_dddd
        );
        assert_eq!(
            protected_emu.read_reg(RegisterX86::RIP).unwrap(),
            0x1111_2222_3333_4444
        );
        assert_eq!(protected_emu.read_reg(RegisterX86::RSP).unwrap(), rsp);

        let mut bad_return_emu = Emu::new().unwrap();
        let mut bad_return_env = Win64Env::new(IMAGE_BASE);
        bad_return_emu
            .map_zeroed_rw(context_page, u64::from(PAGE_SIZE))
            .unwrap();
        bad_return_emu
            .write_mem(
                context_page + AMD64_CONTEXT_FLAGS_OFFSET as u64,
                &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
            )
            .unwrap();
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS {
            bad_return_emu
                .write_mem(context_page + offset as u64, &debug_sentinel.to_le_bytes())
                .unwrap();
        }
        bad_return_emu
            .write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        bad_return_emu
            .write_reg(RegisterX86::RDX, context_page)
            .unwrap();
        bad_return_emu
            .write_reg(RegisterX86::RSP, 0x0000_0000_dead_2000)
            .unwrap();
        assert!(dispatch(&mut bad_return_env, &mut bad_return_emu, "GetThreadContext").is_err());
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS {
            assert_eq!(
                read_u64_at(&bad_return_emu, context_page + offset as u64).unwrap(),
                debug_sentinel
            );
        }
    }

    #[test]
    fn check_remote_debugger_present_reports_false_for_current_process() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x500;
        let output = crate::emu::STACK_BASE + 0x700;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(output, &[0xaa; 8]).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, output).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "CheckRemoteDebuggerPresent").unwrap(),
            ApiOutcome::Handled {
                name: "CheckRemoteDebuggerPresent".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(
            emu.read_mem(output, 8).unwrap(),
            vec![0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa]
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn check_remote_debugger_present_validates_inputs_before_mutation() {
        let output = crate::emu::STACK_BASE + 0x700;
        let rsp = crate::emu::STACK_BASE + 0x500;

        let mut unsupported = Emu::new().unwrap();
        let mut unsupported_env = Win64Env::new(IMAGE_BASE);
        unsupported.write_mem(output, &[0xaa; 8]).unwrap();
        unsupported.write_reg(RegisterX86::RCX, 7).unwrap();
        unsupported
            .write_reg(RegisterX86::RDX, 0x0000_0000_dead_1000)
            .unwrap();
        unsupported
            .write_reg(RegisterX86::RSP, 0x0000_0000_dead_0000)
            .unwrap();
        assert_eq!(
            dispatch(
                &mut unsupported_env,
                &mut unsupported,
                "CheckRemoteDebuggerPresent"
            )
            .unwrap(),
            ApiOutcome::Unhandled {
                name: "CheckRemoteDebuggerPresent".to_owned(),
            }
        );

        let mut invalid_return = Emu::new().unwrap();
        let mut invalid_return_env = Win64Env::new(IMAGE_BASE);
        invalid_return.write_mem(output, &[0xaa; 8]).unwrap();
        invalid_return
            .write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        invalid_return.write_reg(RegisterX86::RDX, output).unwrap();
        invalid_return
            .write_reg(RegisterX86::RSP, 0x0000_0000_dead_0000)
            .unwrap();
        assert!(dispatch(
            &mut invalid_return_env,
            &mut invalid_return,
            "CheckRemoteDebuggerPresent"
        )
        .is_err());
        assert_eq!(invalid_return.read_mem(output, 8).unwrap(), vec![0xaa; 8]);

        let mut invalid_output = Emu::new().unwrap();
        let mut invalid_output_env = Win64Env::new(IMAGE_BASE);
        let return_address = 0x1234_5678_9abc_def0_u64;
        let rax = 0xaaaa_bbbb_cccc_dddd;
        invalid_output
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        invalid_output.write_reg(RegisterX86::RAX, rax).unwrap();
        invalid_output
            .write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        invalid_output
            .write_reg(RegisterX86::RDX, 0x0000_0000_dead_1000)
            .unwrap();
        invalid_output.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert!(dispatch(
            &mut invalid_output_env,
            &mut invalid_output,
            "CheckRemoteDebuggerPresent"
        )
        .is_err());
        assert_eq!(invalid_output.read_reg(RegisterX86::RAX).unwrap(), rax);
        assert_eq!(invalid_output.read_reg(RegisterX86::RSP).unwrap(), rsp);
    }

    #[test]
    fn is_bad_read_ptr_reports_false_for_exact_readable_dword() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let page = VIRTUAL_ALLOCATION_ARENA_BASE;
        let pointer = page + u64::from(PAGE_SIZE) - 4;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.map_zeroed_rw(page, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(pointer, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        seed_sleep_machine_state(&mut emu, pointer, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, 4).unwrap();
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        assert_eq!(
            dispatch(&mut env, &mut emu, "IsBadReadPtr").unwrap(),
            ApiOutcome::Handled {
                name: "IsBadReadPtr".to_owned(),
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
        assert_eq!(
            emu.read_mem(pointer, 4).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(sleep_environment_state(&env), environment_before);
    }

    #[test]
    fn is_bad_read_ptr_reports_true_for_bounded_unreadable_dword() {
        for pointer in [0x0000_0001_dead_1000, u64::MAX - 2] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let rsp = STACK_BASE + 0x500;
            let return_address = 0x1234_5678_9abc_def0_u64;
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(&mut emu, pointer, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, 4).unwrap();

            assert_eq!(
                dispatch(&mut env, &mut emu, "IsBadReadPtr").unwrap(),
                ApiOutcome::Handled {
                    name: "IsBadReadPtr".to_owned(),
                    ret: 1,
                }
            );
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
            assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), pointer);
            assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), 4);
        }

        let mut crossing_emu = Emu::new().unwrap();
        let mut crossing_env = Win64Env::new(IMAGE_BASE);
        let page = VIRTUAL_ALLOCATION_ARENA_BASE;
        let pointer = page + u64::from(PAGE_SIZE) - 2;
        let rsp = STACK_BASE + 0x500;
        crossing_emu
            .map_zeroed_rw(page, u64::from(PAGE_SIZE))
            .unwrap();
        crossing_emu.write_mem(pointer, &[0xa5; 2]).unwrap();
        crossing_emu
            .write_mem(rsp, &0x1234_5678_9abc_def0_u64.to_le_bytes())
            .unwrap();
        seed_sleep_machine_state(&mut crossing_emu, pointer, rsp, 0x1111_2222_3333_4444);
        crossing_emu.write_reg(RegisterX86::RDX, 4).unwrap();
        assert_eq!(
            dispatch(&mut crossing_env, &mut crossing_emu, "IsBadReadPtr").unwrap(),
            ApiOutcome::Handled {
                name: "IsBadReadPtr".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(crossing_emu.read_mem(pointer, 2).unwrap(), vec![0xa5; 2]);
    }

    #[test]
    fn is_bad_read_ptr_rejects_other_full_width_lengths_before_access() {
        for size in [0, 3, 5, 0xaaaa_bbbb_0000_0004] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            seed_sleep_machine_state(
                &mut emu,
                0x0000_0001_dead_1000,
                0x0000_0002_dead_2000,
                0x1111_2222_3333_4444,
            );
            emu.write_reg(RegisterX86::RDX, size).unwrap();
            let machine_before = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "IsBadReadPtr").unwrap(),
                ApiOutcome::Unhandled {
                    name: "IsBadReadPtr".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
        }
    }

    #[test]
    fn is_bad_read_ptr_invalid_return_frame_is_failure_atomic() {
        for readable in [false, true] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let pointer = if readable {
                STACK_BASE + 0x900
            } else {
                0x0000_0001_dead_1000
            };
            if readable {
                emu.write_mem(pointer, &[0xa5; 4]).unwrap();
            }
            seed_sleep_machine_state(
                &mut emu,
                pointer,
                0x0000_0002_dead_2000,
                0x1111_2222_3333_4444,
            );
            emu.write_reg(RegisterX86::RDX, 4).unwrap();
            let machine_before = sleep_machine_state(&emu);

            assert!(dispatch(&mut env, &mut emu, "IsBadReadPtr").is_err());
            assert_eq!(sleep_machine_state(&emu), machine_before);
            if readable {
                assert_eq!(emu.read_mem(pointer, 4).unwrap(), vec![0xa5; 4]);
            }
        }
    }

    #[test]
    fn nt_query_system_information_reports_empty_modules_with_abi_widths() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x500;
        let information = VIRTUAL_ALLOCATION_ARENA_BASE;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.map_zeroed_rw(information, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_mem(information, &[0xa5; 16]).unwrap();
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        seed_sleep_machine_state(&mut emu, 0xaaaa_bbbb_0000_000b, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, information).unwrap();
        emu.write_reg(RegisterX86::R8, 0xcccc_dddd_0001_0000)
            .unwrap();
        emu.write_reg(RegisterX86::R9, 0).unwrap();
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        assert_eq!(
            dispatch(&mut env, &mut emu, "NtQuerySystemInformation").unwrap(),
            ApiOutcome::Handled {
                name: "NtQuerySystemInformation".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(
            emu.read_mem(information, 16).unwrap(),
            vec![
                0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5
            ]
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

    #[test]
    fn nt_query_system_information_short_buffer_preserves_output() {
        for (information_length, information) in [
            (0u64, 0x0000_0001_dead_1000),
            (0xaaaa_bbbb_0000_0001, STACK_BASE + 0x900),
            (0xcccc_dddd_0000_0003, STACK_BASE + 0x900),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let rsp = STACK_BASE + 0x500;
            let return_address = 0x1234_5678_9abc_def0_u64;
            if information == STACK_BASE + 0x900 {
                emu.write_mem(information, &[0xa5; 8]).unwrap();
            }
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(&mut emu, 0xaaaa_bbbb_0000_000b, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, information).unwrap();
            emu.write_reg(RegisterX86::R8, information_length).unwrap();
            emu.write_reg(RegisterX86::R9, 0).unwrap();

            assert_eq!(
                dispatch(&mut env, &mut emu, "NtQuerySystemInformation").unwrap(),
                ApiOutcome::Handled {
                    name: "NtQuerySystemInformation".to_owned(),
                    ret: u64::from(STATUS_INFO_LENGTH_MISMATCH),
                }
            );
            assert_eq!(
                emu.read_reg(RegisterX86::RAX).unwrap(),
                u64::from(STATUS_INFO_LENGTH_MISMATCH)
            );
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
            assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), information);
            assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), information_length);
            if information == STACK_BASE + 0x900 {
                assert_eq!(emu.read_mem(information, 8).unwrap(), vec![0xa5; 8]);
            }
        }
    }

    #[test]
    fn nt_query_system_information_rejects_unobserved_shapes_before_access() {
        for (information_class, return_length) in [
            (0u64, 0),
            (u64::from(SYSTEM_INFORMATION_CLASS_MODULE_INFORMATION), 1),
            (0xaaaa_bbbb_0000_000b, 0x0000_0001_dead_2000),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            seed_sleep_machine_state(
                &mut emu,
                information_class,
                0x0000_0002_dead_3000,
                0x1111_2222_3333_4444,
            );
            emu.write_reg(RegisterX86::RDX, 0x0000_0003_dead_4000)
                .unwrap();
            emu.write_reg(RegisterX86::R8, 0x1_0000).unwrap();
            emu.write_reg(RegisterX86::R9, return_length).unwrap();
            let machine_before = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "NtQuerySystemInformation").unwrap(),
                ApiOutcome::Unhandled {
                    name: "NtQuerySystemInformation".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
        }
    }

    #[test]
    fn nt_query_system_information_pointer_failures_are_atomic() {
        let information_page = VIRTUAL_ALLOCATION_ARENA_BASE;
        let crossing_information = information_page + u64::from(PAGE_SIZE) - 2;
        let rsp = STACK_BASE + 0x500;
        let mut crossing_emu = Emu::new().unwrap();
        let mut crossing_env = Win64Env::new(IMAGE_BASE);
        crossing_emu
            .map_zeroed_rw(information_page, u64::from(PAGE_SIZE))
            .unwrap();
        crossing_emu
            .write_mem(crossing_information, &[0xa5; 2])
            .unwrap();
        crossing_emu
            .write_mem(rsp, &0x1234_5678_9abc_def0_u64.to_le_bytes())
            .unwrap();
        seed_sleep_machine_state(
            &mut crossing_emu,
            u64::from(SYSTEM_INFORMATION_CLASS_MODULE_INFORMATION),
            rsp,
            0x1111_2222_3333_4444,
        );
        crossing_emu
            .write_reg(RegisterX86::RDX, crossing_information)
            .unwrap();
        crossing_emu.write_reg(RegisterX86::R8, 4).unwrap();
        crossing_emu.write_reg(RegisterX86::R9, 0).unwrap();
        let crossing_cpu = sleep_machine_state(&crossing_emu);
        assert!(dispatch(
            &mut crossing_env,
            &mut crossing_emu,
            "NtQuerySystemInformation"
        )
        .is_err());
        assert_eq!(sleep_machine_state(&crossing_emu), crossing_cpu);
        assert_eq!(
            crossing_emu.read_mem(crossing_information, 2).unwrap(),
            vec![0xa5; 2]
        );

        let mut return_emu = Emu::new().unwrap();
        let mut return_env = Win64Env::new(IMAGE_BASE);
        let information = STACK_BASE + 0x900;
        let invalid_rsp = 0x0000_0002_dead_3000;
        return_emu.write_mem(information, &[0xa5; 8]).unwrap();
        seed_sleep_machine_state(
            &mut return_emu,
            u64::from(SYSTEM_INFORMATION_CLASS_MODULE_INFORMATION),
            invalid_rsp,
            0x1111_2222_3333_4444,
        );
        return_emu.write_reg(RegisterX86::RDX, information).unwrap();
        return_emu.write_reg(RegisterX86::R8, 4).unwrap();
        return_emu.write_reg(RegisterX86::R9, 0).unwrap();
        let return_cpu = sleep_machine_state(&return_emu);
        assert!(dispatch(&mut return_env, &mut return_emu, "NtQuerySystemInformation").is_err());
        assert_eq!(sleep_machine_state(&return_emu), return_cpu);
        assert_eq!(return_emu.read_mem(information, 8).unwrap(), vec![0xa5; 8]);
    }

    #[test]
    fn zw_query_information_process_reports_zero_debug_port_with_abi_widths() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x500;
        let output = STACK_BASE + 0x900;
        let return_address = 0x1234_5678_9abc_def0_u64;
        assert_ne!(output >> 32, 0);
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(rsp + 0x28, &0u64.to_le_bytes()).unwrap();
        emu.write_mem(output, &[0xaa; 16]).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_bbbb_0000_0007)
            .unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        emu.write_reg(RegisterX86::R9, 0xcccc_dddd_0000_0008)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "ZwQueryInformationProcess").unwrap(),
            ApiOutcome::Handled {
                name: "ZwQueryInformationProcess".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(
            emu.read_mem(output, 16).unwrap(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn zw_query_information_process_reports_absent_debug_object_handle() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x500;
        let output = STACK_BASE + 0x900;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(rsp + 0x28, &0u64.to_le_bytes()).unwrap();
        emu.write_mem(output, &[0xaa; 16]).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_bbbb_0000_001e)
            .unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        emu.write_reg(RegisterX86::R9, 0xcccc_dddd_0000_0008)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "ZwQueryInformationProcess").unwrap(),
            ApiOutcome::Handled {
                name: "ZwQueryInformationProcess".to_owned(),
                ret: u64::from(STATUS_PORT_NOT_SET),
            }
        );
        assert_eq!(
            emu.read_mem(output, 16).unwrap(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            u64::from(STATUS_PORT_NOT_SET)
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn zw_query_information_process_rejects_unmodeled_shapes_before_output_access() {
        for (process, class, length) in [
            (0, PROCESS_INFORMATION_CLASS_DEBUG_PORT, 8u32),
            (CURRENT_PROCESS_PSEUDO_HANDLE, 0, 8u32),
            (
                CURRENT_PROCESS_PSEUDO_HANDLE,
                PROCESS_INFORMATION_CLASS_DEBUG_PORT,
                4u32,
            ),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.write_reg(RegisterX86::RCX, process).unwrap();
            emu.write_reg(RegisterX86::RDX, u64::from(class)).unwrap();
            emu.write_reg(RegisterX86::R8, 0x0000_0000_dead_1000)
                .unwrap();
            emu.write_reg(RegisterX86::R9, u64::from(length)).unwrap();
            emu.write_reg(RegisterX86::RSP, 0x0000_0000_dead_0000)
                .unwrap();
            let initial_cpu = sleep_machine_state(&emu);
            assert_eq!(
                dispatch(&mut env, &mut emu, "ZwQueryInformationProcess").unwrap(),
                ApiOutcome::Unhandled {
                    name: "ZwQueryInformationProcess".to_owned()
                }
            );
            assert_eq!(sleep_machine_state(&emu), initial_cpu);
        }

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x500;
        let output = STACK_BASE + 0x900;
        emu.write_mem(rsp + 0x28, &output.to_le_bytes()).unwrap();
        emu.write_mem(output, &[0xaa; 8]).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(
            RegisterX86::RDX,
            PROCESS_INFORMATION_CLASS_DEBUG_OBJECT_HANDLE.into(),
        )
        .unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        emu.write_reg(RegisterX86::R9, 8).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let initial_cpu = sleep_machine_state(&emu);
        assert!(matches!(
            dispatch(&mut env, &mut emu, "ZwQueryInformationProcess").unwrap(),
            ApiOutcome::Unhandled { .. }
        ));
        assert_eq!(sleep_machine_state(&emu), initial_cpu);
        assert_eq!(emu.read_mem(output, 8).unwrap(), vec![0xaa; 8]);
    }

    #[test]
    fn zw_query_information_process_pointer_failures_are_atomic() {
        let rsp = STACK_BASE + 0x500;
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.write_mem(rsp, &0x1234_5678_9abc_def0u64.to_le_bytes())
            .unwrap();
        emu.write_mem(rsp + 0x28, &0u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(
            RegisterX86::RDX,
            PROCESS_INFORMATION_CLASS_DEBUG_OBJECT_HANDLE.into(),
        )
        .unwrap();
        emu.write_reg(RegisterX86::R8, 0x0000_0000_dead_1000)
            .unwrap();
        emu.write_reg(RegisterX86::R9, 8).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let initial_cpu = sleep_machine_state(&emu);
        assert!(dispatch(&mut env, &mut emu, "ZwQueryInformationProcess").is_err());
        assert_eq!(sleep_machine_state(&emu), initial_cpu);

        let mut return_emu = Emu::new().unwrap();
        let mut return_env = Win64Env::new(IMAGE_BASE);
        let argument_page = 0x0000_0000_0700_0000;
        let invalid_return_rsp = argument_page - 0x28;
        let output = STACK_BASE + 0x900;
        return_emu
            .map_zeroed_rw(argument_page, u64::from(PAGE_SIZE))
            .unwrap();
        return_emu
            .write_mem(argument_page, &0u64.to_le_bytes())
            .unwrap();
        return_emu.write_mem(output, &[0xaa; 8]).unwrap();
        return_emu
            .write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        return_emu
            .write_reg(
                RegisterX86::RDX,
                PROCESS_INFORMATION_CLASS_DEBUG_PORT.into(),
            )
            .unwrap();
        return_emu.write_reg(RegisterX86::R8, output).unwrap();
        return_emu.write_reg(RegisterX86::R9, 8).unwrap();
        return_emu
            .write_reg(RegisterX86::RSP, invalid_return_rsp)
            .unwrap();
        let return_cpu = sleep_machine_state(&return_emu);
        assert!(dispatch(
            &mut return_env,
            &mut return_emu,
            "ZwQueryInformationProcess"
        )
        .is_err());
        assert_eq!(sleep_machine_state(&return_emu), return_cpu);
        assert_eq!(return_emu.read_mem(output, 8).unwrap(), vec![0xaa; 8]);
    }

    #[test]
    fn open_thread_token_reports_no_impersonation_token_without_output_access() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_bbbb_0000_0008)
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0xcccc_dddd_0000_0001)
            .unwrap();
        emu.write_reg(RegisterX86::R9, 0x0000_0000_dead_1000)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "OpenThreadToken").unwrap(),
            ApiOutcome::Handled {
                name: "OpenThreadToken".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn open_thread_token_rejects_unobserved_shapes_before_guest_access() {
        for (thread, access, open_as_self) in [
            (7, TOKEN_QUERY, 1),
            (CURRENT_THREAD_PSEUDO_HANDLE, TOKEN_QUERY | 1, 1),
            (CURRENT_THREAD_PSEUDO_HANDLE, TOKEN_QUERY, 0),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.write_reg(RegisterX86::RCX, thread).unwrap();
            emu.write_reg(RegisterX86::RDX, u64::from(access)).unwrap();
            emu.write_reg(RegisterX86::R8, open_as_self).unwrap();
            emu.write_reg(RegisterX86::R9, 0x0000_0000_dead_1000)
                .unwrap();
            emu.write_reg(RegisterX86::RSP, 0x0000_0000_dead_0000)
                .unwrap();

            assert_eq!(
                dispatch(&mut env, &mut emu, "OpenThreadToken").unwrap(),
                ApiOutcome::Unhandled {
                    name: "OpenThreadToken".to_owned(),
                }
            );
        }
    }

    #[test]
    fn open_process_token_returns_tracked_query_handle() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x500;
        let output = crate::emu::STACK_BASE + 0x700;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(output, &[0xaa; 16]).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_bbbb_0000_0008)
            .unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "OpenProcessToken").unwrap(),
            ApiOutcome::Handled {
                name: "OpenProcessToken".to_owned(),
                ret: 1,
            }
        );
        let handle = read_u64_le(&emu.read_mem(output, 8).unwrap());
        assert_eq!(handle, KERNEL_HANDLE_BASE);
        assert_eq!(&emu.read_mem(output, 16).unwrap()[8..], &[0xaa; 8]);
        assert_eq!(
            env.kernel_handles.get(&handle),
            Some(&KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            })
        );
        assert_eq!(env.next_kernel_handle, handle + KERNEL_HANDLE_STRIDE);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn open_process_token_invalid_output_preserves_handle_state_and_control() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        let rax = 0xaaaa_bbbb_cccc_dddd;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, rax).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, u64::from(TOKEN_QUERY))
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0x0000_0000_dead_1000)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let handles_before = env.kernel_handles.clone();
        let cursor_before = env.next_kernel_handle;

        assert!(dispatch(&mut env, &mut emu, "OpenProcessToken").is_err());
        assert_eq!(env.kernel_handles, handles_before);
        assert_eq!(env.next_kernel_handle, cursor_before);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), rax);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp);
    }

    #[test]
    fn reg_open_key_a_empty_registry_preserves_full_width_output() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let subkey = VIRTUAL_ALLOCATION_ARENA_BASE;
        let output = STACK_BASE + 0x900;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        let output_before = [0xa5; 16];
        emu.map_zeroed_rw(subkey, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(subkey, b"SOFTWARE\\Midas\0").unwrap();
        emu.write_mem(output, &output_before).unwrap();
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        seed_sleep_machine_state(&mut emu, HKEY_LOCAL_MACHINE, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, subkey).unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        emu.write_reg(RegisterX86::R9, 0xaaaa_bbbb_cccc_dddd)
            .unwrap();
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        assert_eq!(
            dispatch(&mut env, &mut emu, "RegOpenKeyA").unwrap(),
            ApiOutcome::Handled {
                name: "RegOpenKeyA".to_owned(),
                ret: u64::from(ERROR_FILE_NOT_FOUND),
            }
        );
        for (register, value) in machine_before {
            let expected = match register {
                RegisterX86::RAX => u64::from(ERROR_FILE_NOT_FOUND),
                RegisterX86::RIP => return_address,
                RegisterX86::RSP => value + 8,
                _ => value,
            };
            assert_eq!(emu.read_reg(register).unwrap(), expected);
        }
        assert_eq!(emu.read_mem(output, 16).unwrap(), output_before);
        assert_eq!(sleep_environment_state(&env), environment_before);

        let mut unmapped_output_emu = Emu::new().unwrap();
        let mut unmapped_output_env = Win64Env::new(IMAGE_BASE);
        let subkey = STACK_BASE + 0x900;
        let output = 0x0000_0001_dead_1000;
        unmapped_output_emu
            .write_mem(subkey, b"HARDWARE\\Midas\0")
            .unwrap();
        unmapped_output_emu
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        unmapped_output_emu
            .write_reg(RegisterX86::RCX, HKEY_LOCAL_MACHINE)
            .unwrap();
        unmapped_output_emu
            .write_reg(RegisterX86::RDX, subkey)
            .unwrap();
        unmapped_output_emu
            .write_reg(RegisterX86::R8, output)
            .unwrap();
        unmapped_output_emu
            .write_reg(RegisterX86::RSP, rsp)
            .unwrap();
        assert_eq!(
            dispatch(
                &mut unmapped_output_env,
                &mut unmapped_output_emu,
                "RegOpenKeyA"
            )
            .unwrap(),
            ApiOutcome::Handled {
                name: "RegOpenKeyA".to_owned(),
                ret: u64::from(ERROR_FILE_NOT_FOUND),
            }
        );
        assert_eq!(
            unmapped_output_emu.read_reg(RegisterX86::R8).unwrap(),
            output
        );
    }

    #[test]
    fn reg_open_key_a_rejects_unobserved_full_width_shapes_before_access() {
        for (root, subkey, output) in [
            (0xffff_ffff_8000_0002, 0x0000_0001_dead_1000, 1),
            (HKEY_LOCAL_MACHINE + 1, 0x0000_0001_dead_1000, 1),
            (HKEY_LOCAL_MACHINE, 0, 0x0000_0002_dead_2000),
            (HKEY_LOCAL_MACHINE, 0x0000_0001_dead_1000, 0),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            seed_sleep_machine_state(&mut emu, root, 0x0000_0003_dead_3000, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, subkey).unwrap();
            emu.write_reg(RegisterX86::R8, output).unwrap();
            let machine_before = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "RegOpenKeyA").unwrap(),
                ApiOutcome::Unhandled {
                    name: "RegOpenKeyA".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
        }
    }

    #[test]
    fn reg_open_key_a_enforces_printable_nonempty_subkey_cap() {
        let subkey = STACK_BASE + 0x900;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;

        let mut maximum_emu = Emu::new().unwrap();
        let mut maximum_env = Win64Env::new(IMAGE_BASE);
        let mut maximum = vec![b'A'; REGISTRY_SUBKEY_BYTE_CAP - 1];
        maximum.push(0);
        maximum_emu.write_mem(subkey, &maximum).unwrap();
        maximum_emu
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        maximum_emu
            .write_reg(RegisterX86::RCX, HKEY_LOCAL_MACHINE)
            .unwrap();
        maximum_emu.write_reg(RegisterX86::RDX, subkey).unwrap();
        maximum_emu
            .write_reg(RegisterX86::R8, 0x0000_0001_dead_1000)
            .unwrap();
        maximum_emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert!(matches!(
            dispatch(&mut maximum_env, &mut maximum_emu, "RegOpenKeyA").unwrap(),
            ApiOutcome::Handled { ret, .. } if ret == u64::from(ERROR_FILE_NOT_FOUND)
        ));

        for bytes in [
            vec![0],
            vec![b'A', 0x1f, 0],
            vec![b'A'; REGISTRY_SUBKEY_BYTE_CAP],
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.write_mem(subkey, &bytes).unwrap();
            seed_sleep_machine_state(
                &mut emu,
                HKEY_LOCAL_MACHINE,
                0x0000_0003_dead_3000,
                0x1111_2222_3333_4444,
            );
            emu.write_reg(RegisterX86::RDX, subkey).unwrap();
            emu.write_reg(RegisterX86::R8, 0x0000_0002_dead_2000)
                .unwrap();
            let machine_before = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "RegOpenKeyA").unwrap(),
                ApiOutcome::Unhandled {
                    name: "RegOpenKeyA".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(emu.read_mem(subkey, bytes.len()).unwrap(), bytes);
        }

        let mut unmapped_emu = Emu::new().unwrap();
        let mut unmapped_env = Win64Env::new(IMAGE_BASE);
        let unmapped = 0x0000_0001_dead_1000;
        unmapped_emu
            .write_reg(RegisterX86::RCX, HKEY_LOCAL_MACHINE)
            .unwrap();
        unmapped_emu.write_reg(RegisterX86::RDX, unmapped).unwrap();
        unmapped_emu
            .write_reg(RegisterX86::R8, 0x0000_0002_dead_2000)
            .unwrap();
        let machine_before = sleep_machine_state(&unmapped_emu);
        let error = dispatch(&mut unmapped_env, &mut unmapped_emu, "RegOpenKeyA").unwrap_err();
        assert!(
            matches!(error, EmuError::ReadMem { addr, size: 1, .. } if addr == unmapped),
            "unexpected subkey error: {error:?}"
        );
        assert_eq!(sleep_machine_state(&unmapped_emu), machine_before);
    }

    #[test]
    fn reg_open_key_a_invalid_return_frame_preserves_output_and_control() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let subkey = STACK_BASE + 0x900;
        let output = STACK_BASE + 0xa00;
        let output_before = [0xa5; 16];
        emu.write_mem(subkey, b"SOFTWARE\\Midas\0").unwrap();
        emu.write_mem(output, &output_before).unwrap();
        seed_sleep_machine_state(
            &mut emu,
            HKEY_LOCAL_MACHINE,
            0x0000_0003_dead_3000,
            0x1111_2222_3333_4444,
        );
        emu.write_reg(RegisterX86::RDX, subkey).unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        let machine_before = sleep_machine_state(&emu);

        assert!(dispatch(&mut env, &mut emu, "RegOpenKeyA").is_err());
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(emu.read_mem(output, 16).unwrap(), output_before);
    }

    #[test]
    fn close_handle_removes_tracked_token_and_thread_handles() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let token = KERNEL_HANDLE_BASE;
        let thread = token + KERNEL_HANDLE_STRIDE;
        let next_handle = thread + KERNEL_HANDLE_STRIDE;
        env.insert_kernel_handle(
            token,
            thread,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        env.insert_kernel_handle(
            thread,
            next_handle,
            KernelHandle {
                object: KernelObject::Thread { thread_id: 1 },
                desired_access: LEGACY_THREAD_ALL_ACCESS,
                inheritable: false,
            },
        );

        assert_eq!(call_close_handle(&mut env, &mut emu, token), 1);
        assert!(!env.kernel_handles.contains_key(&token));
        assert!(env.kernel_handles.contains_key(&thread));
        assert_eq!(env.next_kernel_handle, next_handle);

        assert_eq!(call_close_handle(&mut env, &mut emu, thread), 1);
        assert!(env.kernel_handles.is_empty());
        assert_eq!(env.next_kernel_handle, next_handle);
    }

    #[test]
    fn close_handle_rejects_repeated_unknown_and_pseudo_handles_without_registry_change() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let handle = KERNEL_HANDLE_BASE;
        env.insert_kernel_handle(
            handle,
            handle + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        assert_eq!(call_close_handle(&mut env, &mut emu, handle), 1);
        let cursor_after_close = env.next_kernel_handle;

        for invalid in [
            handle,
            0,
            handle + 7,
            CURRENT_PROCESS_PSEUDO_HANDLE,
            CURRENT_THREAD_PSEUDO_HANDLE,
            EMULATED_PROCESS_HEAP_HANDLE,
        ] {
            let handles_before = env.kernel_handles.clone();
            assert_eq!(call_close_handle(&mut env, &mut emu, invalid), 0);
            assert_eq!(env.kernel_handles, handles_before);
            assert_eq!(env.next_kernel_handle, cursor_after_close);
        }
    }

    #[test]
    fn close_handle_bad_return_frame_preserves_live_handle_and_control() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let handle = KERNEL_HANDLE_BASE;
        env.insert_kernel_handle(
            handle,
            handle + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        let invalid_rsp = 0x0000_0000_dead_0000;
        let initial_rax = 0xaaaa_bbbb_cccc_dddd;
        let initial_rip = 0x1111_2222_3333_4444;
        emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
        emu.write_reg(RegisterX86::RCX, handle).unwrap();
        emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();
        emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();

        assert!(dispatch(&mut env, &mut emu, "CloseHandle").is_err());
        assert!(env.kernel_handles.contains_key(&handle));
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), invalid_rsp);
    }

    #[test]
    fn allocate_and_initialize_sid_encodes_observed_builtin_administrators_sid() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let authority_page = IMAGE_BASE + u64::from(DATA_RVA);
        let authority = authority_page + 0x100;
        let output = STACK_BASE + 0x900;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.map_zeroed_rw(authority_page, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_mem(authority, &[0, 0, 0, 0, 0, 5, 0xaa, 0xaa])
            .unwrap();
        emu.write_mem(output, &[0xcc; 16]).unwrap();
        prepare_allocate_sid_call(
            &mut emu,
            authority,
            0xaaaa_bbbb_cccc_0002,
            [
                0x1111_2222_0000_0020,
                0x3333_4444_0000_0220,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            output,
            rsp,
            Some(return_address),
        );

        assert_eq!(
            dispatch(&mut env, &mut emu, "AllocateAndInitializeSid").unwrap(),
            ApiOutcome::Handled {
                name: "AllocateAndInitializeSid".to_owned(),
                ret: 1,
            }
        );
        let sid = read_u64_le(&emu.read_mem(output, 8).unwrap());
        assert_eq!(sid, SID_ALLOCATION_ARENA_BASE);
        assert_eq!(SID_ALLOCATION_ARENA_BASE, VIRTUAL_ALLOCATION_ARENA_END);
        assert_eq!(
            emu.read_mem(sid, 16).unwrap(),
            vec![1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0]
        );
        assert_eq!(&emu.read_mem(output, 16).unwrap()[8..], &[0xcc; 8]);
        assert_eq!(
            env.sid_allocations.get(&sid),
            Some(&SidAllocation {
                sid_size: 16,
                mapped_size: u64::from(PAGE_SIZE),
                sub_authority_count: 2,
            })
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        let report = emu.run_observed(sid, 1).unwrap();
        assert!(matches!(
            report.stop_reason,
            StopReason::MemoryFault(fault)
                if fault.kind == FaultKind::FetchProt && fault.address == sid
        ));
    }

    #[test]
    fn allocate_and_initialize_sid_supports_count_bounds_and_distinct_deterministic_pages() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let authority_page = IMAGE_BASE + u64::from(DATA_RVA);
        let authority = authority_page + 0x100;
        let rsp = STACK_BASE + 0x500;
        emu.map_zeroed_rw(authority_page, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_mem(authority, &[1, 2, 3, 4, 5, 6]).unwrap();

        let first_output = STACK_BASE + 0x900;
        prepare_allocate_sid_call(
            &mut emu,
            authority,
            1,
            [0xaaaa_bbbb_0000_0011, 0, 0, 0, 0, 0, 0, 0],
            first_output,
            rsp,
            Some(0x1000),
        );
        assert!(matches!(
            dispatch(&mut env, &mut emu, "AllocateAndInitializeSid").unwrap(),
            ApiOutcome::Handled { ret: 1, .. }
        ));
        let first = read_u64_le(&emu.read_mem(first_output, 8).unwrap());
        assert_eq!(first, SID_ALLOCATION_ARENA_BASE);
        assert_eq!(
            emu.read_mem(first, 12).unwrap(),
            vec![1, 1, 1, 2, 3, 4, 5, 6, 0x11, 0, 0, 0]
        );

        let second_output = STACK_BASE + 0xa00;
        let sub_authorities = [
            0xaaaa_0000_0000_0001,
            0xbbbb_0000_0000_0002,
            0xcccc_0000_0000_0003,
            0xdddd_0000_0000_0004,
            0xeeee_0000_0000_0005,
            0xffff_0000_0000_0006,
            0x1111_0000_0000_0007,
            0x2222_0000_0000_0008,
        ];
        prepare_allocate_sid_call(
            &mut emu,
            authority,
            0xffff_ffff_ffff_0008,
            sub_authorities,
            second_output,
            rsp,
            Some(0x2000),
        );
        assert!(matches!(
            dispatch(&mut env, &mut emu, "AllocateAndInitializeSid").unwrap(),
            ApiOutcome::Handled { ret: 1, .. }
        ));
        let second = read_u64_le(&emu.read_mem(second_output, 8).unwrap());
        assert_eq!(second, first + u64::from(PAGE_SIZE));
        let mut expected = vec![1, 8, 1, 2, 3, 4, 5, 6];
        for value in 1u32..=8 {
            expected.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(emu.read_mem(second, expected.len()).unwrap(), expected);

        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        fresh_emu
            .map_zeroed_rw(authority_page, u64::from(PAGE_SIZE))
            .unwrap();
        fresh_emu.write_mem(authority, &[1, 2, 3, 4, 5, 6]).unwrap();
        prepare_allocate_sid_call(
            &mut fresh_emu,
            authority,
            1,
            [0x11, 0, 0, 0, 0, 0, 0, 0],
            first_output,
            rsp,
            Some(0x3000),
        );
        dispatch(&mut fresh_env, &mut fresh_emu, "AllocateAndInitializeSid").unwrap();
        assert_eq!(
            read_u64_le(&fresh_emu.read_mem(first_output, 8).unwrap()),
            first
        );

        for count in [0, 9] {
            let output = STACK_BASE + 0xb00;
            fresh_emu.write_mem(output, &[0xcc; 8]).unwrap();
            let allocations_before = fresh_env.sid_allocations.clone();
            let cursor_before = fresh_env.sid_allocation_cursor;
            prepare_allocate_sid_call(
                &mut fresh_emu,
                0x0000_0000_dead_0000,
                count,
                [0; 8],
                output,
                rsp,
                Some(0x4000 + count),
            );
            assert_eq!(
                dispatch(&mut fresh_env, &mut fresh_emu, "AllocateAndInitializeSid").unwrap(),
                ApiOutcome::Handled {
                    name: "AllocateAndInitializeSid".to_owned(),
                    ret: 0,
                }
            );
            assert_eq!(fresh_emu.read_mem(output, 8).unwrap(), vec![0xcc; 8]);
            assert_eq!(fresh_env.sid_allocations, allocations_before);
            assert_eq!(fresh_env.sid_allocation_cursor, cursor_before);
        }
    }

    #[test]
    fn allocate_and_initialize_sid_pointer_and_exhaustion_failures_are_atomic() {
        let rsp = STACK_BASE + 0x500;
        let output = STACK_BASE + 0x900;

        let mut authority_emu = Emu::new().unwrap();
        let mut authority_env = Win64Env::new(IMAGE_BASE);
        authority_emu.write_mem(output, &[0xcc; 8]).unwrap();
        prepare_allocate_sid_call(
            &mut authority_emu,
            0x0000_0000_dead_0000,
            2,
            [0x20, 0x220, 0, 0, 0, 0, 0, 0],
            output,
            rsp,
            Some(0x1000),
        );
        let authority_cpu = sleep_machine_state(&authority_emu);
        assert!(dispatch(
            &mut authority_env,
            &mut authority_emu,
            "AllocateAndInitializeSid"
        )
        .is_err());
        assert_eq!(sleep_machine_state(&authority_emu), authority_cpu);
        assert_eq!(authority_emu.read_mem(output, 8).unwrap(), vec![0xcc; 8]);
        assert!(authority_env.sid_allocations.is_empty());
        assert_eq!(
            authority_env.sid_allocation_cursor,
            SID_ALLOCATION_ARENA_BASE
        );
        assert!(authority_emu
            .read_mem(SID_ALLOCATION_ARENA_BASE, 1)
            .is_err());

        let mut output_emu = Emu::new().unwrap();
        let mut output_env = Win64Env::new(IMAGE_BASE);
        let authority_page = IMAGE_BASE + u64::from(DATA_RVA);
        let authority = authority_page + 0x100;
        output_emu
            .map_zeroed_rw(authority_page, u64::from(PAGE_SIZE))
            .unwrap();
        output_emu
            .write_mem(authority, &[0, 0, 0, 0, 0, 5])
            .unwrap();
        prepare_allocate_sid_call(
            &mut output_emu,
            authority,
            2,
            [0x20, 0x220, 0, 0, 0, 0, 0, 0],
            0x0000_0000_dead_1000,
            rsp,
            Some(0x2000),
        );
        let output_cpu = sleep_machine_state(&output_emu);
        assert!(dispatch(&mut output_env, &mut output_emu, "AllocateAndInitializeSid").is_err());
        assert_eq!(sleep_machine_state(&output_emu), output_cpu);
        assert!(output_env.sid_allocations.is_empty());
        assert!(output_emu.read_mem(SID_ALLOCATION_ARENA_BASE, 1).is_err());

        output_env.sid_allocation_cursor = SID_ALLOCATION_ARENA_END;
        prepare_allocate_sid_call(
            &mut output_emu,
            0x0000_0000_dead_0000,
            2,
            [0; 8],
            0x0000_0000_dead_1000,
            rsp,
            Some(0x3000),
        );
        assert_eq!(
            dispatch(&mut output_env, &mut output_emu, "AllocateAndInitializeSid").unwrap(),
            ApiOutcome::Handled {
                name: "AllocateAndInitializeSid".to_owned(),
                ret: 0,
            }
        );
        assert!(output_env.sid_allocations.is_empty());
        assert_eq!(output_env.sid_allocation_cursor, SID_ALLOCATION_ARENA_END);
    }

    #[test]
    fn free_sid_logically_frees_exact_live_base_and_rejects_other_values() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let sid = SID_ALLOCATION_ARENA_BASE;
        let next = sid + u64::from(PAGE_SIZE);
        emu.map_zeroed_rw(sid, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(sid, &[0xa5; 16]).unwrap();
        env.commit_sid_allocation(
            sid,
            next,
            SidAllocation {
                sid_size: 16,
                mapped_size: u64::from(PAGE_SIZE),
                sub_authority_count: 2,
            },
        );

        assert_eq!(call_free_sid(&mut env, &mut emu, sid), 0);
        assert!(!env.sid_allocations.contains_key(&sid));
        assert_eq!(env.sid_allocation_cursor, next);
        assert_eq!(emu.read_mem(sid, 16).unwrap(), vec![0xa5; 16]);

        for invalid in [sid, sid + 1, 0, 0x0000_0000_dead_0000] {
            let allocations_before = env.sid_allocations.clone();
            assert_eq!(call_free_sid(&mut env, &mut emu, invalid), invalid);
            assert_eq!(env.sid_allocations, allocations_before);
            assert_eq!(env.sid_allocation_cursor, next);
        }
    }

    #[test]
    fn free_sid_bad_return_frame_preserves_live_allocation_and_control() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let sid = SID_ALLOCATION_ARENA_BASE;
        env.commit_sid_allocation(
            sid,
            sid + u64::from(PAGE_SIZE),
            SidAllocation {
                sid_size: 16,
                mapped_size: u64::from(PAGE_SIZE),
                sub_authority_count: 2,
            },
        );
        let invalid_rsp = 0x0000_0000_dead_0000;
        let initial_rax = 0xaaaa_bbbb_cccc_dddd;
        let initial_rip = 0x1111_2222_3333_4444;
        emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
        emu.write_reg(RegisterX86::RCX, sid).unwrap();
        emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();
        emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();

        assert!(dispatch(&mut env, &mut emu, "FreeSid").is_err());
        assert!(env.sid_allocations.contains_key(&sid));
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), invalid_rsp);
    }

    #[test]
    fn get_token_information_reports_empty_groups_query_size() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let token = KERNEL_HANDLE_BASE;
        env.insert_kernel_handle(
            token,
            token + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        let rsp = crate::emu::STACK_BASE + 0x500;
        let return_length = crate::emu::STACK_BASE + 0x800;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(rsp + 0x28, &return_length.to_le_bytes())
            .unwrap();
        emu.write_mem(return_length, &[0xaa; 8]).unwrap();
        emu.write_reg(RegisterX86::RCX, token).unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_bbbb_0000_0002)
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0).unwrap();
        emu.write_reg(RegisterX86::R9, 0xcccc_dddd_0000_0000)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "GetTokenInformation").unwrap(),
            ApiOutcome::Handled {
                name: "GetTokenInformation".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(
            emu.read_mem(return_length, 8).unwrap(),
            vec![4, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa]
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_token_information_reads_empty_groups_into_full_width_outputs() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let token = KERNEL_HANDLE_BASE;
        env.insert_kernel_handle(
            token,
            token + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        emu.map_zeroed_rw(VIRTUAL_ALLOCATION_ARENA_BASE, u64::from(PAGE_SIZE))
            .unwrap();
        let image_data = IMAGE_BASE + u64::from(DATA_RVA);
        emu.map_zeroed_rw(image_data, u64::from(PAGE_SIZE)).unwrap();

        let rsp = STACK_BASE + 0x500;
        let information = VIRTUAL_ALLOCATION_ARENA_BASE + 0x100;
        let return_length = image_data + 0x200;
        let return_address = 0x1234_5678_9abc_def0_u64;
        assert_ne!(information >> 32, 0);
        assert_ne!(return_length >> 32, 0);
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(rsp + 0x28, &return_length.to_le_bytes())
            .unwrap();
        emu.write_mem(information, &[0xaa; 8]).unwrap();
        emu.write_mem(return_length, &[0xbb; 8]).unwrap();
        emu.write_reg(RegisterX86::RCX, token).unwrap();
        emu.write_reg(RegisterX86::RDX, 0xaaaa_bbbb_0000_0002)
            .unwrap();
        emu.write_reg(RegisterX86::R8, information).unwrap();
        emu.write_reg(RegisterX86::R9, 0xcccc_dddd_0000_0004)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "GetTokenInformation").unwrap(),
            ApiOutcome::Handled {
                name: "GetTokenInformation".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(
            emu.read_mem(information, 8).unwrap(),
            vec![0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa]
        );
        assert_eq!(
            emu.read_mem(return_length, 8).unwrap(),
            vec![4, 0, 0, 0, 0xbb, 0xbb, 0xbb, 0xbb]
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_token_information_rejects_overlapping_outputs_but_accepts_adjacency() {
        let output_page = VIRTUAL_ALLOCATION_ARENA_BASE;
        let information = output_page + 0x100;
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;

        for return_length in [
            information,
            information + 1,
            information + 3,
            information - 1,
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            env.insert_kernel_handle(
                KERNEL_HANDLE_BASE,
                KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
                KernelHandle {
                    object: KernelObject::ProcessToken,
                    desired_access: TOKEN_QUERY,
                    inheritable: false,
                },
            );
            emu.map_zeroed_rw(output_page, u64::from(PAGE_SIZE))
                .unwrap();
            emu.write_mem(information - 1, &[0xaa; 12]).unwrap();
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            emu.write_mem(rsp + 0x28, &return_length.to_le_bytes())
                .unwrap();
            emu.write_reg(RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd)
                .unwrap();
            emu.write_reg(RegisterX86::RIP, 0x1111_2222_3333_4444)
                .unwrap();
            emu.write_reg(RegisterX86::RCX, KERNEL_HANDLE_BASE).unwrap();
            emu.write_reg(RegisterX86::RDX, TOKEN_INFORMATION_CLASS_GROUPS.into())
                .unwrap();
            emu.write_reg(RegisterX86::R8, information).unwrap();
            emu.write_reg(RegisterX86::R9, EMPTY_TOKEN_GROUPS_SIZE.into())
                .unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();
            let initial_cpu = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "GetTokenInformation").unwrap(),
                ApiOutcome::Unhandled {
                    name: "GetTokenInformation".to_owned()
                }
            );
            assert_eq!(sleep_machine_state(&emu), initial_cpu);
            assert_eq!(emu.read_mem(information - 1, 12).unwrap(), vec![0xaa; 12]);
        }

        let mut adjacent_emu = Emu::new().unwrap();
        let mut adjacent_env = Win64Env::new(IMAGE_BASE);
        adjacent_env.insert_kernel_handle(
            KERNEL_HANDLE_BASE,
            KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        adjacent_emu
            .map_zeroed_rw(output_page, u64::from(PAGE_SIZE))
            .unwrap();
        adjacent_emu.write_mem(information, &[0xaa; 8]).unwrap();
        adjacent_emu
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        adjacent_emu
            .write_mem(rsp + 0x28, &(information + 4).to_le_bytes())
            .unwrap();
        adjacent_emu
            .write_reg(RegisterX86::RCX, KERNEL_HANDLE_BASE)
            .unwrap();
        adjacent_emu
            .write_reg(RegisterX86::RDX, TOKEN_INFORMATION_CLASS_GROUPS.into())
            .unwrap();
        adjacent_emu
            .write_reg(RegisterX86::R8, information)
            .unwrap();
        adjacent_emu
            .write_reg(RegisterX86::R9, EMPTY_TOKEN_GROUPS_SIZE.into())
            .unwrap();
        adjacent_emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut adjacent_env, &mut adjacent_emu, "GetTokenInformation").unwrap(),
            ApiOutcome::Handled {
                name: "GetTokenInformation".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(
            adjacent_emu.read_mem(information, 8).unwrap(),
            vec![0, 0, 0, 0, 4, 0, 0, 0]
        );
    }

    #[test]
    fn get_token_information_rejects_unobserved_queries_before_stack_access() {
        let output_page = VIRTUAL_ALLOCATION_ARENA_BASE;
        let output = output_page + 0x100;
        let invalid_rsp = 0x0000_0000_dead_0000;
        let cases = [
            (0x1234, TOKEN_INFORMATION_CLASS_GROUPS, 0, 0),
            (KERNEL_HANDLE_BASE, 1, output, EMPTY_TOKEN_GROUPS_SIZE),
            (
                KERNEL_HANDLE_BASE,
                TOKEN_INFORMATION_CLASS_GROUPS,
                0,
                EMPTY_TOKEN_GROUPS_SIZE,
            ),
            (
                KERNEL_HANDLE_BASE,
                TOKEN_INFORMATION_CLASS_GROUPS,
                output,
                0,
            ),
            (
                KERNEL_HANDLE_BASE,
                TOKEN_INFORMATION_CLASS_GROUPS,
                output,
                EMPTY_TOKEN_GROUPS_SIZE + 1,
            ),
        ];

        for (token, information_class, information, information_length) in cases {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            env.insert_kernel_handle(
                KERNEL_HANDLE_BASE,
                KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
                KernelHandle {
                    object: KernelObject::ProcessToken,
                    desired_access: TOKEN_QUERY,
                    inheritable: false,
                },
            );
            emu.map_zeroed_rw(output_page, u64::from(PAGE_SIZE))
                .unwrap();
            emu.write_mem(output, &[0xaa; 8]).unwrap();
            emu.write_reg(RegisterX86::RCX, token).unwrap();
            emu.write_reg(RegisterX86::RDX, u64::from(information_class))
                .unwrap();
            emu.write_reg(RegisterX86::R8, information).unwrap();
            emu.write_reg(RegisterX86::R9, u64::from(information_length))
                .unwrap();
            emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();
            let initial_cpu = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "GetTokenInformation").unwrap(),
                ApiOutcome::Unhandled {
                    name: "GetTokenInformation".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), initial_cpu);
            assert_eq!(emu.read_mem(output, 8).unwrap(), vec![0xaa; 8]);
        }
    }

    #[test]
    fn get_token_information_preflights_all_outputs_before_writing() {
        let rsp = STACK_BASE + 0x500;
        let information = VIRTUAL_ALLOCATION_ARENA_BASE + 0x100;
        let return_address = 0x1234_5678_9abc_def0_u64;

        let mut late_emu = Emu::new().unwrap();
        let mut late_env = Win64Env::new(IMAGE_BASE);
        late_env.insert_kernel_handle(
            KERNEL_HANDLE_BASE,
            KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        late_emu
            .map_zeroed_rw(VIRTUAL_ALLOCATION_ARENA_BASE, u64::from(PAGE_SIZE))
            .unwrap();
        late_emu.write_mem(information, &[0xaa; 8]).unwrap();
        late_emu
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        let invalid_return_length: u64 = 0x0000_0000_dead_1000;
        late_emu
            .write_mem(rsp + 0x28, &invalid_return_length.to_le_bytes())
            .unwrap();
        late_emu
            .write_reg(RegisterX86::RCX, KERNEL_HANDLE_BASE)
            .unwrap();
        late_emu
            .write_reg(RegisterX86::RDX, TOKEN_INFORMATION_CLASS_GROUPS.into())
            .unwrap();
        late_emu.write_reg(RegisterX86::R8, information).unwrap();
        late_emu
            .write_reg(RegisterX86::R9, EMPTY_TOKEN_GROUPS_SIZE.into())
            .unwrap();
        late_emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let late_cpu = sleep_machine_state(&late_emu);

        let error = dispatch(&mut late_env, &mut late_emu, "GetTokenInformation").unwrap_err();
        assert!(matches!(
            error,
            EmuError::WriteUnmapped { addr, size: 4 }
                if addr == invalid_return_length
        ));
        assert_eq!(sleep_machine_state(&late_emu), late_cpu);
        assert_eq!(late_emu.read_mem(information, 8).unwrap(), vec![0xaa; 8]);

        let mut early_emu = Emu::new().unwrap();
        let mut early_env = Win64Env::new(IMAGE_BASE);
        early_env.insert_kernel_handle(
            KERNEL_HANDLE_BASE,
            KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        let return_page = IMAGE_BASE + u64::from(DATA_RVA);
        let return_length = return_page + 0x100;
        early_emu
            .map_zeroed_rw(return_page, u64::from(PAGE_SIZE))
            .unwrap();
        early_emu.write_mem(return_length, &[0xbb; 8]).unwrap();
        early_emu
            .write_mem(rsp, &return_address.to_le_bytes())
            .unwrap();
        early_emu
            .write_mem(rsp + 0x28, &return_length.to_le_bytes())
            .unwrap();
        let invalid_information = 0x0000_0000_dead_2000;
        early_emu
            .write_reg(RegisterX86::RCX, KERNEL_HANDLE_BASE)
            .unwrap();
        early_emu
            .write_reg(RegisterX86::RDX, TOKEN_INFORMATION_CLASS_GROUPS.into())
            .unwrap();
        early_emu
            .write_reg(RegisterX86::R8, invalid_information)
            .unwrap();
        early_emu
            .write_reg(RegisterX86::R9, EMPTY_TOKEN_GROUPS_SIZE.into())
            .unwrap();
        early_emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        let early_cpu = sleep_machine_state(&early_emu);

        let error = dispatch(&mut early_env, &mut early_emu, "GetTokenInformation").unwrap_err();
        assert!(matches!(
            error,
            EmuError::WriteUnmapped { addr, size: 4 }
                if addr == invalid_information
        ));
        assert_eq!(sleep_machine_state(&early_emu), early_cpu);
        assert_eq!(early_emu.read_mem(return_length, 8).unwrap(), vec![0xbb; 8]);

        let mut return_emu = Emu::new().unwrap();
        let mut return_env = Win64Env::new(IMAGE_BASE);
        return_env.insert_kernel_handle(
            KERNEL_HANDLE_BASE,
            KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        return_emu
            .map_zeroed_rw(VIRTUAL_ALLOCATION_ARENA_BASE, u64::from(PAGE_SIZE))
            .unwrap();
        return_emu
            .map_zeroed_rw(return_page, u64::from(PAGE_SIZE))
            .unwrap();
        return_emu.write_mem(information, &[0xaa; 8]).unwrap();
        return_emu.write_mem(return_length, &[0xbb; 8]).unwrap();
        let argument_page = 0x0000_0000_0700_0000;
        let invalid_return_rsp = argument_page - 0x28;
        return_emu
            .map_zeroed_rw(argument_page, u64::from(PAGE_SIZE))
            .unwrap();
        return_emu
            .write_mem(argument_page, &return_length.to_le_bytes())
            .unwrap();
        return_emu
            .write_reg(RegisterX86::RCX, KERNEL_HANDLE_BASE)
            .unwrap();
        return_emu
            .write_reg(RegisterX86::RDX, TOKEN_INFORMATION_CLASS_GROUPS.into())
            .unwrap();
        return_emu.write_reg(RegisterX86::R8, information).unwrap();
        return_emu
            .write_reg(RegisterX86::R9, EMPTY_TOKEN_GROUPS_SIZE.into())
            .unwrap();
        return_emu
            .write_reg(RegisterX86::RSP, invalid_return_rsp)
            .unwrap();
        let return_cpu = sleep_machine_state(&return_emu);

        let error = dispatch(&mut return_env, &mut return_emu, "GetTokenInformation").unwrap_err();
        assert!(matches!(
            error,
            EmuError::ReadMem { addr, size: 8, .. }
                if addr == invalid_return_rsp
        ));
        assert_eq!(sleep_machine_state(&return_emu), return_cpu);
        assert_eq!(return_emu.read_mem(information, 8).unwrap(), vec![0xaa; 8]);
        assert_eq!(
            return_emu.read_mem(return_length, 8).unwrap(),
            vec![0xbb; 8]
        );
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
    fn get_system_firmware_table_reports_no_host_firmware_for_observed_query() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x408;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(
            RegisterX86::RCX,
            0xaaaa_bbbb_0000_0000 | u64::from(FIRMWARE_PROVIDER_RSMB),
        )
        .unwrap();
        emu.write_reg(RegisterX86::RDX, 0xcccc_dddd_0000_0000)
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0).unwrap();
        emu.write_reg(RegisterX86::R9, 0xeeee_ffff_0000_0000)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "GetSystemFirmwareTable").unwrap(),
            ApiOutcome::Handled {
                name: "GetSystemFirmwareTable".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn get_system_firmware_table_rejects_other_shapes_before_memory_access() {
        for (provider, table_id, buffer, buffer_size) in [
            (0u32, 0u32, 0u64, 0u32),
            (FIRMWARE_PROVIDER_RSMB, 1u32, 0u64, 0u32),
            (FIRMWARE_PROVIDER_RSMB, 0u32, 0xdead_0000u64, 0u32),
            (FIRMWARE_PROVIDER_RSMB, 0u32, 0u64, 1u32),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let invalid_rsp = 0x0000_0000_dead_1000;
            emu.write_reg(RegisterX86::RCX, u64::from(provider))
                .unwrap();
            emu.write_reg(RegisterX86::RDX, u64::from(table_id))
                .unwrap();
            emu.write_reg(RegisterX86::R8, buffer).unwrap();
            emu.write_reg(RegisterX86::R9, u64::from(buffer_size))
                .unwrap();
            emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();
            let before = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "GetSystemFirmwareTable").unwrap(),
                ApiOutcome::Unhandled {
                    name: "GetSystemFirmwareTable".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), before);
        }
    }

    #[test]
    fn get_command_line_a_returns_stable_readonly_environment_storage() {
        let call = |env: &mut Win64Env, emu: &mut Emu, rsp: u64, return_address: u64| -> u64 {
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(emu, u64::MAX, rsp, 0x1111_2222_3333_4444);
            let outcome = dispatch(env, emu, "GetCommandLineA").unwrap();
            let ApiOutcome::Handled { name, ret } = outcome else {
                panic!("expected GetCommandLineA to be handled");
            };
            assert_eq!(name, "GetCommandLineA");
            assert_eq!(ret, EMULATED_COMMAND_LINE_A_BASE);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), ret);
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
            assert_eq!(
                emu.read_mem(ret, EMULATED_COMMAND_LINE_A.len()).unwrap(),
                EMULATED_COMMAND_LINE_A
            );
            ret
        };

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first = call(
            &mut env,
            &mut emu,
            STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        let second = call(
            &mut env,
            &mut emu,
            STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );
        assert_eq!(first, second);
        assert!(matches!(
            emu.write_mem(first, b"X"),
            Err(EmuError::WriteProt { .. })
        ));

        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        assert_eq!(
            call(
                &mut fresh_env,
                &mut fresh_emu,
                STACK_BASE + 0x600,
                0x1357_2468_ace0_bdf1,
            ),
            first
        );
    }

    #[test]
    fn get_command_line_a_invalid_return_frame_does_not_map_storage() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.write_reg(RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd)
            .unwrap();
        emu.write_reg(RegisterX86::RIP, 0x1111_2222_3333_4444)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, 0x0000_000d_0000_0000)
            .unwrap();

        assert!(dispatch(&mut env, &mut emu, "GetCommandLineA").is_err());
        assert!(!env.command_line_a_mapped);
        assert!(emu.read_mem(EMULATED_COMMAND_LINE_A_BASE, 1).is_err());
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            0xaaaa_bbbb_cccc_dddd
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            0x1111_2222_3333_4444
        );
    }

    #[test]
    fn is_user_an_admin_returns_false_under_empty_groups_policy() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x500;
        let return_address = 0x1234_5678_9abc_def0_u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RAX, u64::MAX).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "IsUserAnAdmin").unwrap(),
            ApiOutcome::Handled {
                name: "IsUserAnAdmin".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
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
    fn wide_char_to_multi_byte_observed_size_query_returns_ascii_bytes_including_nul() {
        let call_and_assert = |env: &mut Win64Env, emu: &mut Emu, rsp: u64, return_address: u64| {
            let wide = "guest.exe\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            emu.write_mem(WIDE_STRING_ADDRESS, &wide).unwrap();
            let args = WideCharToMultiByteArgs::observed(WIDE_STRING_ADDRESS);
            prepare_wide_char_to_multi_byte_call(emu, args, rsp, Some(return_address));
            let machine_before = sleep_machine_state(emu);
            let environment_before = sleep_environment_state(env);
            let stack_before = emu.read_mem(rsp, 0x48).unwrap();
            let wide_before = emu.read_mem(WIDE_STRING_ADDRESS, wide.len()).unwrap();

            let outcome = dispatch(env, emu, "WideCharToMultiByte").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Handled {
                    name: "WideCharToMultiByte".to_owned(),
                    ret: 10,
                }
            );
            for (register, value) in machine_before {
                let expected = match register {
                    RegisterX86::RAX => 10,
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
            assert_eq!(emu.read_mem(rsp, 0x48).unwrap(), stack_before);
            assert_eq!(
                emu.read_mem(WIDE_STRING_ADDRESS, wide.len()).unwrap(),
                wide_before
            );
            assert_eq!(sleep_environment_state(env), environment_before);
        };

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        call_and_assert(
            &mut env,
            &mut emu,
            crate::emu::STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        call_and_assert(
            &mut env,
            &mut emu,
            crate::emu::STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );

        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        call_and_assert(
            &mut fresh_env,
            &mut fresh_emu,
            crate::emu::STACK_BASE + 0x600,
            0x1357_2468_ace0_bdf1,
        );
    }

    #[test]
    fn wide_char_to_multi_byte_observed_conversion_writes_ascii_and_preserves_suffix() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0u64;
        let output = WIDE_STRING_ADDRESS + 0x100;
        let wide = "guest.exe\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        emu.write_mem(WIDE_STRING_ADDRESS, &wide).unwrap();
        emu.write_mem(output, &[0xcc; 12]).unwrap();
        let args = WideCharToMultiByteArgs {
            output,
            output_size_slot: 0xeeee_ffff_0000_000a,
            ..WideCharToMultiByteArgs::observed(WIDE_STRING_ADDRESS)
        };
        prepare_wide_char_to_multi_byte_call(&mut emu, args, rsp, Some(return_address));
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        let outcome = dispatch(&mut env, &mut emu, "WideCharToMultiByte").unwrap();

        assert_eq!(
            outcome,
            ApiOutcome::Handled {
                name: "WideCharToMultiByte".to_owned(),
                ret: 10,
            }
        );
        assert_eq!(emu.read_mem(output, 12).unwrap(), b"guest.exe\0\xcc\xcc");
        for (register, value) in machine_before {
            let expected = match register {
                RegisterX86::RAX => 10,
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
        assert_eq!(sleep_environment_state(&env), environment_before);
    }

    #[test]
    fn wide_char_to_multi_byte_unmodeled_shapes_do_not_read_input_or_return_frame() {
        const ARGUMENT_PAGE: u64 = 0x0000_0000_dead_1000;
        let base = WideCharToMultiByteArgs::observed(0x0000_0000_dead_0000);
        let cases = [
            WideCharToMultiByteArgs {
                code_page: 1,
                ..base
            },
            WideCharToMultiByteArgs { flags: 1, ..base },
            WideCharToMultiByteArgs {
                wide_count: 0,
                ..base
            },
            WideCharToMultiByteArgs { output: 1, ..base },
            WideCharToMultiByteArgs {
                output_size_slot: 1,
                ..base
            },
            WideCharToMultiByteArgs {
                default_character: 1,
                ..base
            },
            WideCharToMultiByteArgs {
                used_default: 1,
                ..base
            },
            WideCharToMultiByteArgs {
                output: base.wide_string,
                output_size_slot: 10,
                ..base
            },
        ];

        for args in cases {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.map_zeroed_rw(ARGUMENT_PAGE, 0x1000).unwrap();
            let rsp = ARGUMENT_PAGE - 0x28;
            prepare_wide_char_to_multi_byte_call(&mut emu, args, rsp, None);
            assert!(emu.read_mem(rsp, 8).is_err());
            assert!(emu.read_mem(args.wide_string, 2).is_err());
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "WideCharToMultiByte").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Unhandled {
                    name: "WideCharToMultiByte".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn wide_char_to_multi_byte_rejects_unmodeled_text_and_output_size_bounds() {
        const ARGUMENT_PAGE: u64 = 0x0000_0000_dead_1000;
        const STRING_PAGE: u64 = 0x0000_0000_beef_0000;
        let inputs = [
            vec![0x00e9, 0],
            vec![u16::from(b'A'); WIDE_CHAR_TO_MULTI_BYTE_UNIT_CAP],
        ];

        for units in inputs {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.map_zeroed_rw(ARGUMENT_PAGE, 0x1000).unwrap();
            emu.map_zeroed_rw(STRING_PAGE, 0x1000).unwrap();
            let bytes = units
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            emu.write_mem(STRING_PAGE, &bytes).unwrap();
            let rsp = ARGUMENT_PAGE - 0x28;
            prepare_wide_char_to_multi_byte_call(
                &mut emu,
                WideCharToMultiByteArgs::observed(STRING_PAGE),
                rsp,
                None,
            );
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let outcome = dispatch(&mut env, &mut emu, "WideCharToMultiByte").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Unhandled {
                    name: "WideCharToMultiByte".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_zeroed_rw(ARGUMENT_PAGE, 0x1000).unwrap();
        emu.map_zeroed_rw(STRING_PAGE, 0x1000).unwrap();
        let wide = "guest.exe\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let output = STRING_PAGE + 0x100;
        emu.write_mem(STRING_PAGE, &wide).unwrap();
        emu.write_mem(output, &[0xcc; 12]).unwrap();
        let rsp = ARGUMENT_PAGE - 0x28;
        prepare_wide_char_to_multi_byte_call(
            &mut emu,
            WideCharToMultiByteArgs {
                output,
                output_size_slot: 11,
                ..WideCharToMultiByteArgs::observed(STRING_PAGE)
            },
            rsp,
            None,
        );
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        let outcome = dispatch(&mut env, &mut emu, "WideCharToMultiByte").unwrap();

        assert_eq!(
            outcome,
            ApiOutcome::Unhandled {
                name: "WideCharToMultiByte".to_owned(),
            }
        );
        assert_eq!(emu.read_mem(output, 12).unwrap(), [0xcc; 12]);
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(sleep_environment_state(&env), environment_before);
    }

    #[test]
    fn wide_char_to_multi_byte_input_and_return_failures_are_atomic() {
        const ARGUMENT_PAGE: u64 = 0x0000_0000_dead_1000;
        const STRING_PAGE: u64 = 0x0000_0000_beef_0000;

        for map_string in [false, true] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.map_zeroed_rw(ARGUMENT_PAGE, 0x1000).unwrap();
            if map_string {
                emu.map_zeroed_rw(STRING_PAGE, 0x1000).unwrap();
                let wide = "guest.exe\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>();
                emu.write_mem(STRING_PAGE, &wide).unwrap();
            }
            let rsp = ARGUMENT_PAGE - 0x28;
            let output = STRING_PAGE + 0x100;
            let args = if map_string {
                emu.write_mem(output, &[0xcc; 12]).unwrap();
                WideCharToMultiByteArgs {
                    output,
                    output_size_slot: 10,
                    ..WideCharToMultiByteArgs::observed(STRING_PAGE)
                }
            } else {
                WideCharToMultiByteArgs::observed(STRING_PAGE)
            };
            prepare_wide_char_to_multi_byte_call(&mut emu, args, rsp, None);
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            let error = dispatch(&mut env, &mut emu, "WideCharToMultiByte").unwrap_err();

            let expected_address = if map_string { rsp } else { STRING_PAGE };
            assert!(
                matches!(error, EmuError::ReadMem { addr, .. } if addr == expected_address),
                "unexpected error: {error:?}"
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
            if map_string {
                assert_eq!(emu.read_mem(output, 12).unwrap(), [0xcc; 12]);
            }
        }

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = crate::emu::STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0;
        let wide = "guest.exe\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        emu.write_mem(WIDE_STRING_ADDRESS, &wide).unwrap();
        let args = WideCharToMultiByteArgs {
            output: 0x0000_0000_dead_0000,
            output_size_slot: 10,
            ..WideCharToMultiByteArgs::observed(WIDE_STRING_ADDRESS)
        };
        prepare_wide_char_to_multi_byte_call(&mut emu, args, rsp, Some(return_address));
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);
        let return_frame_before = emu.read_mem(rsp, 8).unwrap();

        let error = dispatch(&mut env, &mut emu, "WideCharToMultiByte").unwrap_err();

        assert!(
            matches!(error, EmuError::WriteUnmapped { addr, .. } if addr == args.output),
            "unexpected error: {error:?}"
        );
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(sleep_environment_state(&env), environment_before);
        assert_eq!(emu.read_mem(rsp, 8).unwrap(), return_frame_before);
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
    fn find_window_a_accepts_one_printable_selector_and_reports_no_match() {
        let selector = WINDOW_CLASS_NAME_ADDRESS;
        assert!(selector > u64::from(u32::MAX));
        for (class_name, window_name, bytes) in [
            (selector, 0, b"GeneralClass\0".as_slice()),
            (0, selector, b"Arbitrary window title\0".as_slice()),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let rsp = STACK_BASE + 0x400;
            let return_address = 0x1234_5678_9abc_def0_u64;
            emu.write_mem(selector, bytes).unwrap();
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(&mut emu, class_name, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, window_name).unwrap();
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);
            let return_frame_before = emu.read_mem(rsp, 8).unwrap();

            assert_eq!(
                dispatch(&mut env, &mut emu, "FindWindowA").unwrap(),
                ApiOutcome::Handled {
                    name: "FindWindowA".to_owned(),
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
                assert_eq!(
                    emu.read_reg(register).unwrap(),
                    expected,
                    "unexpected {register:?} change"
                );
            }
            assert_eq!(emu.read_mem(selector, bytes.len()).unwrap(), bytes);
            assert_eq!(emu.read_mem(rsp, 8).unwrap(), return_frame_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn find_window_a_rejects_zero_or_ambiguous_selectors_before_access() {
        for (class_name, window_name) in [(0, 0), (0x0000_0001_dead_1000, 0x0000_0002_dead_2000)] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let invalid_rsp = 0x0000_0003_dead_3000;
            seed_sleep_machine_state(&mut emu, class_name, invalid_rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, window_name).unwrap();
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            assert_eq!(
                dispatch(&mut env, &mut emu, "FindWindowA").unwrap(),
                ApiOutcome::Unhandled {
                    name: "FindWindowA".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
        }
    }

    #[test]
    fn find_window_a_fails_closed_on_invalid_selector_text_or_memory() {
        for bytes in [
            vec![0],
            vec![b'A', 0x1f, 0],
            vec![b'A'; WINDOW_CLASS_NAME_BYTE_CAP],
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let invalid_rsp = 0x0000_0003_dead_3000;
            emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, &bytes).unwrap();
            seed_sleep_machine_state(
                &mut emu,
                WINDOW_CLASS_NAME_ADDRESS,
                invalid_rsp,
                0x1111_2222_3333_4444,
            );
            emu.write_reg(RegisterX86::RDX, 0).unwrap();
            let machine_before = sleep_machine_state(&emu);
            let environment_before = sleep_environment_state(&env);

            assert_eq!(
                dispatch(&mut env, &mut emu, "FindWindowA").unwrap(),
                ApiOutcome::Unhandled {
                    name: "FindWindowA".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
            assert_eq!(sleep_environment_state(&env), environment_before);
            assert_eq!(
                emu.read_mem(WINDOW_CLASS_NAME_ADDRESS, bytes.len())
                    .unwrap(),
                bytes
            );
        }

        let mut unmapped_emu = Emu::new().unwrap();
        let mut unmapped_env = Win64Env::new(IMAGE_BASE);
        let unmapped = 0x0000_0001_dead_1000;
        seed_sleep_machine_state(
            &mut unmapped_emu,
            0,
            0x0000_0003_dead_3000,
            0x1111_2222_3333_4444,
        );
        unmapped_emu.write_reg(RegisterX86::RDX, unmapped).unwrap();
        let machine_before = sleep_machine_state(&unmapped_emu);
        let environment_before = sleep_environment_state(&unmapped_env);
        let error = dispatch(&mut unmapped_env, &mut unmapped_emu, "FindWindowA").unwrap_err();
        assert!(
            matches!(error, EmuError::ReadMem { addr, size: 1, .. } if addr == unmapped),
            "unexpected selector error: {error:?}"
        );
        assert_eq!(sleep_machine_state(&unmapped_emu), machine_before);
        assert_eq!(sleep_environment_state(&unmapped_env), environment_before);
    }

    #[test]
    fn find_window_a_invalid_return_frame_is_failure_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let invalid_rsp = 0x0000_0003_dead_3000;
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"GeneralClass\0")
            .unwrap();
        seed_sleep_machine_state(
            &mut emu,
            WINDOW_CLASS_NAME_ADDRESS,
            invalid_rsp,
            0x1111_2222_3333_4444,
        );
        emu.write_reg(RegisterX86::RDX, 0).unwrap();
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        let error = dispatch(&mut env, &mut emu, "FindWindowA").unwrap_err();

        assert!(
            matches!(error, EmuError::ReadMem { addr, size: 8, .. } if addr == invalid_rsp),
            "unexpected return error: {error:?}"
        );
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(sleep_environment_state(&env), environment_before);
        assert_eq!(
            emu.read_mem(WINDOW_CLASS_NAME_ADDRESS, b"GeneralClass\0".len())
                .unwrap(),
            b"GeneralClass\0"
        );
    }

    #[test]
    fn create_window_ex_a_returns_stable_opaque_handle_without_window_state() {
        let call_and_assert = |env: &mut Win64Env, emu: &mut Emu, rsp: u64, return_address: u64| {
            let args = CreateWindowExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS);
            prepare_create_window_ex_a_call(emu, args, rsp, Some(return_address));
            let machine_before = sleep_machine_state(emu);
            let environment_before = sleep_environment_state(env);

            let outcome = dispatch(env, emu, "CreateWindowExA").unwrap();

            assert_eq!(
                outcome,
                ApiOutcome::Handled {
                    name: "CreateWindowExA".to_owned(),
                    ret: EMULATED_WINDOW_HANDLE,
                }
            );
            for (register, value) in machine_before {
                let expected = match register {
                    RegisterX86::RAX => EMULATED_WINDOW_HANDLE,
                    RegisterX86::RIP => return_address,
                    RegisterX86::RSP => value + 8,
                    _ => value,
                };
                assert_eq!(emu.read_reg(register).unwrap(), expected);
            }
            assert_eq!(sleep_environment_state(env), environment_before);
            assert!(emu.read_mem(EMULATED_WINDOW_HANDLE, 1).is_err());
            EMULATED_WINDOW_HANDLE
        };

        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        register_test_window_class(&mut env, &mut emu, STACK_BASE + 0x300);
        let first = call_and_assert(
            &mut env,
            &mut emu,
            STACK_BASE + 0x400,
            0x1234_5678_9abc_def0,
        );
        let second = call_and_assert(
            &mut env,
            &mut emu,
            STACK_BASE + 0x500,
            0x0fed_cba9_8765_4321,
        );
        let mut fresh_emu = Emu::new().unwrap();
        let mut fresh_env = Win64Env::new(IMAGE_BASE);
        register_test_window_class(&mut fresh_env, &mut fresh_emu, STACK_BASE + 0x300);
        let fresh = call_and_assert(
            &mut fresh_env,
            &mut fresh_emu,
            STACK_BASE + 0x600,
            0x1357_2468_ace0_bdf1,
        );
        assert_eq!(first, second);
        assert_eq!(second, fresh);
    }

    #[test]
    fn create_window_ex_a_rejects_unmodeled_or_unregistered_shapes() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"MidasTestClass\0")
            .unwrap();
        let rsp = STACK_BASE + 0x700;
        let return_address = 0x1234_5678_9abc_def0;
        let observed = CreateWindowExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS);

        assert_eq!(
            call_create_window_ex_a(&mut env, &mut emu, observed, rsp, return_address),
            ApiOutcome::Handled {
                name: "CreateWindowExA".to_owned(),
                ret: 0,
            }
        );
        for args in [
            CreateWindowExAArgs {
                window_name: 0x0000_000d_0000_0000,
                ..observed
            },
            CreateWindowExAArgs {
                parent: 1,
                ..observed
            },
            CreateWindowExAArgs {
                menu: 1,
                ..observed
            },
            CreateWindowExAArgs {
                parameter: 1,
                ..observed
            },
            CreateWindowExAArgs {
                width: 0,
                ..observed
            },
            CreateWindowExAArgs {
                height: u64::from(u32::MAX),
                ..observed
            },
            CreateWindowExAArgs {
                class_name: 1,
                ..observed
            },
        ] {
            assert_eq!(
                call_create_window_ex_a(&mut env, &mut emu, args, rsp, return_address),
                ApiOutcome::Unhandled {
                    name: "CreateWindowExA".to_owned(),
                }
            );
        }

        register_test_window_class(&mut env, &mut emu, STACK_BASE + 0x300);
        assert_eq!(
            call_create_window_ex_a(
                &mut env,
                &mut emu,
                CreateWindowExAArgs {
                    instance: IMAGE_BASE + 1,
                    ..observed
                },
                rsp,
                return_address,
            ),
            ApiOutcome::Handled {
                name: "CreateWindowExA".to_owned(),
                ret: 0,
            }
        );
    }

    #[test]
    fn create_window_ex_a_invalid_stack_is_failure_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = 0x0000_000d_0000_0000;
        let args = CreateWindowExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS);
        seed_sleep_machine_state(&mut emu, args.extended_style, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, args.class_name).unwrap();
        emu.write_reg(RegisterX86::R8, args.window_name).unwrap();
        emu.write_reg(RegisterX86::R9, args.style).unwrap();
        let machine_before = sleep_machine_state(&emu);
        let environment_before = sleep_environment_state(&env);

        assert!(dispatch(&mut env, &mut emu, "CreateWindowExA").is_err());
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(sleep_environment_state(&env), environment_before);
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
    fn cooperative_sleep_yield_selects_lowest_id_once_and_preserves_main_state() {
        const SHARED_BASE: u64 = 0x0000_0001_6000_0000;
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        const PARAMETER: u64 = 0x0123_4567_89ab_cdef;
        const SECOND_PARAMETER: u64 = 0xfedc_ba98_7654_3210;
        const MAIN_R15: u64 = 0xa1a2_a3a4_a5a6_a7a8;

        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_zeroed_rw(SHARED_BASE, u64::from(PAGE_SIZE))
            .unwrap();
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env
            .export_stub_by_base(kernel32, "Sleep")
            .expect("Sleep seed");
        let thread_id_stub = env
            .export_stub_by_base(kernel32, "GetCurrentThreadId")
            .expect("GetCurrentThreadId seed");

        let mut child_code = Vec::new();
        child_code.extend_from_slice(&[0x48, 0xbb]); // mov rbx, SHARED_BASE
        child_code.extend_from_slice(&SHARED_BASE.to_le_bytes());
        child_code.extend_from_slice(&[0x48, 0x89, 0x0b]); // mov [rbx], rcx
        child_code.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]); // shadow + alignment
        child_code.extend_from_slice(&[0x48, 0xb8]); // mov rax, GetCurrentThreadId
        child_code.extend_from_slice(&thread_id_stub.to_le_bytes());
        child_code.extend_from_slice(&[0xff, 0xd0]); // call rax
        child_code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
        child_code.extend_from_slice(&[0x48, 0x89, 0x43, 0x08]); // mov [rbx+8], rax
        child_code.extend_from_slice(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0]);
        child_code.extend_from_slice(&[0x48, 0x89, 0x43, 0x10]); // mov [rbx+16], rax
        child_code.extend_from_slice(&[0x48, 0x89, 0xe0]); // mov rax, rsp
        child_code.extend_from_slice(&[0x48, 0x89, 0x43, 0x18]); // mov [rbx+24], rax
        child_code.extend_from_slice(&[0xc6, 0x43, 0x20, 0x01]); // mov byte [rbx+32], 1
        child_code.push(0xc3); // ret
        emu.map_code(CHILD_START, &child_code).unwrap();

        let marker = SHARED_BASE + 32;
        let mut main_code = Vec::new();
        main_code.extend_from_slice(&[0x48, 0xbb]); // mov rbx, marker
        main_code.extend_from_slice(&marker.to_le_bytes());
        main_code.extend_from_slice(&[0x0f, 0xb6, 0x03]); // movzx eax, byte [rbx]
        main_code.push(0xc3); // ret to zero
        emu.map_code(image.entry_point_va(), &main_code).unwrap();

        let handle = env
            .create_thread(&mut emu, 0, 0, CHILD_START, PARAMETER, 0, 0)
            .unwrap();
        assert_ne!(handle, 0);
        let second_handle = env
            .create_thread(&mut emu, 0, 0, CHILD_START, SECOND_PARAMETER, 0, 0)
            .unwrap();
        assert_ne!(second_handle, 0);
        assert_ne!(second_handle, handle);
        let main_rsp = STACK_BASE + 0x20_000;
        let main_stack_window = main_rsp - 0x80;
        let main_stack_pattern = (0..0x200)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
            .collect::<Vec<_>>();
        emu.write_mem(main_stack_window, &main_stack_pattern)
            .unwrap();
        emu.write_mem(main_rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_mem(main_rsp + 8, &0u64.to_le_bytes()).unwrap();
        let main_stack_before = emu.read_mem(main_stack_window, 0x200).unwrap();
        emu.write_reg(RegisterX86::RCX, 1).unwrap();
        emu.write_reg(RegisterX86::RSP, main_rsp).unwrap();
        emu.write_reg(RegisterX86::RIP, sleep_stub).unwrap();
        emu.write_reg(RegisterX86::R15, MAIN_R15).unwrap();

        let result =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        assert_eq!(result.main_instructions_after_first_yield, 3);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected one cooperative yield");
        };
        assert_eq!(yielded.thread_id, 2);
        assert_eq!(yielded.handled, vec!["GetCurrentThreadId".to_owned()]);
        assert_eq!(yielded.stop, CooperativeThreadStop::ReachedReturnGuard);
        assert!(yielded.instructions_executed > 0);
        assert_eq!(yielded.stack_size, STACK_SIZE);
        assert_eq!(yielded.entry_rsp & 0xf, 8);
        assert!((yielded.stack_base..yielded.stack_base + STACK_SIZE).contains(&yielded.entry_rsp));
        assert_eq!(yielded.teb_base, yielded.stack_base + STACK_SIZE);
        assert_eq!(
            read_u64_le(
                &emu.read_mem(yielded.teb_base + TEB_STACKBASE_OFFSET, 8)
                    .unwrap()
            ),
            yielded.stack_base + STACK_SIZE
        );
        assert_eq!(
            read_u64_le(
                &emu.read_mem(yielded.teb_base + TEB_STACKLIMIT_OFFSET, 8)
                    .unwrap()
            ),
            yielded.stack_base
        );
        assert_eq!(
            read_u64_le(&emu.read_mem(yielded.teb_base + TEB_SELF_OFFSET, 8).unwrap()),
            yielded.teb_base
        );
        assert_eq!(
            read_u64_le(&emu.read_mem(yielded.teb_base + TEB_PEB_OFFSET, 8).unwrap()),
            PEB_BASE
        );
        assert_eq!(emu.read_mem(yielded.stack_base, 16).unwrap(), vec![0; 16]);
        assert_eq!(
            read_u64_le(&emu.read_mem(yielded.entry_rsp, 8).unwrap()),
            yielded.teb_base
        );
        assert_eq!(
            read_u64_le(&emu.read_mem(SHARED_BASE, 8).unwrap()),
            PARAMETER
        );
        assert_eq!(read_u64_le(&emu.read_mem(SHARED_BASE + 8, 8).unwrap()), 2);
        assert_eq!(
            read_u64_le(&emu.read_mem(SHARED_BASE + 16, 8).unwrap()),
            yielded.teb_base
        );
        assert_eq!(
            read_u64_le(&emu.read_mem(SHARED_BASE + 24, 8).unwrap()),
            yielded.entry_rsp
        );
        assert_eq!(emu.read_mem(marker, 1).unwrap(), vec![1]);
        assert_eq!(
            emu.read_mem(main_stack_window, main_stack_before.len())
                .unwrap(),
            main_stack_before
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::R15).unwrap(), MAIN_R15);
        assert_eq!(
            emu.read_reg(RegisterX86::GS_BASE).unwrap(),
            crate::emu::TEB_BASE
        );
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
        assert_eq!(
            env.runnable_unscheduled_threads()
                .map(|(thread_id, _)| thread_id)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert!(env.scheduled_thread_ids.contains(&2));
        assert!(!env.scheduled_thread_ids.contains(&3));
        let guard = emu.resume(yielded.teb_base, 1).unwrap();
        assert!(matches!(
            guard.stop_reason,
            StopReason::MemoryFault(crate::emu::MemFault {
                kind: FaultKind::FetchProt,
                address
            }) if address == yielded.teb_base
        ));
    }

    #[test]
    fn cooperative_child_indirect_transfer_observation_stops_outer_runner() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        let image = test_image();
        let target = image.entry_point_va();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();

        let mut child_code = vec![0x48, 0xb8]; // mov rax, target
        child_code.extend_from_slice(&target.to_le_bytes());
        child_code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        emu.map_code(CHILD_START, &child_code).unwrap();
        emu.map_code(target, &[0x90, 0x0f, 0x0b]).unwrap();
        emu.configure_indirect_transfer_watch(
            &[(CHILD_START, CHILD_START + 0x1000)],
            &[(target, target + 0x1000)],
            false,
        )
        .unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();

        let main_rsp = STACK_BASE + 0x20_000;
        emu.write_mem(main_rsp, &target.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, 1).unwrap();
        emu.write_reg(RegisterX86::RSP, main_rsp).unwrap();

        let result =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::IndirectTransferObserved);
        assert_eq!(result.main_instructions_after_first_yield, 0);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected one cooperative yield");
        };
        assert_eq!(
            yielded.stop,
            CooperativeThreadStop::Trap(TrapStop::IndirectTransferObserved)
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), target);
        let observation = emu.indirect_transfer_observation().unwrap();
        assert_eq!(observation.source_rip, CHILD_START + 10);
        assert_eq!(observation.target_rip, target);
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
    }

    #[test]
    fn cooperative_child_changed_exception_continuation_propagates_before_cpu_discard() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        const HANDLER: u64 = IMAGE_BASE + IMAGE_SIZE as u64 + 0x1000;
        const TARGET: u64 = IMAGE_BASE + IMAGE_SIZE as u64 + 0x3000;
        const MAIN_CONTINUATION: u64 = IMAGE_BASE + CODE_RVA as u64;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
        let raise_stub = env.export_stub_by_base(kernel32, "RaiseException").unwrap();

        let mut child_code = vec![0x48, 0x83, 0xec, 0x28]; // shadow + alignment
        child_code.extend_from_slice(&[0x48, 0xb9]); // mov rcx, code
        child_code.extend_from_slice(&0xc000_008e_u64.to_le_bytes());
        child_code.extend_from_slice(&[0x31, 0xd2]); // xor edx,edx
        child_code.extend_from_slice(&[0x45, 0x31, 0xc0]); // xor r8d,r8d
        child_code.extend_from_slice(&[0x45, 0x31, 0xc9]); // xor r9d,r9d
        child_code.extend_from_slice(&[0x48, 0xb8]); // mov rax, RaiseException
        child_code.extend_from_slice(&raise_stub.to_le_bytes());
        child_code.extend_from_slice(&[0xff, 0xd0]); // call rax
        child_code.extend_from_slice(&[0x0f, 0x0b]); // must remain unexecuted
        emu.map_code(CHILD_START, &child_code).unwrap();

        let mut handler_code = vec![0x48, 0x8b, 0x41, 0x08]; // mov rax,[rcx+8]
        handler_code.extend_from_slice(&[0x48, 0xba]); // mov rdx,TARGET
        handler_code.extend_from_slice(&TARGET.to_le_bytes());
        handler_code.extend_from_slice(&[0x48, 0x89, 0x90, 0xf8, 0, 0, 0]); // [rax+f8]=rdx
        handler_code.extend_from_slice(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3]);
        emu.map_code(HANDLER, &handler_code).unwrap();
        emu.map_code(TARGET, &[0xeb, 0xfe]).unwrap();
        emu.map_code(MAIN_CONTINUATION, &[0xc3]).unwrap();
        assert_ne!(env.add_vectored_exception_handler(1, HANDLER), 0);
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();

        let main_rsp = STACK_BASE + 0x20_000;
        emu.write_mem(main_rsp, &MAIN_CONTINUATION.to_le_bytes())
            .unwrap();
        emu.write_mem(main_rsp + 8, &0u64.to_le_bytes()).unwrap();
        seed_sleep_machine_state(&mut emu, 1, main_rsp, sleep_stub);
        let main_before = sleep_machine_state(&emu);

        let result =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::ExceptionContinuationObserved);
        assert_eq!(result.main_instructions_after_first_yield, 0);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected one cooperative yield");
        };
        assert_eq!(yielded.thread_id, 2);
        assert_eq!(
            yielded.stop,
            CooperativeThreadStop::Trap(TrapStop::ExceptionContinuationObserved)
        );
        let observation = env.changed_exception_continuation().unwrap();
        assert_eq!(observation.thread_id, 2);
        assert_eq!(observation.continuing_handler, HANDLER);
        assert_eq!(observation.continuation_rip, TARGET);
        assert_eq!(&observation.target_bytes[..2], &[0xeb, 0xfe]);
        assert!(!env.pending_vectored_exceptions.contains_key(&2));
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
        for (register, initial) in main_before {
            let expected = match register {
                RegisterX86::RIP => MAIN_CONTINUATION,
                RegisterX86::RSP => initial + 8,
                _ => initial,
            };
            assert_eq!(emu.read_reg(register).unwrap(), expected);
        }
    }

    #[test]
    fn observing_scheduler_rearms_refuted_main_transfer_and_reaches_natural_terminal() {
        const SOURCE: u64 = IMAGE_BASE + CODE_RVA as u64;
        const TARGET: u64 = IMAGE_BASE + DATA_RVA as u64;
        const MAIN_R15: u64 = 0x5152_5354_5556_5758;

        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);

        let mut source_code = vec![0x49, 0xbf]; // mov r15, MAIN_R15
        source_code.extend_from_slice(&MAIN_R15.to_le_bytes());
        source_code.extend_from_slice(&[0x48, 0xb8]); // mov rax, TARGET
        source_code.extend_from_slice(&TARGET.to_le_bytes());
        source_code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        emu.map_code(SOURCE, &source_code).unwrap();
        emu.map_code(TARGET, &[0xc3]).unwrap(); // ret through the zero sentinel
        emu.configure_indirect_transfer_watch(
            &[(SOURCE, SOURCE + u64::from(PAGE_SIZE))],
            &[(TARGET, TARGET + u64::from(PAGE_SIZE))],
            false,
        )
        .unwrap();

        let rsp = STACK_BASE + 0x20_000;
        emu.write_mem(rsp, &0u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let mut callbacks = Vec::new();
        let result = run_with_cooperative_scheduler_observing(
            &mut env,
            &mut emu,
            &image,
            SOURCE,
            1_000,
            8,
            |context, observation| {
                assert_eq!(context, IndirectTransferExecutionContext::Main);
                assert_eq!(observation.source_rip, SOURCE + 20);
                assert_eq!(observation.target_rip, TARGET);
                assert_eq!(observation.source_bytes, vec![0xff, 0xe0]);
                assert_eq!(observation.target_bytes.first(), Some(&0xc3));
                assert_eq!(observed_register(observation, RegisterX86::RIP), TARGET);
                assert_eq!(observed_register(observation, RegisterX86::RAX), TARGET);
                assert_eq!(observed_register(observation, RegisterX86::R15), MAIN_R15);
                assert_eq!(observed_register(observation, RegisterX86::RSP), rsp);
                callbacks.push((context, observation.clone()));
                IndirectTransferDisposition::ResumeAdjudicatedRefutation
            },
        )
        .unwrap();

        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        assert!(result.handled.is_empty());
        assert!(result.cooperative_yields.is_empty());
        assert_eq!(result.main_instructions_after_first_yield, 0);
        let [(context, observation)] = callbacks.as_slice() else {
            panic!("expected exactly one main-thread transfer callback");
        };
        assert_eq!(*context, IndirectTransferExecutionContext::Main);
        assert_eq!(observation.target_rip, TARGET);
        assert!(emu.indirect_transfer_observation().is_none());
        assert!(emu.indirect_transfer_capture_failure().is_none());
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        assert_eq!(emu.read_reg(RegisterX86::R15).unwrap(), MAIN_R15);
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
    }

    #[test]
    fn observing_scheduler_rearms_refuted_child_before_restoring_main_context() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        const CHILD_TARGET: u64 = IMAGE_BASE + IMAGE_SIZE as u64 + 0x1000;
        const CHILD_R15: u64 = 0x6162_6364_6566_6768;
        const MAIN_R15: u64 = 0x7172_7374_7576_7778;
        const MAIN_FS: u64 = 0x0000_0000_1234_5000;

        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();

        let mut child_code = vec![0x49, 0xbf]; // mov r15, CHILD_R15
        child_code.extend_from_slice(&CHILD_R15.to_le_bytes());
        child_code.extend_from_slice(&[0x48, 0xb8]); // mov rax, CHILD_TARGET
        child_code.extend_from_slice(&CHILD_TARGET.to_le_bytes());
        child_code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        emu.map_code(CHILD_START, &child_code).unwrap();
        emu.map_code(CHILD_TARGET, &[0xc3]).unwrap(); // ret to the child return guard
        emu.map_code(image.entry_point_va(), &[0xc3]).unwrap(); // main ret to zero
        emu.configure_indirect_transfer_watch(
            &[(CHILD_START, CHILD_START + u64::from(PAGE_SIZE))],
            &[(CHILD_TARGET, CHILD_TARGET + u64::from(PAGE_SIZE))],
            false,
        )
        .unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();

        let main_rsp = STACK_BASE + 0x20_000;
        let main_stack_before = vec![0x5a; 0x40];
        emu.write_mem(main_rsp, &main_stack_before).unwrap();
        emu.write_mem(main_rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_mem(main_rsp + 8, &0u64.to_le_bytes()).unwrap();
        let main_stack_expected = emu.read_mem(main_rsp, main_stack_before.len()).unwrap();
        seed_sleep_machine_state(&mut emu, 1, main_rsp, sleep_stub);
        emu.write_reg(RegisterX86::R15, MAIN_R15).unwrap();
        emu.write_reg(RegisterX86::FS_BASE, MAIN_FS).unwrap();
        emu.write_reg(RegisterX86::GS_BASE, crate::emu::TEB_BASE)
            .unwrap();
        let main_before = sleep_machine_state(&emu);

        let mut callbacks = Vec::new();
        let result = run_with_cooperative_scheduler_observing(
            &mut env,
            &mut emu,
            &image,
            sleep_stub,
            1_000,
            8,
            |context, observation| {
                assert_eq!(
                    context,
                    IndirectTransferExecutionContext::Child { thread_id: 2 }
                );
                assert_eq!(observation.source_rip, CHILD_START + 20);
                assert_eq!(observation.target_rip, CHILD_TARGET);
                assert_eq!(
                    observed_register(observation, RegisterX86::RIP),
                    CHILD_TARGET
                );
                assert_eq!(
                    observed_register(observation, RegisterX86::RAX),
                    CHILD_TARGET
                );
                assert_eq!(observed_register(observation, RegisterX86::R15), CHILD_R15);
                assert_eq!(observation.source_bytes, vec![0xff, 0xe0]);
                assert_eq!(observation.target_bytes.first(), Some(&0xc3));
                callbacks.push((context, observation.clone()));
                IndirectTransferDisposition::ResumeAdjudicatedRefutation
            },
        )
        .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        assert!(result.main_instructions_after_first_yield > 0);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected exactly one cooperative child turn");
        };
        assert_eq!(yielded.thread_id, 2);
        assert_eq!(yielded.stop, CooperativeThreadStop::ReachedReturnGuard);
        assert!(yielded.handled.is_empty());
        assert!(yielded.instructions_executed > 0);

        let [(context, observation)] = callbacks.as_slice() else {
            panic!("expected exactly one child transfer callback");
        };
        assert_eq!(
            *context,
            IndirectTransferExecutionContext::Child { thread_id: 2 }
        );
        assert_eq!(
            observed_register(observation, RegisterX86::RSP),
            yielded.entry_rsp
        );
        assert!(emu.indirect_transfer_observation().is_none());
        assert!(emu.indirect_transfer_capture_failure().is_none());

        for (register, initial) in main_before {
            let expected = match register {
                RegisterX86::RIP => 0,
                RegisterX86::RSP => initial + 16,
                _ => initial,
            };
            assert_eq!(
                emu.read_reg(register).unwrap(),
                expected,
                "child state leaked into restored main {register:?}"
            );
        }
        assert_eq!(emu.read_reg(RegisterX86::FS_BASE).unwrap(), MAIN_FS);
        assert_eq!(
            emu.read_reg(RegisterX86::GS_BASE).unwrap(),
            crate::emu::TEB_BASE
        );
        assert_eq!(
            emu.read_mem(main_rsp, main_stack_expected.len()).unwrap(),
            main_stack_expected
        );
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
        assert!(env.scheduled_thread_ids.contains(&2));
        assert!(env.runnable_unscheduled_threads().next().is_none());
    }

    #[test]
    fn observing_scheduler_stop_preserves_child_boundary_and_labels_context() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        const CHILD_TARGET: u64 = IMAGE_BASE + IMAGE_SIZE as u64 + 0x1000;
        const MAIN_CONTINUATION: u64 = IMAGE_BASE + CODE_RVA as u64;
        const MAIN_R15: u64 = 0x8182_8384_8586_8788;

        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();

        let mut child_code = vec![0x48, 0xb8]; // mov rax, CHILD_TARGET
        child_code.extend_from_slice(&CHILD_TARGET.to_le_bytes());
        child_code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        emu.map_code(CHILD_START, &child_code).unwrap();
        emu.map_code(CHILD_TARGET, &[0x90, 0x0f, 0x0b]).unwrap();
        emu.map_code(MAIN_CONTINUATION, &[0xc3]).unwrap();
        emu.configure_indirect_transfer_watch(
            &[(CHILD_START, CHILD_START + u64::from(PAGE_SIZE))],
            &[(CHILD_TARGET, CHILD_TARGET + u64::from(PAGE_SIZE))],
            false,
        )
        .unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();

        let main_rsp = STACK_BASE + 0x20_000;
        emu.write_mem(main_rsp, &MAIN_CONTINUATION.to_le_bytes())
            .unwrap();
        emu.write_mem(main_rsp + 8, &0u64.to_le_bytes()).unwrap();
        seed_sleep_machine_state(&mut emu, 1, main_rsp, sleep_stub);
        emu.write_reg(RegisterX86::R15, MAIN_R15).unwrap();
        let main_before = sleep_machine_state(&emu);

        let mut callbacks = Vec::new();
        let result = run_with_cooperative_scheduler_observing(
            &mut env,
            &mut emu,
            &image,
            sleep_stub,
            1_000,
            8,
            |context, observation| {
                callbacks.push((context, observation.clone()));
                IndirectTransferDisposition::Stop
            },
        )
        .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::IndirectTransferObserved);
        assert_eq!(result.main_instructions_after_first_yield, 0);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected one stopped cooperative child turn");
        };
        assert_eq!(yielded.thread_id, 2);
        assert_eq!(
            yielded.stop,
            CooperativeThreadStop::Trap(TrapStop::IndirectTransferObserved)
        );

        let [(context, callback_observation)] = callbacks.as_slice() else {
            panic!("expected exactly one stopped child callback");
        };
        assert_eq!(
            *context,
            IndirectTransferExecutionContext::Child { thread_id: 2 }
        );
        assert_eq!(callback_observation.source_rip, CHILD_START + 10);
        assert_eq!(callback_observation.target_rip, CHILD_TARGET);
        assert_eq!(
            emu.indirect_transfer_observation().as_ref(),
            Some(callback_observation)
        );
        assert!(emu.indirect_transfer_capture_failure().is_none());

        for (register, initial) in main_before {
            let expected = match register {
                RegisterX86::RIP => MAIN_CONTINUATION,
                RegisterX86::RSP => initial + 8,
                _ => initial,
            };
            assert_eq!(
                emu.read_reg(register).unwrap(),
                expected,
                "stopped child state leaked into main {register:?}"
            );
        }
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
    }

    #[test]
    fn cooperative_return_guard_requires_consumed_entry_cell() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;

        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        // Load the dynamic guard from the entry cell, then jump to it without
        // consuming that cell as a real `ret` would.
        emu.map_code(CHILD_START, &[0x48, 0x8b, 0x04, 0x24, 0xff, 0xe0])
            .unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();
        let thread = *env.created_threads.get(&2).unwrap();
        let runtime = configure_cooperative_runtime(&mut env, &mut emu, 2, thread).unwrap();
        let mut stop_at_transfer =
            |_: IndirectTransferExecutionContext, _: &IndirectTransferObservation| {
                IndirectTransferDisposition::Stop
            };

        let (handled, stop, instructions_executed) = run_cooperative_child(
            &mut env,
            &mut emu,
            &image,
            2,
            CHILD_START,
            runtime,
            &mut stop_at_transfer,
        )
        .unwrap();

        assert!(handled.is_empty());
        assert!(instructions_executed > 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            runtime.return_guard
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), runtime.entry_rsp);
        assert_eq!(
            stop,
            CooperativeThreadStop::Trap(TrapStop::UnexpectedFault {
                address: runtime.return_guard,
            })
        );
    }

    #[test]
    fn cooperative_child_hard_error_restores_main_cpu_and_thread_id() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        const BAD_RSP: u64 = 0x0000_0000_dead_0000;

        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        assert!(emu.read_mem(BAD_RSP, 8).is_err());
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
        let thread_id_stub = env
            .export_stub_by_base(kernel32, "GetCurrentThreadId")
            .unwrap();
        emu.map_code(image.entry_point_va(), &[0xc3]).unwrap();
        let mut child_code = Vec::new();
        child_code.extend_from_slice(&[0x48, 0xbc]); // mov rsp, BAD_RSP
        child_code.extend_from_slice(&BAD_RSP.to_le_bytes());
        child_code.extend_from_slice(&[0x48, 0xb8]); // mov rax, GetCurrentThreadId
        child_code.extend_from_slice(&thread_id_stub.to_le_bytes());
        child_code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        emu.map_code(CHILD_START, &child_code).unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();

        let main_rsp = STACK_BASE + 0x20_000;
        let return_address = image.entry_point_va();
        emu.write_mem(main_rsp, &return_address.to_le_bytes())
            .unwrap();
        seed_sleep_machine_state(&mut emu, 1, main_rsp, sleep_stub);
        emu.write_reg(RegisterX86::FS_BASE, PEB_BASE).unwrap();
        emu.write_reg(RegisterX86::GS_BASE, crate::emu::TEB_BASE)
            .unwrap();
        let main_before = sleep_machine_state(&emu);
        let main_fs = emu.read_reg(RegisterX86::FS_BASE).unwrap();
        let main_gs = emu.read_reg(RegisterX86::GS_BASE).unwrap();

        let error =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                .unwrap_err();

        assert!(
            matches!(error, EmuError::ReadMem { addr, size, .. } if addr == BAD_RSP && size == 8),
            "unexpected child error: {error:?}"
        );
        assert_sleep_return_state(&emu, &main_before, return_address);
        assert_eq!(emu.read_reg(RegisterX86::FS_BASE).unwrap(), main_fs);
        assert_eq!(emu.read_reg(RegisterX86::GS_BASE).unwrap(), main_gs);
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
        assert!(env.scheduled_thread_ids.contains(&2));
    }

    #[test]
    fn raw_trap_runner_keeps_created_thread_unscheduled() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
        emu.map_code(image.entry_point_va(), &[0xeb, 0xfe]).unwrap();
        emu.map_code(CHILD_START, &[0xc3]).unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();
        let rsp = STACK_BASE + 0x20_000;
        emu.write_mem(rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, 1).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let result = run_with_import_trap(&mut env, &mut emu, &image, sleep_stub, 32, 8).unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(env.runnable_unscheduled_threads().count(), 1);
        assert!(env.scheduled_thread_ids.is_empty());
        assert!(emu.read_mem(COOPERATIVE_THREAD_RUNTIME_BASE, 1).is_err());
    }

    #[test]
    fn cooperative_child_sleep_and_named_api_wall_restore_main() {
        for child_sleeps in [true, false] {
            let image = test_image();
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
            let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
            let child_start = if child_sleeps {
                sleep_stub
            } else {
                env.resolve_proc(&mut emu, kernel32, "FutureObservedApi")
                    .unwrap()
            };
            emu.map_code(image.entry_point_va(), &[0xc3]).unwrap();
            env.create_thread(&mut emu, 0, 0, child_start, 1, 0, 0)
                .unwrap();
            let rsp = STACK_BASE + 0x20_000;
            emu.write_mem(rsp, &image.entry_point_va().to_le_bytes())
                .unwrap();
            emu.write_mem(rsp + 8, &0u64.to_le_bytes()).unwrap();
            emu.write_reg(RegisterX86::RCX, 1).unwrap();
            emu.write_reg(RegisterX86::RSP, rsp).unwrap();

            let result =
                run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                    .unwrap();

            assert_eq!(result.stop, TrapStop::NullControlTransfer);
            let [yielded] = result.cooperative_yields.as_slice() else {
                panic!("expected one cooperative yield");
            };
            if child_sleeps {
                assert_eq!(yielded.handled, vec!["Sleep".to_owned()]);
                assert_eq!(yielded.stop, CooperativeThreadStop::BlockedOnSleep);
            } else {
                assert!(yielded.handled.is_empty());
                assert_eq!(
                    yielded.stop,
                    CooperativeThreadStop::Trap(TrapStop::UnhandledApi {
                        name: "FutureObservedApi".to_owned(),
                        rva: 0,
                    })
                );
            }
            assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
            assert_eq!(
                emu.read_reg(RegisterX86::GS_BASE).unwrap(),
                crate::emu::TEB_BASE
            );
        }
    }

    #[test]
    fn unsupported_main_sleep_does_not_claim_pending_child() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
        emu.map_code(CHILD_START, &[0xc3]).unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();
        emu.write_reg(RegisterX86::RCX, 0).unwrap();

        let result =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                .unwrap();

        assert_eq!(
            result.stop,
            TrapStop::UnhandledApi {
                name: "Sleep".to_owned(),
                rva: env.stub_export_at(sleep_stub).unwrap().1,
            }
        );
        assert!(result.cooperative_yields.is_empty());
        assert_eq!(env.runnable_unscheduled_threads().count(), 1);
    }

    #[test]
    fn cooperative_child_instruction_cap_restores_and_resumes_main() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        const MAIN_R15: u64 = 0xfeed_face_cafe_beef;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
        emu.map_code(image.entry_point_va(), &[0xc3]).unwrap();
        emu.map_code(CHILD_START, &[0xeb, 0xfe]).unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();
        let rsp = STACK_BASE + 0x20_000;
        emu.write_mem(rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_mem(rsp + 8, &0u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, 1).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        emu.write_reg(RegisterX86::R15, MAIN_R15).unwrap();

        let result =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 8)
                .unwrap();

        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected one cooperative yield");
        };
        assert_eq!(
            yielded.stop,
            CooperativeThreadStop::Trap(TrapStop::InstructionCap)
        );
        assert_eq!(
            yielded.instructions_executed,
            COOPERATIVE_CHILD_INSTRUCTION_CAP
        );
        assert_eq!(emu.read_reg(RegisterX86::R15).unwrap(), MAIN_R15);
        assert_eq!(
            emu.read_reg(RegisterX86::GS_BASE).unwrap(),
            crate::emu::TEB_BASE
        );
        assert_eq!(env.current_thread_id, EMULATED_CURRENT_THREAD_ID);
    }

    #[test]
    fn cooperative_child_api_cap_is_independent_of_main_call_cap() {
        const CHILD_START: u64 = IMAGE_BASE + DATA_RVA as u64;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let sleep_stub = env.export_stub_by_base(kernel32, "Sleep").unwrap();
        let thread_id_stub = env
            .export_stub_by_base(kernel32, "GetCurrentThreadId")
            .unwrap();
        emu.map_code(image.entry_point_va(), &[0xc3]).unwrap();
        let mut child_code = Vec::new();
        for _ in 0..=COOPERATIVE_CHILD_API_CAP {
            child_code.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]);
            child_code.extend_from_slice(&[0x48, 0xb8]);
            child_code.extend_from_slice(&thread_id_stub.to_le_bytes());
            child_code.extend_from_slice(&[0xff, 0xd0]);
            child_code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
        }
        child_code.push(0xc3);
        emu.map_code(CHILD_START, &child_code).unwrap();
        env.create_thread(&mut emu, 0, 0, CHILD_START, 0, 0, 0)
            .unwrap();
        let rsp = STACK_BASE + 0x20_000;
        emu.write_mem(rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_mem(rsp + 8, &0u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, 1).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let result =
            run_with_cooperative_scheduler(&mut env, &mut emu, &image, sleep_stub, 1_000, 1)
                .unwrap();

        assert_eq!(result.handled, vec!["Sleep".to_owned()]);
        let [yielded] = result.cooperative_yields.as_slice() else {
            panic!("expected one cooperative yield");
        };
        assert_eq!(yielded.handled.len(), COOPERATIVE_CHILD_API_CAP);
        assert!(yielded
            .handled
            .iter()
            .all(|name| name == "GetCurrentThreadId"));
        assert_eq!(
            yielded.stop,
            CooperativeThreadStop::Trap(TrapStop::Other(
                "cooperative child API cap reached".to_owned()
            ))
        );
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
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
                first: 1,
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
    fn rtl_add_vectored_exception_handler_invalid_return_is_failure_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let invalid_rsp = 0x0000_0000_dead_0000;
        let initial_rax = 0xaaaa_bbbb_cccc_dddd;
        let initial_rip = 0x1111_2222_3333_4444;
        let initial_cursor = env.next_vectored_exception_handler_token;
        emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
        emu.write_reg(RegisterX86::RCX, 1).unwrap();
        emu.write_reg(RegisterX86::RDX, 0x0000_0001_4006_aa83)
            .unwrap();
        emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();
        emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();

        assert!(dispatch(&mut env, &mut emu, "RtlAddVectoredExceptionHandler").is_err());
        assert!(env.vectored_exception_handlers.is_empty());
        assert_eq!(env.next_vectored_exception_handler_token, initial_cursor);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), invalid_rsp);
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
                    first: 0x8000_0000,
                    handler: handler_d,
                },
                VectoredExceptionHandlerRegistration {
                    token: token_c,
                    first: 1,
                    handler: handler_c,
                },
                VectoredExceptionHandlerRegistration {
                    token: token_a,
                    first: 0,
                    handler: handler_a,
                },
                VectoredExceptionHandlerRegistration {
                    token: token_b,
                    first: 0,
                    handler: handler_b,
                },
            ]
        );
        assert_eq!(
            env.vectored_exception_handler_registrations()
                .collect::<Vec<_>>(),
            vec![
                (0, token_d, 0x8000_0000, handler_d),
                (1, token_c, 1, handler_c),
                (2, token_a, 0, handler_a),
                (3, token_b, 0, handler_b),
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
                    first: 0,
                    handler: duplicate_handler,
                },
                VectoredExceptionHandlerRegistration {
                    token: zero,
                    first: 0,
                    handler: 0,
                },
                VectoredExceptionHandlerRegistration {
                    token: duplicate,
                    first: 0,
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
    fn rtl_remove_vectored_exception_handler_removes_exact_token_and_is_failure_atomic() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let first =
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, 0x1111_2222_3333_4444);
        let second =
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, 0x5555_6666_7777_8888);
        let rsp = STACK_BASE + 0x608;
        let return_address = 0x1234_5678_9abc_def0u64;
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, first).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "RtlRemoveVectoredExceptionHandler").unwrap(),
            ApiOutcome::Handled {
                name: "RtlRemoveVectoredExceptionHandler".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(
            env.vectored_exception_handlers
                .iter()
                .map(|registration| registration.token)
                .collect::<Vec<_>>(),
            vec![second]
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);

        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RCX, first).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert_eq!(
            dispatch(&mut env, &mut emu, "RtlRemoveVectoredExceptionHandler").unwrap(),
            ApiOutcome::Handled {
                name: "RtlRemoveVectoredExceptionHandler".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(env.vectored_exception_handlers.len(), 1);

        let registrations_before = env.vectored_exception_handlers.clone();
        let invalid_rsp = 0x0000_0000_dead_0000;
        emu.write_reg(RegisterX86::RCX, second).unwrap();
        emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();
        assert!(matches!(
            dispatch(&mut env, &mut emu, "RtlRemoveVectoredExceptionHandler"),
            Err(EmuError::ReadMem { addr, size: 8, .. }) if addr == invalid_rsp
        ));
        assert_eq!(env.vectored_exception_handlers, registrations_before);
    }

    #[test]
    fn raise_exception_builds_bounded_zero_argument_frame_and_continues_via_first_handler() {
        const HANDLER: u64 = IMAGE_BASE + 0x10_000;
        const CONTINUATION: u64 = IMAGE_BASE + 0x12_000;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_code(HANDLER, &[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3])
            .unwrap();
        emu.map_code(CONTINUATION, &[0xeb, 0xfe]).unwrap();
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, HANDLER);
        let rsp = STACK_BASE + 0x808;

        assert_eq!(
            begin_test_raise_exception(
                &mut env,
                &mut emu,
                TestRaiseExceptionArgs {
                    code: 0xaaaa_bbbb_c000_008e,
                    flags: 0xcccc_dddd_0000_0000,
                    argument_count: 0xeeee_ffff_0000_0000,
                    arguments: 0,
                    rsp,
                    return_address: CONTINUATION,
                },
            ),
            ApiOutcome::HandledVoid {
                name: "RaiseException".to_owned()
            }
        );
        let pending = env
            .pending_vectored_exceptions
            .get(&EMULATED_CURRENT_THREAD_ID)
            .unwrap()
            .clone();
        assert_eq!(pending.return_guard, EXCEPTION_DISPATCH_ARENA_BASE);
        assert_eq!(pending.exception_pointers & 0xf, 0);
        assert_eq!(pending.context_record & 0xf, 0);
        assert_eq!(pending.callback_rsp & 0xf, 8);
        assert_eq!(
            read_u64_at(&emu, pending.exception_pointers).unwrap(),
            pending.exception_record
        );
        assert_eq!(
            read_u64_at(&emu, pending.exception_pointers + 8).unwrap(),
            pending.context_record
        );
        assert_eq!(
            read_u32_at(&emu, pending.exception_record).unwrap(),
            0xc000_008e
        );
        assert_eq!(read_u32_at(&emu, pending.exception_record + 4).unwrap(), 0);
        assert_eq!(read_u64_at(&emu, pending.exception_record + 8).unwrap(), 0);
        assert_eq!(
            read_u64_at(&emu, pending.exception_record + 0x10).unwrap(),
            CONTINUATION
        );
        assert_eq!(
            read_u32_at(&emu, pending.exception_record + 0x18).unwrap(),
            0
        );
        assert_eq!(
            read_u32_at(
                &emu,
                pending.context_record + AMD64_CONTEXT_FLAGS_OFFSET as u64
            )
            .unwrap(),
            CONTEXT_AMD64_CONTROL_INTEGER
        );
        assert_eq!(
            read_u64_at(
                &emu,
                pending.context_record + AMD64_CONTEXT_RSP_OFFSET as u64
            )
            .unwrap(),
            rsp + 8
        );
        assert_eq!(
            read_u64_at(
                &emu,
                pending.context_record + AMD64_CONTEXT_RIP_OFFSET as u64
            )
            .unwrap(),
            CONTINUATION
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RCX).unwrap(),
            pending.exception_pointers
        );
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), HANDLER);
        assert_eq!(
            emu.read_reg(RegisterX86::RSP).unwrap(),
            pending.callback_rsp
        );
        assert_eq!(
            read_u64_at(&emu, pending.callback_rsp).unwrap(),
            pending.return_guard
        );

        let result = run_with_import_trap(&mut env, &mut emu, &image, HANDLER, 32, 8).unwrap();
        assert_eq!(result.handled, Vec::<String>::new());
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), CONTINUATION);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            0xaaaa_bbbb_cccc_dddd
        );
        assert!(!env.has_pending_vectored_exception());
    }

    #[test]
    fn raise_exception_search_uses_snapshotted_order_then_continues() {
        const SEARCH_HANDLER: u64 = IMAGE_BASE + 0x14_000;
        const CONTINUE_HANDLER: u64 = IMAGE_BASE + 0x16_000;
        const LATE_FIRST_HANDLER: u64 = IMAGE_BASE + 0x18_000;
        const CONTINUATION: u64 = IMAGE_BASE + 0x1a_000;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_code(SEARCH_HANDLER, &[0x31, 0xc0, 0xc3]).unwrap();
        emu.map_code(CONTINUE_HANDLER, &[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3])
            .unwrap();
        emu.map_code(CONTINUATION, &[0xeb, 0xfe]).unwrap();
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, SEARCH_HANDLER);
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, CONTINUE_HANDLER);
        let rsp = STACK_BASE + 0xa08;
        begin_test_raise_exception(
            &mut env,
            &mut emu,
            TestRaiseExceptionArgs {
                code: 0xc000_008e,
                flags: 0,
                argument_count: 0,
                arguments: 0,
                rsp,
                return_address: CONTINUATION,
            },
        );

        // Registrations made after RaiseException begins do not perturb the
        // snapshot already walking on this thread.
        assert_ne!(env.add_vectored_exception_handler(1, LATE_FIRST_HANDLER), 0);
        let result =
            run_with_import_trap(&mut env, &mut emu, &image, SEARCH_HANDLER, 64, 8).unwrap();
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), CONTINUATION);
        assert!(!env.has_pending_vectored_exception());
    }

    #[test]
    fn raise_exception_attributes_changed_context_to_handler_returning_continue() {
        const MUTATING_SEARCH_HANDLER: u64 = IMAGE_BASE + 0x32_000;
        const CONTINUE_HANDLER: u64 = IMAGE_BASE + 0x34_000;
        const TARGET: u64 = IMAGE_BASE + 0x36_000;
        const CONTINUATION: u64 = IMAGE_BASE + 0x38_000;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let mut mutator = vec![0x48, 0x8b, 0x41, 0x08]; // mov rax,[rcx+8]
        mutator.extend_from_slice(&[0x48, 0xba]); // mov rdx,TARGET
        mutator.extend_from_slice(&TARGET.to_le_bytes());
        mutator.extend_from_slice(&[0x48, 0x89, 0x90, 0xf8, 0, 0, 0]); // [rax+f8]=rdx
        mutator.extend_from_slice(&[0x31, 0xc0, 0xc3]); // CONTINUE_SEARCH
        emu.map_code(MUTATING_SEARCH_HANDLER, &mutator).unwrap();
        emu.map_code(CONTINUE_HANDLER, &[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3])
            .unwrap();
        emu.map_code(TARGET, &[0xeb, 0xfe]).unwrap();
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, MUTATING_SEARCH_HANDLER);
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 0, CONTINUE_HANDLER);
        begin_test_raise_exception(
            &mut env,
            &mut emu,
            TestRaiseExceptionArgs {
                code: 0xc000_008e,
                flags: 0,
                argument_count: 0,
                arguments: 0,
                rsp: STACK_BASE + 0x1608,
                return_address: CONTINUATION,
            },
        );

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, MUTATING_SEARCH_HANDLER, 64, 8)
                .unwrap();
        assert_eq!(result.stop, TrapStop::ExceptionContinuationObserved);
        let observation = env.changed_exception_continuation().unwrap();
        assert_eq!(observation.original_rip, CONTINUATION);
        assert_eq!(observation.continuation_rip, TARGET);
        assert_eq!(observation.continuing_handler, CONTINUE_HANDLER);
    }

    #[test]
    fn raise_exception_fails_closed_on_terminal_handler_dispositions() {
        const HANDLER: u64 = IMAGE_BASE + 0x1c_000;
        const CONTINUATION: u64 = IMAGE_BASE + 0x1e_000;
        let image = test_image();
        for (handler_bytes, flags, expected) in [
            (
                &[0x31, 0xc0, 0xc3][..],
                0,
                TrapStop::UnhandledSoftwareException { code: 0xc000_008e },
            ),
            (
                &[0xb8, 1, 0, 0, 0, 0xc3][..],
                0,
                TrapStop::InvalidVectoredExceptionDisposition {
                    code: 0xc000_008e,
                    disposition: 1,
                },
            ),
            (
                &[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3][..],
                1,
                TrapStop::NoncontinuableContinuationAttempt { code: 0xc000_008e },
            ),
        ] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            emu.map_code(HANDLER, handler_bytes).unwrap();
            call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, HANDLER);
            begin_test_raise_exception(
                &mut env,
                &mut emu,
                TestRaiseExceptionArgs {
                    code: 0xc000_008e,
                    flags,
                    argument_count: 0,
                    arguments: 0,
                    rsp: STACK_BASE + 0xc08,
                    return_address: CONTINUATION,
                },
            );
            let result = run_with_import_trap(&mut env, &mut emu, &image, HANDLER, 16, 8).unwrap();
            assert_eq!(result.stop, expected);
            assert!(env.has_pending_vectored_exception());
        }
    }

    #[test]
    fn raise_exception_copies_bounded_arguments_and_rejects_bad_input_atomically() {
        const HANDLER: u64 = IMAGE_BASE + 0x20_000;
        const ARGUMENTS: u64 = 0x0000_000f_6000_0000;
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_code(HANDLER, &[0x31, 0xc0, 0xc3]).unwrap();
        emu.map_zeroed_rw(ARGUMENTS, u64::from(PAGE_SIZE)).unwrap();
        let values = (0..16u64).map(|value| value + 0x100).collect::<Vec<_>>();
        for (index, value) in values.iter().enumerate() {
            emu.write_mem(ARGUMENTS + index as u64 * 8, &value.to_le_bytes())
                .unwrap();
        }
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, HANDLER);
        begin_test_raise_exception(
            &mut env,
            &mut emu,
            TestRaiseExceptionArgs {
                code: 0xaaaa_bbbb_c000_008e,
                flags: 0,
                argument_count: 0xcccc_dddd_0000_0010,
                arguments: ARGUMENTS,
                rsp: STACK_BASE + 0xe08,
                return_address: IMAGE_BASE + 0x22_000,
            },
        );
        let pending = env
            .pending_vectored_exceptions
            .get(&EMULATED_CURRENT_THREAD_ID)
            .unwrap();
        assert_eq!(
            read_u32_at(&emu, pending.exception_record + 0x18).unwrap(),
            EXCEPTION_MAXIMUM_PARAMETERS as u32
        );
        for (index, expected) in values[..EXCEPTION_MAXIMUM_PARAMETERS].iter().enumerate() {
            assert_eq!(
                read_u64_at(&emu, pending.exception_record + 0x20 + index as u64 * 8).unwrap(),
                *expected
            );
        }

        let mut bad_emu = Emu::new().unwrap();
        let mut bad_env = Win64Env::new(IMAGE_BASE);
        bad_emu.map_code(HANDLER, &[0x31, 0xc0, 0xc3]).unwrap();
        call_rtl_add_vectored_exception_handler(&mut bad_env, &mut bad_emu, 1, HANDLER);
        let cursor_before = bad_env.next_exception_dispatch_base;
        let rsp = STACK_BASE + 0xe08;
        bad_emu
            .write_mem(rsp, &(IMAGE_BASE + 0x22_000).to_le_bytes())
            .unwrap();
        bad_emu.write_reg(RegisterX86::RCX, 0xc000_008e).unwrap();
        bad_emu.write_reg(RegisterX86::RDX, 0).unwrap();
        bad_emu.write_reg(RegisterX86::R8, 1).unwrap();
        bad_emu.write_reg(RegisterX86::R9, 0xdead_0000).unwrap();
        bad_emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert!(matches!(
            dispatch(&mut bad_env, &mut bad_emu, "RaiseException"),
            Err(EmuError::ReadMem { .. })
        ));
        assert_eq!(bad_env.next_exception_dispatch_base, cursor_before);
        assert!(!bad_env.has_pending_vectored_exception());
        assert!(bad_emu.read_mem(EXCEPTION_DISPATCH_ARENA_BASE, 1).is_err());
    }

    #[test]
    fn raise_exception_rejects_undeclared_context_mutation() {
        const HANDLER: u64 = IMAGE_BASE + 0x24_000;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_code(HANDLER, &[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3])
            .unwrap();
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, HANDLER);
        begin_test_raise_exception(
            &mut env,
            &mut emu,
            TestRaiseExceptionArgs {
                code: 0xc000_008e,
                flags: 0,
                argument_count: 0,
                arguments: 0,
                rsp: STACK_BASE + 0x1008,
                return_address: IMAGE_BASE + 0x26_000,
            },
        );
        let context = env
            .pending_vectored_exceptions
            .get(&EMULATED_CURRENT_THREAD_ID)
            .unwrap()
            .context_record;
        emu.write_mem(context + 0x100, &[1]).unwrap();
        let result = run_with_import_trap(&mut env, &mut emu, &image, HANDLER, 16, 8).unwrap();
        assert_eq!(
            result.stop,
            TrapStop::InvalidVectoredExceptionContext { code: 0xc000_008e }
        );
        assert!(env.has_pending_vectored_exception());
    }

    #[test]
    fn raise_exception_changed_rip_stops_before_target_without_consuming_oep_coverage() {
        const HANDLER: u64 = IMAGE_BASE + 0x28_000;
        const TARGET: u64 = IMAGE_BASE + 0x2a_000;
        const CONTINUATION: u64 = IMAGE_BASE + 0x2c_000;
        const RESTORED_RAX: u64 = 0xfeed_face_cafe_beef;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        emu.map_code(HANDLER, &[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3])
            .unwrap();
        emu.map_code(TARGET, &[0xeb, 0xfe]).unwrap();
        emu.configure_indirect_transfer_watch(
            &[(HANDLER, HANDLER + 0x100)],
            &[(TARGET, TARGET + 0x100)],
            false,
        )
        .unwrap();
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, HANDLER);
        begin_test_raise_exception(
            &mut env,
            &mut emu,
            TestRaiseExceptionArgs {
                code: 0xc000_008e,
                flags: 0,
                argument_count: 0,
                arguments: 0,
                rsp: STACK_BASE + 0x1208,
                return_address: CONTINUATION,
            },
        );
        let context_record = env
            .pending_vectored_exceptions
            .get(&EMULATED_CURRENT_THREAD_ID)
            .unwrap()
            .context_record;
        emu.write_mem(
            context_record + AMD64_CONTEXT_RIP_OFFSET as u64,
            &TARGET.to_le_bytes(),
        )
        .unwrap();
        emu.write_mem(
            context_record + AMD64_CONTEXT_RAX_OFFSET as u64,
            &RESTORED_RAX.to_le_bytes(),
        )
        .unwrap();

        let result = run_with_import_trap(&mut env, &mut emu, &image, HANDLER, 32, 8).unwrap();
        assert_eq!(result.stop, TrapStop::ExceptionContinuationObserved);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), TARGET);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), RESTORED_RAX);
        assert!(emu.indirect_transfer_observation().is_none());
        assert!(!env.has_pending_vectored_exception());
        let observation = env.changed_exception_continuation().unwrap();
        assert_eq!(observation.thread_id, EMULATED_CURRENT_THREAD_ID);
        assert_eq!(observation.exception_code, 0xc000_008e);
        assert_eq!(observation.continuing_handler, HANDLER);
        assert_eq!(observation.original_rip, CONTINUATION);
        assert_eq!(observation.continuation_rip, TARGET);
        assert_eq!(observation.context_record, context_record);
        assert_eq!(&observation.target_bytes[..2], &[0xeb, 0xfe]);
        assert_eq!(observation.context_bytes.len(), AMD64_CONTEXT_SIZE);
        assert_eq!(observation.registers.len(), 18);
        assert_eq!(
            observation
                .registers
                .iter()
                .find_map(|(register, value)| (*register == RegisterX86::RAX).then_some(*value)),
            Some(RESTORED_RAX)
        );
        let count_before_retry = emu.total_instructions_executed();
        let retry = run_with_import_trap(&mut env, &mut emu, &image, TARGET, 32, 8).unwrap();
        assert_eq!(retry.stop, TrapStop::ExceptionContinuationObserved);
        assert!(retry.handled.is_empty());
        assert_eq!(emu.total_instructions_executed(), count_before_retry);
        assert!(emu.indirect_transfer_observation().is_none());
    }

    #[test]
    fn raise_exception_preserves_xmm_and_mxcsr_state_across_observed_leaf_handler() {
        const HANDLER: u64 = IMAGE_BASE + 0x2e_000;
        const CONTINUATION: u64 = IMAGE_BASE + 0x30_000;
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        // mov dword [rsp+8],0x1f80; ldmxcsr [rsp+8];
        // pxor xmm0,xmm0; mov eax,-1; ret
        emu.map_code(
            HANDLER,
            &[
                0xc7, 0x44, 0x24, 0x08, 0x80, 0x1f, 0, 0, 0x0f, 0xae, 0x54, 0x24, 0x08, 0x66, 0x0f,
                0xef, 0xc0, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,
            ],
        )
        .unwrap();
        emu.map_code(CONTINUATION, &[0xeb, 0xfe]).unwrap();
        call_rtl_add_vectored_exception_handler(&mut env, &mut emu, 1, HANDLER);
        let initial_xmm0 = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
            0x23, 0x01,
        ];
        emu.write_reg_128(RegisterX86::XMM0, &initial_xmm0).unwrap();
        let initial_mxcsr = 0x1f40;
        emu.write_reg(RegisterX86::MXCSR, initial_mxcsr).unwrap();
        begin_test_raise_exception(
            &mut env,
            &mut emu,
            TestRaiseExceptionArgs {
                code: 0xc000_008e,
                flags: 0,
                argument_count: 0,
                arguments: 0,
                rsp: STACK_BASE + 0x1408,
                return_address: CONTINUATION,
            },
        );

        let result = run_with_import_trap(&mut env, &mut emu, &image, HANDLER, 32, 8).unwrap();
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg_128(RegisterX86::XMM0).unwrap(), initial_xmm0);
        assert_eq!(emu.read_reg(RegisterX86::MXCSR).unwrap(), initial_mxcsr);
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
    fn virtual_alloc_handles_observed_commit_as_zeroed_writable_nx_memory() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x400;
        let return_address = 0x1234_5678_9abc_def0;
        let allocation = call_virtual_alloc(
            &mut env,
            &mut emu,
            VirtualAllocArgs {
                allocation_type: 0xaaaa_bbbb_0000_0000 | u64::from(MEM_COMMIT),
                protection: 0xcccc_dddd_0000_0000 | u64::from(PAGE_READWRITE),
                ..VirtualAllocArgs::observed(4)
            },
            rsp,
            return_address,
        );

        assert_eq!(allocation, VIRTUAL_ALLOCATION_ARENA_BASE);
        assert_ne!(allocation, 0);
        assert!(allocation.is_multiple_of(VIRTUAL_ALLOCATION_GRANULARITY));
        assert_eq!(
            env.virtual_allocations.get(&allocation),
            Some(&VirtualAllocation {
                requested_size: 4,
                mapped_size: u64::from(PAGE_SIZE),
                allocation_type: MEM_COMMIT,
                protection: PAGE_READWRITE,
            })
        );
        assert_eq!(
            env.virtual_allocation_cursor,
            VIRTUAL_ALLOCATION_ARENA_BASE + VIRTUAL_ALLOCATION_GRANULARITY
        );
        assert_eq!(
            emu.read_mem(allocation, PAGE_SIZE as usize).unwrap(),
            vec![0; PAGE_SIZE as usize]
        );
        emu.write_mem(allocation, &[1, 2, 3, 4]).unwrap();
        assert_eq!(emu.read_mem(allocation, 4).unwrap(), vec![1, 2, 3, 4]);

        let report = emu.run_observed(allocation, 1).unwrap();
        assert!(matches!(
            report.stop_reason,
            StopReason::MemoryFault(fault)
                if fault.kind == FaultKind::FetchProt && fault.address == allocation
        ));
    }

    #[test]
    fn virtual_alloc_repeats_without_overlap_and_is_deterministic() {
        let sizes = [
            17,
            u64::from(PAGE_SIZE) + 1,
            VIRTUAL_ALLOCATION_GRANULARITY + 1,
        ];
        let rsp = STACK_BASE + 0x400;

        let mut first_emu = Emu::new().unwrap();
        let mut first_env = Win64Env::new(IMAGE_BASE);
        let first_addresses = sizes
            .into_iter()
            .enumerate()
            .map(|(index, size)| {
                call_virtual_alloc(
                    &mut first_env,
                    &mut first_emu,
                    VirtualAllocArgs::observed(size),
                    rsp,
                    0x1000 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            first_addresses,
            vec![
                VIRTUAL_ALLOCATION_ARENA_BASE,
                VIRTUAL_ALLOCATION_ARENA_BASE + VIRTUAL_ALLOCATION_GRANULARITY,
                VIRTUAL_ALLOCATION_ARENA_BASE + 2 * VIRTUAL_ALLOCATION_GRANULARITY,
            ]
        );
        for address in &first_addresses {
            assert!(address.is_multiple_of(VIRTUAL_ALLOCATION_GRANULARITY));
        }
        assert_eq!(
            first_env.virtual_allocations[&first_addresses[0]].mapped_size,
            u64::from(PAGE_SIZE)
        );
        assert_eq!(
            first_env.virtual_allocations[&first_addresses[1]].mapped_size,
            2 * u64::from(PAGE_SIZE)
        );
        assert_eq!(
            first_env.virtual_allocations[&first_addresses[2]].mapped_size,
            VIRTUAL_ALLOCATION_GRANULARITY + u64::from(PAGE_SIZE)
        );
        first_emu
            .write_mem(first_addresses[0], &[0xa5; 17])
            .unwrap();
        assert_eq!(
            first_emu.read_mem(first_addresses[0], 17).unwrap(),
            vec![0xa5; 17]
        );
        assert_eq!(
            first_emu.read_mem(first_addresses[1], 17).unwrap(),
            vec![0; 17]
        );
        assert!(first_emu
            .read_mem(first_addresses[0] + u64::from(PAGE_SIZE), 1)
            .is_err());

        let mut second_emu = Emu::new().unwrap();
        let mut second_env = Win64Env::new(IMAGE_BASE);
        let second_addresses = sizes
            .into_iter()
            .enumerate()
            .map(|(index, size)| {
                call_virtual_alloc(
                    &mut second_env,
                    &mut second_emu,
                    VirtualAllocArgs::observed(size),
                    rsp,
                    0x2000 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(second_addresses, first_addresses);
        assert_eq!(
            second_env.virtual_allocations,
            first_env.virtual_allocations
        );
        assert_eq!(
            second_env.virtual_allocation_cursor,
            first_env.virtual_allocation_cursor
        );
    }

    #[test]
    fn virtual_alloc_rejects_unmodeled_shapes_before_return_stack_access() {
        let invalid_rsp = 0x0000_0000_dead_0000;
        let cases = [
            VirtualAllocArgs {
                requested_address: u64::from(u32::MAX) + 1,
                ..VirtualAllocArgs::observed(4)
            },
            VirtualAllocArgs {
                allocation_type: 0xaaaa_bbbb_0000_2000,
                ..VirtualAllocArgs::observed(4)
            },
            VirtualAllocArgs {
                allocation_type: u64::from(MEM_COMMIT | 0x2000),
                ..VirtualAllocArgs::observed(4)
            },
            VirtualAllocArgs {
                protection: 0xcccc_dddd_0000_0002,
                ..VirtualAllocArgs::observed(4)
            },
        ];

        for args in cases {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            prepare_virtual_alloc_call(&mut emu, args, invalid_rsp, None);
            let initial_cpu = sleep_machine_state(&emu);
            let initial_cursor = env.virtual_allocation_cursor;
            let initial_allocations = env.virtual_allocations.clone();

            assert_eq!(
                dispatch(&mut env, &mut emu, "VirtualAlloc").unwrap(),
                ApiOutcome::Unhandled {
                    name: "VirtualAlloc".to_owned()
                }
            );
            assert_eq!(sleep_machine_state(&emu), initial_cpu);
            assert_eq!(env.virtual_allocation_cursor, initial_cursor);
            assert_eq!(env.virtual_allocations, initial_allocations);
            assert!(emu.read_mem(VIRTUAL_ALLOCATION_ARENA_BASE, 1).is_err());
        }
    }

    #[test]
    fn virtual_alloc_handles_size_and_arena_bounds_without_partial_state() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x400;
        let initial_cursor = env.virtual_allocation_cursor;

        for (index, size) in [0, u64::MAX, VIRTUAL_ALLOCATION_ARENA_SIZE + 1]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                call_virtual_alloc(
                    &mut env,
                    &mut emu,
                    VirtualAllocArgs::observed(size),
                    rsp,
                    0x3000 + index as u64,
                ),
                0
            );
            assert_eq!(env.virtual_allocation_cursor, initial_cursor);
            assert!(env.virtual_allocations.is_empty());
            assert!(emu.read_mem(VIRTUAL_ALLOCATION_ARENA_BASE, 1).is_err());
        }

        env.virtual_allocation_cursor =
            VIRTUAL_ALLOCATION_ARENA_END - VIRTUAL_ALLOCATION_GRANULARITY;
        let last = call_virtual_alloc(
            &mut env,
            &mut emu,
            VirtualAllocArgs::observed(VIRTUAL_ALLOCATION_GRANULARITY),
            rsp,
            0x4000,
        );
        assert_eq!(
            last,
            VIRTUAL_ALLOCATION_ARENA_END - VIRTUAL_ALLOCATION_GRANULARITY
        );
        assert_eq!(env.virtual_allocation_cursor, VIRTUAL_ALLOCATION_ARENA_END);
        let allocations_at_exhaustion = env.virtual_allocations.clone();
        assert_eq!(
            call_virtual_alloc(
                &mut env,
                &mut emu,
                VirtualAllocArgs::observed(1),
                rsp,
                0x5000,
            ),
            0
        );
        assert_eq!(env.virtual_allocation_cursor, VIRTUAL_ALLOCATION_ARENA_END);
        assert_eq!(env.virtual_allocations, allocations_at_exhaustion);
    }

    #[test]
    fn virtual_alloc_preflights_return_and_preserves_state_on_mapping_failure() {
        let invalid_rsp = 0x0000_0000_dead_0000;
        let mut invalid_emu = Emu::new().unwrap();
        let mut invalid_env = Win64Env::new(IMAGE_BASE);
        prepare_virtual_alloc_call(
            &mut invalid_emu,
            VirtualAllocArgs::observed(4),
            invalid_rsp,
            None,
        );
        let invalid_cpu = sleep_machine_state(&invalid_emu);
        let error = dispatch(&mut invalid_env, &mut invalid_emu, "VirtualAlloc").unwrap_err();
        assert!(matches!(
            error,
            EmuError::ReadMem { addr, size: 8, .. } if addr == invalid_rsp
        ));
        assert_eq!(sleep_machine_state(&invalid_emu), invalid_cpu);
        assert_eq!(
            invalid_env.virtual_allocation_cursor,
            VIRTUAL_ALLOCATION_ARENA_BASE
        );
        assert!(invalid_env.virtual_allocations.is_empty());
        assert!(invalid_emu
            .read_mem(VIRTUAL_ALLOCATION_ARENA_BASE, 1)
            .is_err());

        let mut collision_emu = Emu::new().unwrap();
        let mut collision_env = Win64Env::new(IMAGE_BASE);
        collision_emu
            .map_zeroed_rw(VIRTUAL_ALLOCATION_ARENA_BASE, u64::from(PAGE_SIZE))
            .unwrap();
        collision_emu
            .write_mem(VIRTUAL_ALLOCATION_ARENA_BASE, &[0x5a; 16])
            .unwrap();
        let rsp = STACK_BASE + 0x400;
        prepare_virtual_alloc_call(
            &mut collision_emu,
            VirtualAllocArgs::observed(4),
            rsp,
            Some(0x1234_5678_9abc_def0),
        );
        let collision_cpu = sleep_machine_state(&collision_emu);
        let error = dispatch(&mut collision_env, &mut collision_emu, "VirtualAlloc").unwrap_err();
        assert!(matches!(
            error,
            EmuError::Map { addr, size, .. }
                if addr == VIRTUAL_ALLOCATION_ARENA_BASE
                    && size == u64::from(PAGE_SIZE)
        ));
        assert_eq!(sleep_machine_state(&collision_emu), collision_cpu);
        assert_eq!(
            collision_env.virtual_allocation_cursor,
            VIRTUAL_ALLOCATION_ARENA_BASE
        );
        assert!(collision_env.virtual_allocations.is_empty());
        assert_eq!(
            collision_emu
                .read_mem(VIRTUAL_ALLOCATION_ARENA_BASE, 16)
                .unwrap(),
            vec![0x5a; 16]
        );
    }

    #[test]
    fn virtual_free_releases_exact_live_allocation_without_cursor_reuse() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x400;
        let allocation = call_virtual_alloc(
            &mut env,
            &mut emu,
            VirtualAllocArgs::observed(u64::from(PAGE_SIZE) + 1),
            rsp,
            0x1000,
        );
        let cursor_after_allocation = env.virtual_allocation_cursor;
        emu.write_mem(allocation, &[0xa5; 16]).unwrap();

        assert_eq!(
            call_virtual_free(
                &mut env,
                &mut emu,
                allocation + 1,
                0xaaaa_bbbb_0000_0000 | u64::from(MEM_RELEASE),
            ),
            0
        );
        assert!(env.virtual_allocations.contains_key(&allocation));
        assert_eq!(emu.read_mem(allocation, 16).unwrap(), vec![0xa5; 16]);

        assert_eq!(
            call_virtual_free(
                &mut env,
                &mut emu,
                allocation,
                0xaaaa_bbbb_0000_0000 | u64::from(MEM_RELEASE),
            ),
            1
        );
        assert!(!env.virtual_allocations.contains_key(&allocation));
        assert_eq!(env.virtual_allocation_cursor, cursor_after_allocation);
        assert!(emu.read_mem(allocation, 1).is_err());
        assert!(emu.read_mem(allocation + u64::from(PAGE_SIZE), 1).is_err());
        assert_eq!(
            call_virtual_free(&mut env, &mut emu, allocation, u64::from(MEM_RELEASE)),
            0
        );

        let next = call_virtual_alloc(
            &mut env,
            &mut emu,
            VirtualAllocArgs::observed(4),
            rsp,
            0x2000,
        );
        assert_eq!(next, cursor_after_allocation);
        assert_ne!(next, allocation);
    }

    #[test]
    fn virtual_free_unmaps_allocation_after_virtual_protect_splits_permissions() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x408;
        let old_protection = STACK_BASE + 0x900;
        let allocation = call_virtual_alloc(
            &mut env,
            &mut emu,
            VirtualAllocArgs::observed(u64::from(PAGE_SIZE) * 2),
            STACK_BASE + 0x400,
            0x1000,
        );
        emu.write_mem(rsp, &0x2222_3333_4444_5555u64.to_le_bytes())
            .unwrap();
        emu.write_mem(old_protection, &[0xa5; 8]).unwrap();
        emu.write_reg(RegisterX86::RCX, allocation).unwrap();
        emu.write_reg(RegisterX86::RDX, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_reg(RegisterX86::R8, u64::from(PAGE_EXECUTE_READ))
            .unwrap();
        emu.write_reg(RegisterX86::R9, old_protection).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert!(matches!(
            dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
            ApiOutcome::Handled { ret: 1, .. }
        ));

        assert_eq!(
            call_virtual_free(&mut env, &mut emu, allocation, u64::from(MEM_RELEASE)),
            1
        );
        assert!(emu.read_mem(allocation, 1).is_err());
        assert!(emu.read_mem(allocation + u64::from(PAGE_SIZE), 1).is_err());
        assert!(!env.virtual_allocations.contains_key(&allocation));
    }

    #[test]
    fn virtual_free_rejects_unmodeled_shapes_before_return_or_state_access() {
        for (size, free_type) in [(1, MEM_RELEASE), (0, MEM_COMMIT), (0, MEM_RELEASE | 1)] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            env.virtual_allocations.insert(
                VIRTUAL_ALLOCATION_ARENA_BASE,
                VirtualAllocation {
                    requested_size: 4,
                    mapped_size: u64::from(PAGE_SIZE),
                    allocation_type: MEM_COMMIT,
                    protection: PAGE_READWRITE,
                },
            );
            let invalid_rsp = 0x0000_0000_dead_0000;
            prepare_virtual_free_call(
                &mut emu,
                VIRTUAL_ALLOCATION_ARENA_BASE,
                size,
                u64::from(free_type),
                invalid_rsp,
                None,
            );
            let initial_cpu = sleep_machine_state(&emu);
            let allocations_before = env.virtual_allocations.clone();

            assert_eq!(
                dispatch(&mut env, &mut emu, "VirtualFree").unwrap(),
                ApiOutcome::Unhandled {
                    name: "VirtualFree".to_owned()
                }
            );
            assert_eq!(sleep_machine_state(&emu), initial_cpu);
            assert_eq!(env.virtual_allocations, allocations_before);
        }
    }

    #[test]
    fn virtual_free_bad_return_preserves_live_mapping_metadata_and_control() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let allocation = call_virtual_alloc(
            &mut env,
            &mut emu,
            VirtualAllocArgs::observed(4),
            STACK_BASE + 0x400,
            0x1000,
        );
        emu.write_mem(allocation, &[0xa5; 16]).unwrap();
        let invalid_rsp = 0x0000_0000_dead_0000;
        let initial_rax = 0xaaaa_bbbb_cccc_dddd;
        let initial_rip = 0x1111_2222_3333_4444;
        prepare_virtual_free_call(
            &mut emu,
            allocation,
            0,
            u64::from(MEM_RELEASE),
            invalid_rsp,
            None,
        );
        emu.write_reg(RegisterX86::RAX, initial_rax).unwrap();
        emu.write_reg(RegisterX86::RIP, initial_rip).unwrap();

        assert!(dispatch(&mut env, &mut emu, "VirtualFree").is_err());
        assert!(env.virtual_allocations.contains_key(&allocation));
        assert_eq!(emu.read_mem(allocation, 16).unwrap(), vec![0xa5; 16]);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), initial_rax);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), initial_rip);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), invalid_rsp);
    }

    #[test]
    fn virtual_protect_null_committed_page_probe_fails_without_output_write() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let rsp = STACK_BASE + 0x408;
        let return_address = 0x1234_5678_9abc_def0u64;
        let old_protection = STACK_BASE + 0x900;
        let sentinel = 0xaaaa_bbbb_0000_0046u64.to_le_bytes();
        emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
        emu.write_mem(old_protection, &sentinel).unwrap();
        seed_sleep_machine_state(&mut emu, 0, rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_reg(RegisterX86::R8, 0xaaaa_bbbb_0000_0040)
            .unwrap();
        emu.write_reg(RegisterX86::R9, old_protection).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
            ApiOutcome::Handled {
                name: "VirtualProtect".to_owned(),
                ret: 0,
            }
        );
        assert_eq!(
            emu.read_mem(old_protection, sentinel.len()).unwrap(),
            sentinel
        );
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn virtual_protect_rejects_unsupported_protections_and_null_output_before_access() {
        for (protection, old_protection) in [(0x08, 0xdead_0000), (0x104, 0xdead_0000), (0x20, 0)] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let invalid_rsp = 0x0000_0000_dead_1000;
            seed_sleep_machine_state(&mut emu, 1, invalid_rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, u64::from(PAGE_SIZE))
                .unwrap();
            emu.write_reg(RegisterX86::R8, protection).unwrap();
            emu.write_reg(RegisterX86::R9, old_protection).unwrap();
            let machine_before = sleep_machine_state(&emu);

            assert_eq!(
                dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
                ApiOutcome::Unhandled {
                    name: "VirtualProtect".to_owned(),
                }
            );
            assert_eq!(sleep_machine_state(&emu), machine_before);
        }
    }

    #[test]
    fn virtual_protect_rejects_overlapping_old_protection_without_mutation() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let base = 0x0000_0000_0738_0000;
        let output = base + 8;
        let sentinel = [0xa5; 8];
        emu.map_zeroed_rw(base, u64::from(PAGE_SIZE)).unwrap();
        emu.write_mem(output, &sentinel).unwrap();
        let invalid_rsp = 0x0000_0000_dead_1000;
        seed_sleep_machine_state(&mut emu, base, invalid_rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_reg(RegisterX86::R8, u64::from(PAGE_READONLY))
            .unwrap();
        emu.write_reg(RegisterX86::R9, output).unwrap();
        let machine_before = sleep_machine_state(&emu);

        assert_eq!(
            dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
            ApiOutcome::Unhandled {
                name: "VirtualProtect".to_owned(),
            }
        );
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(emu.read_mem(output, sentinel.len()).unwrap(), sentinel);
        emu.write_mem(base, &[0x5a]).unwrap();
    }

    #[test]
    fn virtual_protect_changes_rounded_image_pages_and_reports_first_old_protection() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let base = 0x0000_0000_0740_0000;
        let rsp = STACK_BASE + 0x408;
        let old_protection = STACK_BASE + 0x900;
        let sentinel = [0xa5; 8];
        emu.map_code(base, &vec![0xc3; PAGE_SIZE as usize + 0x200])
            .unwrap();
        emu.write_mem(rsp, &0x1111_2222_3333_4444u64.to_le_bytes())
            .unwrap();
        emu.write_mem(old_protection, &sentinel).unwrap();
        seed_sleep_machine_state(&mut emu, base + 0x10, rsp, 0x5555_6666_7777_8888);
        emu.write_reg(RegisterX86::RDX, 0x1bf0).unwrap();
        emu.write_reg(
            RegisterX86::R8,
            0xaaaa_bbbb_0000_0000 | u64::from(PAGE_READWRITE),
        )
        .unwrap();
        emu.write_reg(RegisterX86::R9, old_protection).unwrap();

        assert_eq!(
            dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
            ApiOutcome::Handled {
                name: "VirtualProtect".to_owned(),
                ret: 1,
            }
        );
        assert_eq!(
            emu.read_mem(old_protection, sentinel.len()).unwrap(),
            [PAGE_EXECUTE_READ.to_le_bytes().as_slice(), &sentinel[4..]].concat()
        );
        emu.write_mem(base, &[0x90]).unwrap();
        emu.write_mem(base + u64::from(PAGE_SIZE), &[0x90]).unwrap();
        let report = emu.resume(base, 1).unwrap();
        assert!(matches!(
            report.stop_reason,
            StopReason::MemoryFault(crate::emu::MemFault {
                kind: FaultKind::FetchProt,
                address,
            }) if address == base
        ));

        emu.write_mem(rsp, &0x9999_aaaa_bbbb_ccccu64.to_le_bytes())
            .unwrap();
        emu.write_mem(old_protection, &sentinel).unwrap();
        emu.write_reg(RegisterX86::RCX, base).unwrap();
        emu.write_reg(RegisterX86::RDX, 0x1c00).unwrap();
        emu.write_reg(RegisterX86::R8, u64::from(PAGE_EXECUTE_READ))
            .unwrap();
        emu.write_reg(RegisterX86::R9, old_protection).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        assert!(matches!(
            dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
            ApiOutcome::Handled { ret: 1, .. }
        ));
        assert_eq!(
            emu.read_mem(old_protection, 4).unwrap(),
            PAGE_READWRITE.to_le_bytes()
        );
        assert!(matches!(
            emu.write_mem(base, &[0xcc]),
            Err(EmuError::WriteProt { .. })
        ));
        assert_eq!(
            emu.resume(base, 1).unwrap().stop_reason,
            StopReason::ReachedInstructionCap
        );
    }

    #[test]
    fn virtual_protect_unmapped_and_overflowing_ranges_fail_without_output_access() {
        for (address, size) in [(0x0000_0000_0750_0000, 0x1000), (u64::MAX - 7, 16)] {
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            let rsp = STACK_BASE + 0x408;
            let return_address = 0x1234_5678_9abc_def0u64;
            emu.write_mem(rsp, &return_address.to_le_bytes()).unwrap();
            seed_sleep_machine_state(&mut emu, address, rsp, 0x1111_2222_3333_4444);
            emu.write_reg(RegisterX86::RDX, size).unwrap();
            emu.write_reg(RegisterX86::R8, u64::from(PAGE_READWRITE))
                .unwrap();
            emu.write_reg(RegisterX86::R9, 0x0000_0000_dead_0000)
                .unwrap();

            assert!(matches!(
                dispatch(&mut env, &mut emu, "VirtualProtect").unwrap(),
                ApiOutcome::Handled { ret: 0, .. }
            ));
            assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), return_address);
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
        }
    }

    #[test]
    fn virtual_protect_failure_preflights_return_without_touching_output() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let protected_base = 0x0000_0000_0760_0000;
        emu.map_code(protected_base, &[0xc3]).unwrap();
        let old_protection = STACK_BASE + 0x900;
        let sentinel = [0x5a; 8];
        emu.write_mem(old_protection, &sentinel).unwrap();
        let invalid_rsp = 0x0000_0000_dead_1000;
        seed_sleep_machine_state(&mut emu, protected_base, invalid_rsp, 0x1111_2222_3333_4444);
        emu.write_reg(RegisterX86::RDX, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_reg(RegisterX86::R8, u64::from(PAGE_READWRITE))
            .unwrap();
        emu.write_reg(RegisterX86::R9, old_protection).unwrap();
        let machine_before = sleep_machine_state(&emu);

        assert!(matches!(
            dispatch(&mut env, &mut emu, "VirtualProtect"),
            Err(EmuError::ReadMem { addr, size: 8, .. }) if addr == invalid_rsp
        ));
        assert_eq!(sleep_machine_state(&emu), machine_before);
        assert_eq!(
            emu.read_mem(old_protection, sentinel.len()).unwrap(),
            sentinel
        );
        assert!(matches!(
            emu.write_mem(protected_base, &[0x90]),
            Err(EmuError::WriteProt { .. })
        ));
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
    fn rtl_free_heap_logically_frees_exact_live_allocations() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let allocation = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, 32);
        emu.write_mem(allocation, &[0xa5; 32]).unwrap();
        let cursor_after_allocation = env.heap_cursor;
        let rsp = STACK_BASE + 0x800;

        for (heap, flags, address) in [
            (process_heap + 1, 0, allocation),
            (process_heap, 0x2, allocation),
            (process_heap, 0, 0),
            (process_heap, 0, allocation + 1),
            (process_heap, 0, allocation + u64::from(PAGE_SIZE)),
        ] {
            assert_eq!(
                call_rtl_free_heap(
                    &mut env,
                    &mut emu,
                    heap,
                    flags,
                    address,
                    rsp,
                    0x1234_5678_9abc_def0,
                ),
                0
            );
            assert!(env.heap_allocations.contains_key(&allocation));
        }

        assert_eq!(
            call_rtl_free_heap(
                &mut env,
                &mut emu,
                process_heap,
                0xa5a5_5a5a_0000_0000 | u64::from(HEAP_NO_SERIALIZE),
                allocation,
                rsp,
                0x0fed_cba9_8765_4321,
            ),
            1
        );
        assert!(!env.heap_allocations.contains_key(&allocation));
        assert_eq!(env.heap_cursor, cursor_after_allocation);
        assert_eq!(emu.read_mem(allocation, 32).unwrap(), vec![0xa5; 32]);
        assert_eq!(
            call_rtl_free_heap(
                &mut env,
                &mut emu,
                process_heap,
                0,
                allocation,
                rsp,
                0x1357_2468_ace0_bdf1,
            ),
            0
        );
    }

    #[test]
    fn rtl_free_heap_invalid_return_frame_preserves_live_allocation() {
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let allocation = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, 16);
        let invalid_rsp = 0x0000_000d_0000_0000;
        emu.write_reg(RegisterX86::RCX, process_heap).unwrap();
        emu.write_reg(RegisterX86::RDX, 0).unwrap();
        emu.write_reg(RegisterX86::R8, allocation).unwrap();
        emu.write_reg(RegisterX86::RAX, 0xaaaa_bbbb_cccc_dddd)
            .unwrap();
        emu.write_reg(RegisterX86::RIP, 0x1111_2222_3333_4444)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, invalid_rsp).unwrap();

        assert!(dispatch(&mut env, &mut emu, "RtlFreeHeap").is_err());
        assert!(env.heap_allocations.contains_key(&allocation));
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            0xaaaa_bbbb_cccc_dddd
        );
        assert_eq!(
            emu.read_reg(RegisterX86::RIP).unwrap(),
            0x1111_2222_3333_4444
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), invalid_rsp);
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
    fn trap_dispatches_close_handle_via_kernel32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("CloseHandle")
            .unwrap();
        let handle = KERNEL_HANDLE_BASE;
        env.insert_kernel_handle(
            handle,
            handle + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        emu.write_reg(RegisterX86::RCX, handle).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["CloseHandle".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert!(!env.kernel_handles.contains_key(&handle));
    }

    #[test]
    fn trap_dispatches_is_bad_read_ptr_via_kernel32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("IsBadReadPtr")
            .unwrap();
        let pointer = STACK_BASE + 0x900;
        emu.write_mem(pointer, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        emu.write_reg(RegisterX86::RCX, pointer).unwrap();
        emu.write_reg(RegisterX86::RDX, 4).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["IsBadReadPtr".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), pointer);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), 4);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(
            emu.read_mem(pointer, 4).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn trap_dispatches_allocate_and_initialize_sid_via_advapi32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let advapi = env.ensure_loaded_module(&mut emu, "advapi32.dll").unwrap();
        let stub = env
            .export_stub_by_base(advapi, "AllocateAndInitializeSid")
            .unwrap();
        let authority_page = IMAGE_BASE + u64::from(DATA_RVA);
        let authority = authority_page + 0x100;
        emu.map_zeroed_rw(authority_page, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_mem(authority, &[0, 0, 0, 0, 0, 5]).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let output = STACK_BASE + 0x900;
        emu.write_mem(initial_rsp + 0x50, &output.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, authority).unwrap();
        emu.write_reg(RegisterX86::RDX, 2).unwrap();
        emu.write_reg(RegisterX86::R8, 0x20).unwrap();
        emu.write_reg(RegisterX86::R9, 0x220).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["AllocateAndInitializeSid".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        let sid = read_u64_le(&emu.read_mem(output, 8).unwrap());
        assert_eq!(sid, SID_ALLOCATION_ARENA_BASE);
        assert_eq!(
            emu.read_mem(sid, 16).unwrap(),
            vec![1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0]
        );
    }

    #[test]
    fn trap_dispatches_free_sid_via_advapi32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let advapi = env.ensure_loaded_module(&mut emu, "advapi32.dll").unwrap();
        let stub = env.export_stub_by_base(advapi, "FreeSid").unwrap();
        let sid = SID_ALLOCATION_ARENA_BASE;
        env.commit_sid_allocation(
            sid,
            sid + u64::from(PAGE_SIZE),
            SidAllocation {
                sid_size: 16,
                mapped_size: u64::from(PAGE_SIZE),
                sub_authority_count: 2,
            },
        );
        emu.write_reg(RegisterX86::RCX, sid).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["FreeSid".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert!(!env.sid_allocations.contains_key(&sid));
    }

    #[test]
    fn trap_dispatches_reg_open_key_a_via_advapi32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let advapi = env.ensure_loaded_module(&mut emu, "advapi32.dll").unwrap();
        let stub = env
            .export_stub_by_base(advapi, "RegOpenKeyA")
            .expect("RegOpenKeyA seed");
        let subkey = STACK_BASE + 0x900;
        let output = STACK_BASE + 0xa00;
        let output_before = [0xa5; 16];
        emu.write_mem(subkey, b"SOFTWARE\\Midas\0").unwrap();
        emu.write_mem(output, &output_before).unwrap();
        emu.write_reg(RegisterX86::RCX, HKEY_LOCAL_MACHINE).unwrap();
        emu.write_reg(RegisterX86::RDX, subkey).unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["RegOpenKeyA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            u64::from(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(emu.read_reg(RegisterX86::RCX).unwrap(), HKEY_LOCAL_MACHINE);
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), subkey);
        assert_eq!(emu.read_reg(RegisterX86::R8).unwrap(), output);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(emu.read_mem(output, 16).unwrap(), output_before);
    }

    #[test]
    fn trap_dispatches_current_pseudo_handles_via_export_stubs() {
        for (name, expected) in [
            ("GetCurrentProcess", CURRENT_PROCESS_PSEUDO_HANDLE),
            ("GetCurrentThread", CURRENT_THREAD_PSEUDO_HANDLE),
        ] {
            let image = test_image();
            let mut emu = Emu::new().unwrap();
            let mut env = Win64Env::new(IMAGE_BASE);
            env.ensure_kernel32(&mut emu).unwrap();
            let stub = env
                .synthetic_modules
                .get("kernel32.dll")
                .unwrap()
                .export_stub(name)
                .unwrap();
            let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

            let mut code = vec![0x48, 0xb8]; // mov rax, stub
            code.extend_from_slice(&stub.to_le_bytes());
            code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]); // call rax; jmp $
            emu.map_code(image.entry_point_va(), &code).unwrap();

            let result =
                run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                    .unwrap();

            assert_eq!(result.handled, vec![name.to_owned()]);
            assert_eq!(result.stop, TrapStop::InstructionCap);
            assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), expected);
            assert_eq!(
                emu.read_reg(RegisterX86::RIP).unwrap(),
                image.entry_point_va() + 12
            );
            assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        }
    }

    #[test]
    fn trap_dispatches_get_thread_context_via_kernel32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("GetThreadContext")
            .unwrap();
        let context = STACK_BASE + 0x800;
        emu.write_mem(
            context + AMD64_CONTEXT_FLAGS_OFFSET as u64,
            &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
        )
        .unwrap();
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS {
            emu.write_mem(
                context + offset as u64,
                &0xfeed_face_cafe_beef_u64.to_le_bytes(),
            )
            .unwrap();
        }
        emu.write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(RegisterX86::RDX, context).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["GetThreadContext".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(
            read_u32_at(&emu, context + AMD64_CONTEXT_FLAGS_OFFSET as u64).unwrap(),
            CONTEXT_AMD64_DEBUG_REGISTERS
        );
        for &offset in &AMD64_CONTEXT_DEBUG_REGISTER_OFFSETS {
            assert_eq!(read_u64_at(&emu, context + offset as u64).unwrap(), 0);
        }
    }

    #[test]
    fn trap_dispatches_debugger_query_and_thread_token_boundaries() {
        let image = test_image();

        let mut debugger_emu = Emu::new().unwrap();
        let mut debugger_env = Win64Env::new(IMAGE_BASE);
        let kernel32 = debugger_env.ensure_kernel32(&mut debugger_emu).unwrap();
        let debugger_stub = debugger_env
            .export_stub_by_base(kernel32, "CheckRemoteDebuggerPresent")
            .unwrap();
        let debugger_output = crate::emu::STACK_BASE + 0x700;
        debugger_emu.write_mem(debugger_output, &[0xaa; 4]).unwrap();
        debugger_emu
            .write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        debugger_emu
            .write_reg(RegisterX86::RDX, debugger_output)
            .unwrap();
        let mut debugger_code = vec![0x48, 0xb8];
        debugger_code.extend_from_slice(&debugger_stub.to_le_bytes());
        debugger_code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        debugger_emu
            .map_code(image.entry_point_va(), &debugger_code)
            .unwrap();
        let debugger = run_with_import_trap(
            &mut debugger_env,
            &mut debugger_emu,
            &image,
            image.entry_point_va(),
            64,
            8,
        )
        .unwrap();
        assert_eq!(
            debugger.handled,
            vec!["CheckRemoteDebuggerPresent".to_owned()]
        );
        assert_eq!(debugger.stop, TrapStop::InstructionCap);
        assert_eq!(
            debugger_emu.read_mem(debugger_output, 4).unwrap(),
            vec![0; 4]
        );
        assert_eq!(debugger_emu.read_reg(RegisterX86::RAX).unwrap(), 1);

        let mut token_emu = Emu::new().unwrap();
        let mut token_env = Win64Env::new(IMAGE_BASE);
        let advapi = token_env
            .ensure_loaded_module(&mut token_emu, "advapi32.dll")
            .unwrap();
        let token_stub = token_env
            .export_stub_by_base(advapi, "OpenThreadToken")
            .unwrap();
        token_emu
            .write_reg(RegisterX86::RCX, CURRENT_THREAD_PSEUDO_HANDLE)
            .unwrap();
        token_emu
            .write_reg(RegisterX86::RDX, u64::from(TOKEN_QUERY))
            .unwrap();
        token_emu.write_reg(RegisterX86::R8, 1).unwrap();
        token_emu
            .write_reg(RegisterX86::R9, 0x0000_0000_dead_1000)
            .unwrap();
        let mut token_code = vec![0x48, 0xb8];
        token_code.extend_from_slice(&token_stub.to_le_bytes());
        token_code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        token_emu
            .map_code(image.entry_point_va(), &token_code)
            .unwrap();
        let token = run_with_import_trap(
            &mut token_env,
            &mut token_emu,
            &image,
            image.entry_point_va(),
            64,
            8,
        )
        .unwrap();
        assert_eq!(token.handled, vec!["OpenThreadToken".to_owned()]);
        assert_eq!(token.stop, TrapStop::InstructionCap);
        assert_eq!(token_emu.read_reg(RegisterX86::RAX).unwrap(), 0);

        let mut process_token_emu = Emu::new().unwrap();
        let mut process_token_env = Win64Env::new(IMAGE_BASE);
        let advapi = process_token_env
            .ensure_loaded_module(&mut process_token_emu, "advapi32.dll")
            .unwrap();
        let process_token_stub = process_token_env
            .export_stub_by_base(advapi, "OpenProcessToken")
            .unwrap();
        let process_token_output = crate::emu::STACK_BASE + 0x700;
        process_token_emu
            .write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        process_token_emu
            .write_reg(RegisterX86::RDX, u64::from(TOKEN_QUERY))
            .unwrap();
        process_token_emu
            .write_reg(RegisterX86::R8, process_token_output)
            .unwrap();
        let mut process_token_code = vec![0x48, 0xb8];
        process_token_code.extend_from_slice(&process_token_stub.to_le_bytes());
        process_token_code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        process_token_emu
            .map_code(image.entry_point_va(), &process_token_code)
            .unwrap();
        let process_token = run_with_import_trap(
            &mut process_token_env,
            &mut process_token_emu,
            &image,
            image.entry_point_va(),
            64,
            8,
        )
        .unwrap();
        assert_eq!(process_token.handled, vec!["OpenProcessToken".to_owned()]);
        assert_eq!(process_token.stop, TrapStop::InstructionCap);
        assert_eq!(process_token_emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(
            read_u64_le(&process_token_emu.read_mem(process_token_output, 8).unwrap()),
            KERNEL_HANDLE_BASE
        );

        let mut information_emu = Emu::new().unwrap();
        let mut information_env = Win64Env::new(IMAGE_BASE);
        let advapi = information_env
            .ensure_loaded_module(&mut information_emu, "advapi32.dll")
            .unwrap();
        let information_stub = information_env
            .export_stub_by_base(advapi, "GetTokenInformation")
            .unwrap();
        information_env.insert_kernel_handle(
            KERNEL_HANDLE_BASE,
            KERNEL_HANDLE_BASE + KERNEL_HANDLE_STRIDE,
            KernelHandle {
                object: KernelObject::ProcessToken,
                desired_access: TOKEN_QUERY,
                inheritable: false,
            },
        );
        let initial_rsp = information_emu.read_reg(RegisterX86::RSP).unwrap();
        let information_length = crate::emu::STACK_BASE + 0x700;
        information_emu
            .write_mem(initial_rsp + 0x20, &information_length.to_le_bytes())
            .unwrap();
        information_emu
            .write_reg(RegisterX86::RCX, KERNEL_HANDLE_BASE)
            .unwrap();
        information_emu
            .write_reg(RegisterX86::RDX, TOKEN_INFORMATION_CLASS_GROUPS.into())
            .unwrap();
        information_emu.write_reg(RegisterX86::R8, 0).unwrap();
        information_emu.write_reg(RegisterX86::R9, 0).unwrap();
        let mut information_code = vec![0x48, 0xb8];
        information_code.extend_from_slice(&information_stub.to_le_bytes());
        information_code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        information_emu
            .map_code(image.entry_point_va(), &information_code)
            .unwrap();
        let information = run_with_import_trap(
            &mut information_env,
            &mut information_emu,
            &image,
            image.entry_point_va(),
            64,
            8,
        )
        .unwrap();
        assert_eq!(information.handled, vec!["GetTokenInformation".to_owned()]);
        assert_eq!(information.stop, TrapStop::InstructionCap);
        assert_eq!(
            information_emu.read_mem(information_length, 4).unwrap(),
            EMPTY_TOKEN_GROUPS_SIZE.to_le_bytes()
        );
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
    fn synthetic_user32_export_traps_create_window_ex_a() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let user32 = env.ensure_loaded_module(&mut emu, "user32.dll").unwrap();
        let stub = env
            .export_stub_by_base(user32, "CreateWindowExA")
            .expect("CreateWindowExA seed");
        emu.map_code(image.entry_point_va(), &[0xeb, 0xfe]).unwrap();
        register_test_window_class(&mut env, &mut emu, STACK_BASE + 0x300);
        let rsp = STACK_BASE + 0x700;
        prepare_create_window_ex_a_call(
            &mut emu,
            CreateWindowExAArgs::observed(WINDOW_CLASS_NAME_ADDRESS),
            rsp,
            Some(image.entry_point_va()),
        );

        let result = run_with_import_trap(&mut env, &mut emu, &image, stub, 32, 8).unwrap();

        assert_eq!(result.handled, vec!["CreateWindowExA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            EMULATED_WINDOW_HANDLE
        );
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
    }

    #[test]
    fn synthetic_user32_send_message_a_remains_a_names_only_boundary() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let user32 = env.ensure_loaded_module(&mut emu, "user32.dll").unwrap();
        let module = env.synthetic_modules.get("user32.dll").unwrap();
        let rva = *module.exports.get("SendMessageA").unwrap();
        let stub = user32 + u64::from(rva);
        assert_eq!(
            env.callable_stub_name_at(stub).as_deref(),
            Some("SendMessageA")
        );

        let result = run_with_import_trap(&mut env, &mut emu, &image, stub, 32, 8).unwrap();

        assert!(result.handled.is_empty());
        assert_eq!(
            result.stop,
            TrapStop::UnhandledApi {
                name: "SendMessageA".to_owned(),
                rva,
            }
        );
    }

    #[test]
    fn synthetic_kernel32_export_traps_get_command_line_a() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32 = env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .export_stub_by_base(kernel32, "GetCommandLineA")
            .expect("GetCommandLineA seed");
        emu.map_code(image.entry_point_va(), &[0xeb, 0xfe]).unwrap();
        let rsp = STACK_BASE + 0x400;
        emu.write_mem(rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let result = run_with_import_trap(&mut env, &mut emu, &image, stub, 32, 8).unwrap();

        assert_eq!(result.handled, vec!["GetCommandLineA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(
            emu.read_reg(RegisterX86::RAX).unwrap(),
            EMULATED_COMMAND_LINE_A_BASE
        );
        assert_eq!(
            emu.read_mem(EMULATED_COMMAND_LINE_A_BASE, EMULATED_COMMAND_LINE_A.len())
                .unwrap(),
            EMULATED_COMMAND_LINE_A
        );
    }

    #[test]
    fn synthetic_ntdll_export_traps_rtl_free_heap() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let process_heap = env.process_heap;
        let allocation = call_rtl_allocate_heap(&mut env, &mut emu, process_heap, 0, 16);
        let ntdll = env.ensure_loaded_module(&mut emu, "ntdll.dll").unwrap();
        let stub = env
            .export_stub_by_base(ntdll, "RtlFreeHeap")
            .expect("RtlFreeHeap seed");
        emu.map_code(image.entry_point_va(), &[0xeb, 0xfe]).unwrap();
        let rsp = STACK_BASE + 0x800;
        emu.write_mem(rsp, &image.entry_point_va().to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, process_heap).unwrap();
        emu.write_reg(RegisterX86::RDX, 0).unwrap();
        emu.write_reg(RegisterX86::R8, allocation).unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();

        let result = run_with_import_trap(&mut env, &mut emu, &image, stub, 32, 8).unwrap();

        assert_eq!(result.handled, vec!["RtlFreeHeap".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert!(!env.heap_allocations.contains_key(&allocation));
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
            vec![
                "CreateWindowExA",
                "FindWindowA",
                "LoadCursorA",
                "RegisterClassExA",
                "SendMessageA"
            ]
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
    fn synthetic_user32_export_traps_find_window_a() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let user32_base = env.ensure_loaded_module(&mut emu, "user32.dll").unwrap();
        let stub = env
            .export_stub_by_base(user32_base, "FindWindowA")
            .expect("FindWindowA seed");
        assert_eq!(
            env.callable_stub_name_at(stub).as_deref(),
            Some("FindWindowA")
        );
        assert_eq!(
            env.resolve_proc(&mut emu, user32_base, "FindWindowA")
                .unwrap(),
            stub
        );
        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"GeneralClass\0")
            .unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]); // sub rsp,20h
        code.extend_from_slice(&[0x48, 0xb9]); // mov rcx,selector
        code.extend_from_slice(&WINDOW_CLASS_NAME_ADDRESS.to_le_bytes());
        code.extend_from_slice(&[0x31, 0xd2]); // xor edx,edx
        code.extend_from_slice(&[0x49, 0xbb]); // mov r11,stub
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xff, 0xd3]); // call r11
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]); // add rsp,20h
        code.extend_from_slice(&[0xeb, 0xfe]); // jmp $
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["FindWindowA".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RCX).unwrap(),
            WINDOW_CLASS_NAME_ADDRESS
        );
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn synthetic_kernel32_export_traps_wide_char_to_multi_byte_size_query() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let kernel32_base = env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("WideCharToMultiByte")
            .unwrap();
        assert_eq!(
            env.callable_stub_name_at(stub).as_deref(),
            Some("WideCharToMultiByte")
        );
        assert_eq!(
            env.resolve_proc(&mut emu, kernel32_base, "WideCharToMultiByte")
                .unwrap(),
            stub
        );

        let loop_address = image.entry_point_va();
        emu.map_code(loop_address, &[0xeb, 0xfe]).unwrap();
        let rsp = crate::emu::STACK_BASE + 0x400;
        let wide = "guest.exe\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        emu.write_mem(WIDE_STRING_ADDRESS, &wide).unwrap();
        prepare_wide_char_to_multi_byte_call(
            &mut emu,
            WideCharToMultiByteArgs::observed(WIDE_STRING_ADDRESS),
            rsp,
            Some(loop_address),
        );

        let result = run_with_import_trap(&mut env, &mut emu, &image, stub, 32, 8).unwrap();

        assert_eq!(result.handled, vec!["WideCharToMultiByte".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 10);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), rsp + 8);
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
        assert_eq!(
            env.registered_window_procedures().collect::<Vec<_>>(),
            vec![(WINDOW_CLASS_ATOM_BASE as u16, args.window_procedure)]
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
    fn trap_dispatches_zw_query_information_process_via_ntdll_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let ntdll = env.ensure_loaded_module(&mut emu, "ntdll.dll").unwrap();
        let stub = env
            .export_stub_by_base(ntdll, "ZwQueryInformationProcess")
            .unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let output = STACK_BASE + 0x900;
        emu.write_mem(initial_rsp + 0x20, &0u64.to_le_bytes())
            .unwrap();
        emu.write_mem(output, &[0xaa; 16]).unwrap();
        emu.write_reg(RegisterX86::RCX, CURRENT_PROCESS_PSEUDO_HANDLE)
            .unwrap();
        emu.write_reg(
            RegisterX86::RDX,
            PROCESS_INFORMATION_CLASS_DEBUG_PORT.into(),
        )
        .unwrap();
        emu.write_reg(RegisterX86::R8, output).unwrap();
        emu.write_reg(RegisterX86::R9, 8).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["ZwQueryInformationProcess".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(&emu.read_mem(output, 16).unwrap()[..8], &[0; 8]);
        assert_eq!(&emu.read_mem(output, 16).unwrap()[8..], &[0xaa; 8]);
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
                first: 1,
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
        let module = SyntheticModule::build(
            FAKE_MODULE_BASE_START,
            "kernel32.dll",
            KERNEL32_EXPORTS.as_slice(),
        );
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
        let module = SyntheticModule::build(
            FAKE_MODULE_BASE_START,
            "kernel32.dll",
            KERNEL32_EXPORTS.as_slice(),
        );
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
        data[..b"MidasDynamicProcedureForTest\0".len()]
            .copy_from_slice(b"MidasDynamicProcedureForTest\0");
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
    fn trap_dispatches_virtual_alloc_via_kernel32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_module(&mut emu, "kernel32.dll", KERNEL32_EXPORTS.as_slice())
            .unwrap();
        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let virtual_alloc_rva = *module.exports.get("VirtualAlloc").unwrap();
        let virtual_alloc_addr = module.base + u64::from(virtual_alloc_rva);
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        let mut code = Vec::new();
        code.extend_from_slice(&[0x31, 0xc9]); // xor ecx,ecx
        code.push(0xba); // mov edx,4
        code.extend_from_slice(&4u32.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xb8]); // mov r8d,MEM_COMMIT
        code.extend_from_slice(&MEM_COMMIT.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xb9]); // mov r9d,PAGE_READWRITE
        code.extend_from_slice(&PAGE_READWRITE.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&virtual_alloc_addr.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        code.extend_from_slice(&[0xc7, 0x00, 0x11, 0x22, 0x33, 0x44]);
        code.extend_from_slice(&[0xeb, 0xfe]);
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;

        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["VirtualAlloc".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        let allocation = emu.read_reg(RegisterX86::RAX).unwrap();
        assert_eq!(allocation, VIRTUAL_ALLOCATION_ARENA_BASE);
        assert_eq!(
            env.virtual_allocations.get(&allocation),
            Some(&VirtualAllocation {
                requested_size: 4,
                mapped_size: u64::from(PAGE_SIZE),
                allocation_type: MEM_COMMIT,
                protection: PAGE_READWRITE,
            })
        );
        assert_eq!(
            emu.read_mem(allocation, 8).unwrap(),
            vec![0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0]
        );
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
    }

    #[test]
    fn trap_dispatches_virtual_free_via_kernel32_export_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_kernel32(&mut emu).unwrap();
        let stub = env
            .synthetic_modules
            .get("kernel32.dll")
            .unwrap()
            .export_stub("VirtualFree")
            .unwrap();
        let allocation = VIRTUAL_ALLOCATION_ARENA_BASE;
        emu.map_zeroed_rw(allocation, u64::from(PAGE_SIZE)).unwrap();
        env.virtual_allocations.insert(
            allocation,
            VirtualAllocation {
                requested_size: 4,
                mapped_size: u64::from(PAGE_SIZE),
                allocation_type: MEM_COMMIT,
                protection: PAGE_READWRITE,
            },
        );
        env.virtual_allocation_cursor = allocation + VIRTUAL_ALLOCATION_GRANULARITY;
        emu.write_reg(RegisterX86::RCX, allocation).unwrap();
        emu.write_reg(RegisterX86::RDX, 0).unwrap();
        emu.write_reg(RegisterX86::R8, u64::from(MEM_RELEASE))
            .unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["VirtualFree".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 1);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert!(!env.virtual_allocations.contains_key(&allocation));
        assert!(emu.read_mem(allocation, 1).is_err());
    }

    #[test]
    fn trap_reports_other_unhandled_kernel32_export_call_by_name() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        env.ensure_module(&mut emu, "kernel32.dll", KERNEL32_EXPORTS.as_slice())
            .unwrap();
        let module = env.synthetic_modules.get("kernel32.dll").unwrap();
        let virtual_protect_rva = *module.exports.get("VirtualProtect").unwrap();
        let virtual_protect_addr = module.base + u64::from(virtual_protect_rva);

        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&virtual_protect_addr.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert!(result.handled.is_empty());
        assert_eq!(
            result.stop,
            TrapStop::UnhandledApi {
                name: "VirtualProtect".to_owned(),
                rva: virtual_protect_rva
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
        let module =
            SyntheticModule::build(kernel32_base, "kernel32.dll", KERNEL32_EXPORTS.as_slice());
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
    fn trap_dispatches_is_user_an_admin_resolved_from_loaded_shell32() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let shell32 = env.ensure_loaded_module(&mut emu, "shell32.dll").unwrap();
        let name_address = IMAGE_BASE + u64::from(DATA_RVA);
        emu.map_code(name_address, b"IsUserAnAdmin\0").unwrap();
        let get_proc_rsp = STACK_BASE + 0x500;
        emu.write_mem(get_proc_rsp, &0x1234_5678_9abc_def0u64.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, shell32).unwrap();
        emu.write_reg(RegisterX86::RDX, name_address).unwrap();
        emu.write_reg(RegisterX86::RSP, get_proc_rsp).unwrap();
        let outcome = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        let ApiOutcome::Handled { ret: stub, .. } = outcome else {
            panic!("expected GetProcAddress to resolve IsUserAnAdmin");
        };
        assert_ne!(stub, 0);
        assert_eq!(env.proc_stubs.get("IsUserAnAdmin"), Some(&stub));

        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]);
        emu.map_code(image.entry_point_va(), &code).unwrap();
        let run_rsp = STACK_BASE + 0x808;
        emu.write_reg(RegisterX86::RSP, run_rsp).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 64, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["IsUserAnAdmin".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), run_rsp);
    }

    #[test]
    fn trap_dispatches_dynamic_nt_query_system_information_stub() {
        let image = test_image();
        let mut emu = Emu::new().unwrap();
        let mut env = Win64Env::new(IMAGE_BASE);
        let ntdll = env.ensure_loaded_module(&mut emu, "ntdll.dll").unwrap();
        assert!(!NTDLL_EXPORTS.contains(&"NtQuerySystemInformation"));
        assert!(env
            .synthetic_modules
            .get("ntdll.dll")
            .unwrap()
            .export_stub("NtQuerySystemInformation")
            .is_none());

        emu.write_mem(WINDOW_CLASS_NAME_ADDRESS, b"NtQuerySystemInformation\0")
            .unwrap();
        let lookup_rsp = STACK_BASE + 0x500;
        emu.write_mem(lookup_rsp, &0x1234_5678_9abc_def0_u64.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RCX, ntdll).unwrap();
        emu.write_reg(RegisterX86::RDX, WINDOW_CLASS_NAME_ADDRESS)
            .unwrap();
        emu.write_reg(RegisterX86::RSP, lookup_rsp).unwrap();
        let lookup = dispatch(&mut env, &mut emu, "GetProcAddress").unwrap();
        let ApiOutcome::Handled { ret: stub, .. } = lookup else {
            panic!("expected GetProcAddress to resolve dynamic stub");
        };
        assert_eq!(env.proc_stubs.get("NtQuerySystemInformation"), Some(&stub));
        assert!(env.stub_export_at(stub).is_none());
        assert_eq!(
            env.proc_stub_at(stub).map(|(name, _)| name),
            Some("NtQuerySystemInformation".to_owned())
        );

        let information = VIRTUAL_ALLOCATION_ARENA_BASE;
        emu.map_zeroed_rw(information, u64::from(PAGE_SIZE))
            .unwrap();
        emu.write_mem(information, &[0xa5; 8]).unwrap();
        let initial_rsp = STACK_BASE + 0x808;
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]); // mov rcx,class
        code.extend_from_slice(&0xaaaa_bbbb_0000_000b_u64.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xba]); // mov rdx,buffer
        code.extend_from_slice(&information.to_le_bytes());
        code.extend_from_slice(&[0x49, 0xb8]); // mov r8,length
        code.extend_from_slice(&0xcccc_dddd_0001_0000_u64.to_le_bytes());
        code.extend_from_slice(&[0x45, 0x31, 0xc9]); // xor r9d,r9d
        code.extend_from_slice(&[0x48, 0xb8]); // mov rax,stub
        code.extend_from_slice(&stub.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0xeb, 0xfe]); // call rax; jmp $
        let loop_address = image.entry_point_va() + code.len() as u64 - 2;
        emu.map_code(image.entry_point_va(), &code).unwrap();
        emu.write_reg(RegisterX86::RSP, initial_rsp).unwrap();

        let result =
            run_with_import_trap(&mut env, &mut emu, &image, image.entry_point_va(), 128, 8)
                .unwrap();

        assert_eq!(result.handled, vec!["NtQuerySystemInformation".to_owned()]);
        assert_eq!(result.stop, TrapStop::InstructionCap);
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0);
        assert_eq!(
            emu.read_reg(RegisterX86::RCX).unwrap(),
            0xaaaa_bbbb_0000_000b
        );
        assert_eq!(emu.read_reg(RegisterX86::RDX).unwrap(), information);
        assert_eq!(
            emu.read_reg(RegisterX86::R8).unwrap(),
            0xcccc_dddd_0001_0000
        );
        assert_eq!(emu.read_reg(RegisterX86::R9).unwrap(), 0);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), loop_address);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(
            emu.read_mem(information, 8).unwrap(),
            vec![0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]
        );
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
