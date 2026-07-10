//! Minimal Win64 import-call trap and API stubs.

use std::collections::BTreeMap;

use crate::{
    emu::{Emu, EmuError, FaultKind, RegisterX86, StopReason},
    pe,
};

const IMPORT_NAME_CAP: usize = 256;
const FAKE_MODULE_BASE_START: u64 = 0x0000_7fff_0000_0000;
const FAKE_MODULE_BASE_STEP: u64 = 0x0010_0000;
const PROC_STUB_BASE: u64 = 0x0000_7ffe_0000_0000;
const PROC_STUB_STRIDE: u64 = 16;
const PAGE_SIZE: u32 = 0x1000;

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
    "GetModuleHandleA",
    "GetModuleHandleW",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "ExitProcess",
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

#[derive(Debug, Clone)]
pub struct Win64Env {
    image_base: u64,
    modules: BTreeMap<String, u64>,
    next_base: u64,
    synthetic_modules: BTreeMap<String, SyntheticModule>,
    proc_stubs: BTreeMap<String, u64>,
    proc_stub_mapped_end: u64,
}

impl Win64Env {
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            modules: BTreeMap::new(),
            next_base: FAKE_MODULE_BASE_START,
            synthetic_modules: BTreeMap::new(),
            proc_stubs: BTreeMap::new(),
            proc_stub_mapped_end: PROC_STUB_BASE,
        }
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
        let exports = if module_name.eq_ignore_ascii_case("kernel32.dll") {
            KERNEL32_EXPORTS
        } else if module_name.eq_ignore_ascii_case("ntdll.dll") {
            NTDLL_EXPORTS
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
    Unhandled { name: String },
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

fn read_arg_ascii_z(emu: &Emu, reg: RegisterX86) -> Result<String, EmuError> {
    let address = emu.read_reg(reg)?;
    read_ascii_z_at(emu, address)
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
                        ApiOutcome::Handled { name, .. } => {
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
                    ApiOutcome::Handled { name, .. } => {
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
