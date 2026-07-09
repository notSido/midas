//! Minimal Win64 import-call trap and API stubs.

use std::collections::BTreeMap;

use crate::{
    emu::{Emu, EmuError, FaultKind, RegisterX86, StopReason},
    pe,
};

const IMPORT_NAME_CAP: usize = 256;
const FAKE_MODULE_BASE_START: u64 = 0x0000_7fff_0000_0000;
const FAKE_MODULE_BASE_STEP: u64 = 0x0010_0000;
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
    kernel32: Option<SyntheticModule>,
}

impl Win64Env {
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            modules: BTreeMap::new(),
            next_base: FAKE_MODULE_BASE_START,
            kernel32: None,
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

    fn ensure_kernel32(&mut self, emu: &mut Emu) -> Result<u64, EmuError> {
        if let Some(kernel32) = &self.kernel32 {
            return Ok(kernel32.base);
        }

        let base = self.module_base("kernel32.dll");
        let kernel32 = SyntheticModule::build(base, "kernel32.dll", KERNEL32_EXPORTS);
        kernel32.map_into(emu)?;
        self.kernel32 = Some(kernel32);
        Ok(base)
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
            let base = if module_name.is_empty() {
                env.image_base
            } else if module_name.eq_ignore_ascii_case("kernel32.dll") {
                env.ensure_kernel32(emu)?
            } else {
                0
            };
            emu.write_reg(RegisterX86::RAX, base)?;
            api_return(emu)?;
            Ok(ApiOutcome::Handled {
                name: name.to_owned(),
                ret: base,
            })
        }
        _ => Ok(ApiOutcome::Unhandled {
            name: name.to_owned(),
        }),
    }
}

fn read_arg_ascii_z(emu: &Emu, reg: RegisterX86) -> Result<String, EmuError> {
    let address = emu.read_reg(reg)?;
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
                if let Some((name, rva)) = env.kernel32.as_ref().and_then(|kernel32| {
                    let name = kernel32.stub_name(fault.address)?.to_owned();
                    let rva = u32::try_from(fault.address.checked_sub(kernel32.base)?).ok()?;
                    Some((name, rva))
                }) {
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
        let module =
            SyntheticModule::build(FAKE_MODULE_BASE_START, "kernel32.dll", KERNEL32_EXPORTS);
        let virtual_alloc_rva = *module.exports.get("VirtualAlloc").unwrap();
        let virtual_alloc_addr = module.base + u64::from(virtual_alloc_rva);
        module.map_into(&mut emu).unwrap();
        env.kernel32 = Some(module);

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
}
