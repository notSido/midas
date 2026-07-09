//! Minimal Unicorn-backed x86-64 emulation harness.

use std::collections::VecDeque;

use crate::pe;

pub use unicorn_engine::RegisterX86;

use thiserror::Error;
use unicorn_engine::{
    uc_error,
    unicorn_const::{Arch, HookType, MemType, Mode, Prot},
    Unicorn,
};

const PAGE_SIZE: u64 = 0x1000;
const RECENT_RIPS_CAP: usize = 64;
const REGISTER_SNAPSHOT_ORDER: [RegisterX86; 18] = [
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

/// Base address of the default emulated stack mapping.
pub const STACK_BASE: u64 = 0x0000_000f_fff0_0000;

/// Size, in bytes, of the default emulated stack mapping.
pub const STACK_SIZE: u64 = 0x0010_0000;

/// Base address of the default x64 Thread Environment Block mapping.
pub const TEB_BASE: u64 = 0x0000_000f_1000_0000;

/// Size, in bytes, of the default x64 Thread Environment Block mapping.
pub const TEB_SIZE: u64 = PAGE_SIZE;

/// Base address of the default x64 Process Environment Block mapping.
pub const PEB_BASE: u64 = 0x0000_000f_2000_0000;

/// Size, in bytes, of the default x64 Process Environment Block mapping.
pub const PEB_SIZE: u64 = PAGE_SIZE;

#[derive(Debug, Error)]
pub enum EmuError {
    #[error("failed to initialize Unicorn: {0}")]
    Init(#[source] uc_error),

    #[error("failed to map memory at 0x{addr:016x} ({size:#x} bytes): {source}")]
    Map {
        addr: u64,
        size: u64,
        #[source]
        source: uc_error,
    },

    #[error("failed to write memory at 0x{addr:016x} ({size:#x} bytes): {source}")]
    WriteMem {
        addr: u64,
        size: usize,
        #[source]
        source: uc_error,
    },

    #[error("failed to read memory at 0x{addr:016x} ({size:#x} bytes): {source}")]
    ReadMem {
        addr: u64,
        size: usize,
        #[source]
        source: uc_error,
    },

    #[error("failed to write register {reg:?}: {source}")]
    WriteReg {
        reg: RegisterX86,
        #[source]
        source: uc_error,
    },

    #[error("failed to read register {reg:?}: {source}")]
    ReadReg {
        reg: RegisterX86,
        #[source]
        source: uc_error,
    },

    #[error(
        "failed to start emulation at 0x{begin:016x} until 0x{until:016x} with count {count}: {source}"
    )]
    Start {
        begin: u64,
        until: u64,
        count: usize,
        #[source]
        source: uc_error,
    },

    #[error("failed to install code trace hook: {0}")]
    Hook(#[source] uc_error),

    #[error("instruction cap {count} is too large for Unicorn's count parameter")]
    InstructionCapTooLarge { count: u64 },

    #[error("address range overflows: base 0x{base:016x}, size {size:#x}")]
    AddressRangeOverflow { base: u64, size: u64 },

    #[error("code buffer is too large to map")]
    CodeTooLarge,

    #[error(
        "section raw data points outside the file: offset {offset:#x}, size {size:#x}, file size {file_size:#x}"
    )]
    SectionOutOfFile {
        offset: u32,
        size: u32,
        file_size: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    ReadUnmapped,
    WriteUnmapped,
    FetchUnmapped,
    ReadProt,
    WriteProt,
    FetchProt,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemFault {
    pub kind: FaultKind,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    ReachedInstructionCap,
    ReachedUntil,
    MemoryFault(MemFault),
    InvalidInstruction,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub stop_reason: StopReason,
    pub final_rip: u64,
    pub instructions_executed: u64,
    pub recent_rips: Vec<u64>,
    pub registers: Vec<(RegisterX86, u64)>,
}

#[derive(Default)]
struct EmuData {
    executed_addresses: Vec<u64>,
    recent_rips: VecDeque<u64>,
    instr_count: u64,
    last_fault: Option<MemFault>,
}

pub struct Emu {
    uc: Unicorn<'static, EmuData>,
}

impl Emu {
    pub fn new() -> Result<Self, EmuError> {
        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, EmuData::default())
            .map_err(EmuError::Init)?;

        map_region(&mut uc, STACK_BASE, STACK_SIZE, Prot::READ | Prot::WRITE)?;
        map_region(&mut uc, TEB_BASE, TEB_SIZE, Prot::READ | Prot::WRITE)?;
        map_region(&mut uc, PEB_BASE, PEB_SIZE, Prot::READ | Prot::WRITE)?;

        let stack_pointer = STACK_BASE + STACK_SIZE - PAGE_SIZE;
        uc.reg_write(RegisterX86::RSP, stack_pointer)
            .map_err(|source| EmuError::WriteReg {
                reg: RegisterX86::RSP,
                source,
            })?;

        uc.reg_write(RegisterX86::GS_BASE, TEB_BASE)
            .map_err(|source| EmuError::WriteReg {
                reg: RegisterX86::GS_BASE,
                source,
            })?;

        Ok(Self { uc })
    }

    pub fn map_code(&mut self, base: u64, bytes: &[u8]) -> Result<(), EmuError> {
        let len = u64::try_from(bytes.len()).map_err(|_| EmuError::CodeTooLarge)?;
        let size = align_up(len.max(1), PAGE_SIZE)?;
        base.checked_add(size)
            .ok_or(EmuError::AddressRangeOverflow { base, size })?;

        self.uc
            .mem_map(base, size, Prot::READ | Prot::EXEC)
            .map_err(|source| EmuError::Map {
                addr: base,
                size,
                source,
            })?;
        self.uc
            .mem_write(base, bytes)
            .map_err(|source| EmuError::WriteMem {
                addr: base,
                size: bytes.len(),
                source,
            })
    }

    pub fn map_image(
        &mut self,
        image: &pe::PeImage,
        file_bytes: &[u8],
        base: u64,
    ) -> Result<(), EmuError> {
        if image.size_of_headers > 0 {
            let aligned_size = align_up(u64::from(image.size_of_headers), PAGE_SIZE)?;
            let header_size = image
                .sections
                .iter()
                .map(|section| u64::from(section.virtual_address))
                .min()
                .map_or(aligned_size, |first_section| {
                    aligned_size.min(first_section)
                });

            if header_size > 0 {
                checked_end(base, header_size)?;
                map_region(&mut self.uc, base, header_size, Prot::READ)?;

                let file_len =
                    u64::try_from(file_bytes.len()).map_err(|_| EmuError::CodeTooLarge)?;
                let copy_len = usize::try_from(
                    u64::from(image.size_of_headers)
                        .min(file_len)
                        .min(header_size),
                )
                .map_err(|_| EmuError::CodeTooLarge)?;
                if copy_len > 0 {
                    self.uc
                        .mem_write(base, &file_bytes[..copy_len])
                        .map_err(|source| EmuError::WriteMem {
                            addr: base,
                            size: copy_len,
                            source,
                        })?;
                }
            }
        }

        let mut sections = image.sections.iter().collect::<Vec<_>>();
        sections.sort_by_key(|section| section.virtual_address);

        for section in sections {
            let section_size = u64::from(section.virtual_size.max(section.size_of_raw_data));
            if section_size == 0 {
                continue;
            }

            let map_size = align_up(section_size, PAGE_SIZE)?;
            let addr = base.checked_add(u64::from(section.virtual_address)).ok_or(
                EmuError::AddressRangeOverflow {
                    base,
                    size: u64::from(section.virtual_address),
                },
            )?;
            checked_end(addr, map_size)?;
            map_region(
                &mut self.uc,
                addr,
                map_size,
                section_prot(section.characteristics),
            )?;

            if section.size_of_raw_data == 0 {
                continue;
            }

            let file_len = u64::try_from(file_bytes.len()).map_err(|_| EmuError::CodeTooLarge)?;
            let raw_start = u64::from(section.pointer_to_raw_data);
            if raw_start > file_len {
                return Err(EmuError::SectionOutOfFile {
                    offset: section.pointer_to_raw_data,
                    size: section.size_of_raw_data,
                    file_size: file_bytes.len(),
                });
            }

            let raw_start = usize::try_from(raw_start).map_err(|_| EmuError::SectionOutOfFile {
                offset: section.pointer_to_raw_data,
                size: section.size_of_raw_data,
                file_size: file_bytes.len(),
            })?;
            let remaining = file_len - u64::from(section.pointer_to_raw_data);
            let copy_len = usize::try_from(u64::from(section.size_of_raw_data).min(remaining))
                .map_err(|_| EmuError::CodeTooLarge)?;
            if copy_len > 0 {
                self.uc
                    .mem_write(addr, &file_bytes[raw_start..raw_start + copy_len])
                    .map_err(|source| EmuError::WriteMem {
                        addr,
                        size: copy_len,
                        source,
                    })?;
            }
        }

        Ok(())
    }

    pub fn write_reg(&mut self, reg: RegisterX86, val: u64) -> Result<(), EmuError> {
        self.uc
            .reg_write(reg, val)
            .map_err(|source| EmuError::WriteReg { reg, source })
    }

    pub fn read_reg(&self, reg: RegisterX86) -> Result<u64, EmuError> {
        self.uc
            .reg_read(reg)
            .map_err(|source| EmuError::ReadReg { reg, source })
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmuError> {
        let mut bytes = vec![0; len];
        self.uc
            .mem_read(addr, &mut bytes)
            .map_err(|source| EmuError::ReadMem {
                addr,
                size: len,
                source,
            })?;
        Ok(bytes)
    }

    pub fn run(&mut self, begin: u64, until: u64, count: usize) -> Result<(), EmuError> {
        self.uc
            .emu_start(begin, until, 0, count)
            .map_err(|source| EmuError::Start {
                begin,
                until,
                count,
                source,
            })
    }

    /// Run with lightweight execution observation.
    ///
    /// This installs hooks and leaves them installed, so it is intended to be
    /// called once per `Emu` instance. Use a fresh `Emu` for each observation.
    pub fn run_observed(
        &mut self,
        begin: u64,
        max_instructions: u64,
    ) -> Result<RunReport, EmuError> {
        let count =
            usize::try_from(max_instructions).map_err(|_| EmuError::InstructionCapTooLarge {
                count: max_instructions,
            })?;

        {
            let data = self.uc.get_data_mut();
            data.instr_count = 0;
            data.last_fault = None;
            data.recent_rips.clear();
        }

        self.uc
            .add_code_hook(0, u64::MAX, |uc, address, _size| {
                let data = uc.get_data_mut();
                data.instr_count += 1;
                data.recent_rips.push_back(address);
                if data.recent_rips.len() > RECENT_RIPS_CAP {
                    data.recent_rips.pop_front();
                }
            })
            .map(|_| ())
            .map_err(EmuError::Hook)?;

        self.uc
            .add_mem_hook(
                HookType::MEM_UNMAPPED | HookType::MEM_PROT,
                0,
                u64::MAX,
                |uc, mem_type, address, _size, _value| {
                    uc.get_data_mut().last_fault = Some(MemFault {
                        kind: fault_kind_from_mem_type(mem_type),
                        address,
                    });
                    false
                },
            )
            .map(|_| ())
            .map_err(EmuError::Hook)?;

        let run_result = if max_instructions == 0 {
            Ok(())
        } else {
            self.uc.emu_start(begin, 0, 0, count)
        };

        let instructions_executed = self.uc.get_data().instr_count;
        let stop_reason = match run_result {
            Ok(()) => {
                if instructions_executed >= max_instructions {
                    StopReason::ReachedInstructionCap
                } else {
                    StopReason::ReachedUntil
                }
            }
            Err(source) => {
                stop_reason_from_uc_error(source, self.uc.get_data().last_fault, || {
                    self.uc.reg_read(RegisterX86::RIP)
                })?
            }
        };

        let final_rip = self
            .uc
            .reg_read(RegisterX86::RIP)
            .map_err(|source| EmuError::ReadReg {
                reg: RegisterX86::RIP,
                source,
            })?;
        let recent_rips = self.recent_rips();
        let registers = snapshot_registers(&self.uc);

        Ok(RunReport {
            stop_reason,
            final_rip,
            instructions_executed,
            recent_rips,
            registers,
        })
    }

    pub fn install_code_trace_hook(&mut self) -> Result<(), EmuError> {
        self.uc
            .add_code_hook(0, u64::MAX, |uc, address, _size| {
                uc.get_data_mut().executed_addresses.push(address);
            })
            .map(|_| ())
            .map_err(EmuError::Hook)
    }

    pub fn executed_addresses(&self) -> Vec<u64> {
        self.uc.get_data().executed_addresses.clone()
    }

    pub fn recent_rips(&self) -> Vec<u64> {
        self.uc.get_data().recent_rips.iter().copied().collect()
    }
}

fn snapshot_registers(uc: &Unicorn<'static, EmuData>) -> Vec<(RegisterX86, u64)> {
    REGISTER_SNAPSHOT_ORDER
        .iter()
        .filter_map(|&reg| uc.reg_read(reg).ok().map(|value| (reg, value)))
        .collect()
}

fn fault_kind_from_mem_type(mem_type: MemType) -> FaultKind {
    match mem_type {
        MemType::READ_UNMAPPED => FaultKind::ReadUnmapped,
        MemType::WRITE_UNMAPPED => FaultKind::WriteUnmapped,
        MemType::FETCH_UNMAPPED => FaultKind::FetchUnmapped,
        MemType::READ_PROT => FaultKind::ReadProt,
        MemType::WRITE_PROT => FaultKind::WriteProt,
        MemType::FETCH_PROT => FaultKind::FetchProt,
        _ => FaultKind::Other,
    }
}

fn fault_kind_from_uc_error(source: uc_error) -> FaultKind {
    match source {
        uc_error::READ_UNMAPPED => FaultKind::ReadUnmapped,
        uc_error::WRITE_UNMAPPED => FaultKind::WriteUnmapped,
        uc_error::FETCH_UNMAPPED => FaultKind::FetchUnmapped,
        uc_error::READ_PROT => FaultKind::ReadProt,
        uc_error::WRITE_PROT => FaultKind::WriteProt,
        uc_error::FETCH_PROT => FaultKind::FetchProt,
        _ => FaultKind::Other,
    }
}

fn stop_reason_from_uc_error(
    source: uc_error,
    last_fault: Option<MemFault>,
    read_rip: impl FnOnce() -> Result<u64, uc_error>,
) -> Result<StopReason, EmuError> {
    match source {
        uc_error::READ_UNMAPPED
        | uc_error::WRITE_UNMAPPED
        | uc_error::FETCH_UNMAPPED
        | uc_error::READ_PROT
        | uc_error::WRITE_PROT
        | uc_error::FETCH_PROT => {
            let fault = match last_fault {
                Some(fault) => fault,
                None => MemFault {
                    kind: fault_kind_from_uc_error(source),
                    address: read_rip().map_err(|source| EmuError::ReadReg {
                        reg: RegisterX86::RIP,
                        source,
                    })?,
                },
            };
            Ok(StopReason::MemoryFault(fault))
        }
        uc_error::INSN_INVALID => Ok(StopReason::InvalidInstruction),
        _ => Ok(StopReason::Other(source.to_string())),
    }
}

fn checked_end(base: u64, size: u64) -> Result<u64, EmuError> {
    base.checked_add(size)
        .ok_or(EmuError::AddressRangeOverflow { base, size })
}

fn map_region(
    uc: &mut Unicorn<'static, EmuData>,
    addr: u64,
    size: u64,
    perms: Prot,
) -> Result<(), EmuError> {
    uc.mem_map(addr, size, perms)
        .map_err(|source| EmuError::Map { addr, size, source })
}

fn section_prot(characteristics: u32) -> Prot {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    let mut prot = Prot::NONE;
    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        prot |= Prot::EXEC;
    }
    if characteristics & IMAGE_SCN_MEM_READ != 0 {
        prot |= Prot::READ;
    }
    if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
        prot |= Prot::WRITE;
    }

    if prot == Prot::NONE {
        Prot::READ
    } else {
        prot
    }
}

fn align_up(value: u64, align: u64) -> Result<u64, EmuError> {
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|with_padding| with_padding & !mask)
        .ok_or(EmuError::AddressRangeOverflow {
            base: value,
            size: mask,
        })
}

#[cfg(test)]
mod tests {
    use crate::pe;

    use super::{Emu, FaultKind, RegisterX86, StopReason, RECENT_RIPS_CAP};

    const CODE_BASE: u64 = 0x0000_0000_0040_0000;
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: u16 = 0xf0;

    const ARITHMETIC_SHELLCODE: &[u8] = &[
        0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, // mov rax, 2
        0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00, // mov rcx, 3
        0x48, 0x0f, 0xaf, 0xc1, // imul rax, rcx
        0x48, 0x83, 0xc0, 0x07, // add rax, 7
    ];

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_pe64_with_text_pattern() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];

        bytes[0..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, PE_OFFSET as u32);

        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff = PE_OFFSET + 4;
        write_u16(&mut bytes, coff, 0x8664);
        write_u16(&mut bytes, coff + 2, 1);
        write_u16(&mut bytes, coff + 16, OPTIONAL_HEADER_SIZE);
        write_u16(&mut bytes, coff + 18, 0x0002);

        let optional = coff + 20;
        write_u16(&mut bytes, optional, 0x20b);
        bytes[optional + 2] = 14;
        write_u32(&mut bytes, optional + 4, 0x200);
        write_u32(&mut bytes, optional + 16, 0x1000);
        write_u32(&mut bytes, optional + 20, 0x1000);

        let windows = optional + 24;
        write_u64(&mut bytes, windows, 0x140000000);
        write_u32(&mut bytes, windows + 8, 0x1000);
        write_u32(&mut bytes, windows + 12, 0x200);
        write_u16(&mut bytes, windows + 16, 6);
        write_u16(&mut bytes, windows + 18, 0);
        write_u32(&mut bytes, windows + 32, 0x2000);
        write_u32(&mut bytes, windows + 36, 0x400);
        write_u16(&mut bytes, windows + 44, 3);
        write_u64(&mut bytes, windows + 48, 0x100000);
        write_u64(&mut bytes, windows + 56, 0x1000);
        write_u64(&mut bytes, windows + 64, 0x100000);
        write_u64(&mut bytes, windows + 72, 0x1000);
        write_u32(&mut bytes, windows + 84, 16);

        let section_table = optional + usize::from(OPTIONAL_HEADER_SIZE);
        bytes[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
        write_u32(&mut bytes, section_table + 8, 0x200);
        write_u32(&mut bytes, section_table + 12, 0x1000);
        write_u32(&mut bytes, section_table + 16, 0x200);
        write_u32(&mut bytes, section_table + 20, 0x400);
        write_u32(&mut bytes, section_table + 36, 0x60000020);

        bytes[0x400..0x408].copy_from_slice(&[0xcc, 0x48, 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90]);

        bytes
    }

    #[test]
    fn arithmetic_shellcode_reaches_known_state() {
        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, ARITHMETIC_SHELLCODE).unwrap();

        let until = CODE_BASE + ARITHMETIC_SHELLCODE.len() as u64;
        emu.run(CODE_BASE, until, 16).unwrap();

        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 13);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), until);
    }

    #[test]
    fn stack_push_pop_roundtrip() {
        let shellcode = [
            0xb8, 0xef, 0xbe, 0xad, 0xde, // mov eax, 0xDEADBEEF
            0x50, // push rax
            0x5b, // pop rbx
        ];

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();
        let initial_rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        emu.run(CODE_BASE, CODE_BASE + shellcode.len() as u64, 16)
            .unwrap();

        assert_eq!(emu.read_reg(RegisterX86::RBX).unwrap(), 0xdead_beef);
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), initial_rsp);
        assert_eq!(
            emu.read_mem(initial_rsp - 8, 8).unwrap(),
            0xdead_beefu64.to_le_bytes()
        );
    }

    #[test]
    fn code_trace_hook_records_each_instruction() {
        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, ARITHMETIC_SHELLCODE).unwrap();
        emu.install_code_trace_hook().unwrap();

        emu.run(CODE_BASE, CODE_BASE + ARITHMETIC_SHELLCODE.len() as u64, 16)
            .unwrap();

        assert_eq!(
            emu.executed_addresses(),
            vec![CODE_BASE, CODE_BASE + 7, CODE_BASE + 14, CODE_BASE + 18]
        );
    }

    #[test]
    fn run_observed_reports_unmapped_read() {
        let unmapped_addr: u64 = 0x0000_0000_1234_5000;
        let mut shellcode = vec![0x48, 0xa1];
        shellcode.extend_from_slice(&unmapped_addr.to_le_bytes());

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();

        let report = emu.run_observed(CODE_BASE, 16).unwrap();

        match &report.stop_reason {
            StopReason::MemoryFault(fault) => {
                assert_eq!(fault.kind, FaultKind::ReadUnmapped);
                assert_eq!(fault.address, unmapped_addr);
            }
            other => panic!("expected memory fault, got {other:?}"),
        }
        assert!(report.instructions_executed >= 1);
        assert!(!report.recent_rips.is_empty());
        assert_eq!(report.recent_rips.last().copied(), Some(CODE_BASE));
        assert!(report
            .registers
            .iter()
            .any(|(reg, _value)| *reg == RegisterX86::RIP));
    }

    #[test]
    fn run_observed_hits_instruction_cap() {
        let shellcode = [0xeb, 0xfe];

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();

        let report = emu.run_observed(CODE_BASE, 1_000).unwrap();

        assert_eq!(report.stop_reason, StopReason::ReachedInstructionCap);
        assert_eq!(report.instructions_executed, 1_000);
        assert!(report.recent_rips.len() <= RECENT_RIPS_CAP);
    }

    #[test]
    fn map_image_maps_sections_and_headers() {
        let bytes = minimal_pe64_with_text_pattern();
        let image = pe::PeImage::parse(&bytes).unwrap();
        let text = image
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .unwrap();

        let mut emu = Emu::new().unwrap();
        emu.map_image(&image, &bytes, image.image_base).unwrap();

        let text_va = image.image_base + u64::from(text.virtual_address);
        assert_eq!(
            emu.read_mem(text_va, 8).unwrap(),
            vec![0xcc, 0x48, 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90]
        );

        if image.size_of_headers > 0 {
            assert_eq!(emu.read_mem(image.image_base, 1).unwrap(), vec![bytes[0]]);
        }
    }
}
