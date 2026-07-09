//! Minimal Unicorn-backed x86-64 emulation harness.

pub use unicorn_engine::RegisterX86;

use thiserror::Error;
use unicorn_engine::{
    uc_error,
    unicorn_const::{Arch, Mode, Prot},
    Unicorn,
};

const PAGE_SIZE: u64 = 0x1000;

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

    #[error("address range overflows: base 0x{base:016x}, size {size:#x}")]
    AddressRangeOverflow { base: u64, size: u64 },

    #[error("code buffer is too large to map")]
    CodeTooLarge,
}

#[derive(Default)]
struct EmuData {
    executed_addresses: Vec<u64>,
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
    use super::{Emu, RegisterX86};

    const CODE_BASE: u64 = 0x0000_0000_0040_0000;

    const ARITHMETIC_SHELLCODE: &[u8] = &[
        0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, // mov rax, 2
        0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00, // mov rcx, 3
        0x48, 0x0f, 0xaf, 0xc1, // imul rax, rcx
        0x48, 0x83, 0xc0, 0x07, // add rax, 7
    ];

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
}
