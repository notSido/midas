//! Minimal Unicorn-backed x86-64 emulation harness.

use std::collections::VecDeque;
use std::rc::Rc;

use crate::pe;

pub use unicorn_engine::RegisterX86;

use thiserror::Error;
use unicorn_engine::{
    uc_error,
    unicorn_const::{Arch, ContextMode, HookType, MemType, Mode, Prot},
    Context, Unicorn,
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

/// Offset of `NtTib.StackBase` in the x64 TEB.
pub const TEB_STACKBASE_OFFSET: u64 = 0x08;

/// Offset of `NtTib.StackLimit` in the x64 TEB.
pub const TEB_STACKLIMIT_OFFSET: u64 = 0x10;

/// Offset of `NtTib.Self` in the x64 TEB.
pub const TEB_SELF_OFFSET: u64 = 0x30;

/// Offset of `TEB.ProcessEnvironmentBlock` in the x64 TEB.
pub const TEB_PEB_OFFSET: u64 = 0x60;

/// Offset of `PEB.BeingDebugged` in the x64 PEB.
pub const PEB_BEINGDEBUGGED_OFFSET: u64 = 0x02;

/// Offset of `PEB.ImageBaseAddress` in the x64 PEB.
pub const PEB_IMAGEBASE_OFFSET: u64 = 0x10;

#[derive(Debug, Error)]
pub enum EmuError {
    #[error("failed to initialize Unicorn: {0}")]
    Init(#[source] uc_error),

    #[error("failed to configure Unicorn for CPU-only contexts: {0}")]
    ConfigureCpuContext(#[source] uc_error),

    #[error("failed to capture Unicorn CPU context: {0}")]
    CaptureCpuContext(#[source] uc_error),

    #[error("failed to save Unicorn CPU context: {0}")]
    SaveCpuContext(#[source] uc_error),

    #[error("failed to restore Unicorn CPU context: {0}")]
    RestoreCpuContext(#[source] uc_error),

    #[error("CPU context belongs to another Emu")]
    ForeignCpuContext,

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

    #[error("failed to inspect mapped memory regions: {0}")]
    MemoryRegions(#[source] uc_error),

    #[error("cannot write unmapped memory at 0x{addr:016x} ({size:#x} bytes)")]
    WriteUnmapped { addr: u64, size: usize },

    #[error("cannot write protected memory at 0x{addr:016x} ({size:#x} bytes)")]
    WriteProt { addr: u64, size: usize },

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

#[derive(Debug, Clone)]
pub enum TraceEvent {
    Insn {
        address: u64,
    },
    MemRead {
        address: u64,
        size: usize,
        value: u64,
    },
    MemWrite {
        address: u64,
        size: usize,
        value: u64,
    },
}

#[derive(Debug, Clone)]
pub struct WatchHit {
    pub instruction_index: u64,
    pub is_write: bool,
    pub address: u64,
    pub size: usize,
    pub rip: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentWatchHit {
    pub global_instruction_index: u64,
    pub is_write: bool,
    pub address: u64,
    pub size: usize,
    pub rip: u64,
    /// The value of the full access (up to eight bytes), not only the bytes
    /// intersecting the watched range. Accesses wider than eight bytes and
    /// failed reads have no captured value.
    pub value: Option<u64>,
    pub registers: Vec<(RegisterX86, u64)>,
}

#[derive(Default)]
struct EmuData {
    executed_addresses: Vec<u64>,
    recent_rips: VecDeque<u64>,
    instr_count: u64,
    total_instr_count: u64,
    last_fault: Option<MemFault>,
    trace_from: u64,
    trace_events: Vec<TraceEvent>,
    trace_active: bool,
    watch_ranges: Vec<(u64, u64)>,
    watch_hits: Vec<WatchHit>,
    watch_hit_cap: usize,
    persistent_watch_ranges: Vec<(u64, u64)>,
    persistent_watch_hits: Vec<PersistentWatchHit>,
    persistent_watch_hit_cap: usize,
}

/// An opaque, reusable snapshot of Unicorn CPU state owned by one [`Emu`].
///
/// This snapshots Unicorn CPU state only. Guest memory, memory mappings, hooks,
/// `EmuData` observation buffers and counters, `Win64Env`, and scheduler or time
/// state remain live and are not snapshotted.
pub struct CpuContext {
    context: Context,
    owner: Rc<()>,
}

pub struct Emu {
    uc: Unicorn<'static, EmuData>,
    observation_hooks_installed: bool,
    cpu_context_owner: Rc<()>,
    persistent_watch_hook_installed: bool,
}

impl Emu {
    pub fn new() -> Result<Self, EmuError> {
        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, EmuData::default())
            .map_err(EmuError::Init)?;
        uc.ctl_set_context_mode(ContextMode::CPU)
            .map_err(EmuError::ConfigureCpuContext)?;

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

        write_u64_mem(
            &mut uc,
            TEB_BASE + TEB_STACKBASE_OFFSET,
            STACK_BASE + STACK_SIZE,
        )?;
        write_u64_mem(&mut uc, TEB_BASE + TEB_STACKLIMIT_OFFSET, STACK_BASE)?;
        write_u64_mem(&mut uc, TEB_BASE + TEB_SELF_OFFSET, TEB_BASE)?;
        write_u64_mem(&mut uc, TEB_BASE + TEB_PEB_OFFSET, PEB_BASE)?;
        write_u8_mem(&mut uc, PEB_BASE + PEB_BEINGDEBUGGED_OFFSET, 0)?;

        let mut emu = Self {
            uc,
            observation_hooks_installed: false,
            cpu_context_owner: Rc::new(()),
            persistent_watch_hook_installed: false,
        };
        emu.ensure_observation_hooks()?;
        Ok(emu)
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

    pub fn map_readonly(&mut self, base: u64, bytes: &[u8]) -> Result<(), EmuError> {
        let len = u64::try_from(bytes.len()).map_err(|_| EmuError::CodeTooLarge)?;
        let size = align_up(len.max(1), PAGE_SIZE)?;
        base.checked_add(size)
            .ok_or(EmuError::AddressRangeOverflow { base, size })?;

        self.uc
            .mem_map(base, size, Prot::READ)
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

    /// Map a nonzero, page-aligned region as explicitly zeroed RW/NX memory.
    pub(crate) fn map_zeroed_rw(&mut self, base: u64, size: u64) -> Result<(), EmuError> {
        let end = checked_end(base, size)?;
        map_region(&mut self.uc, base, size, Prot::READ | Prot::WRITE)?;

        let zero_page = [0u8; PAGE_SIZE as usize];
        let mut page = base;
        while page < end {
            self.uc
                .mem_write(page, &zero_page)
                .map_err(|source| EmuError::WriteMem {
                    addr: page,
                    size: zero_page.len(),
                    source,
                })?;
            page = page
                .checked_add(PAGE_SIZE)
                .ok_or(EmuError::AddressRangeOverflow { base, size })?;
        }
        Ok(())
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

        self.set_image_base_in_peb(base)?;

        Ok(())
    }

    pub fn set_image_base_in_peb(&mut self, image_base: u64) -> Result<(), EmuError> {
        self.write_u64(PEB_BASE + PEB_IMAGEBASE_OFFSET, image_base)
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

    /// Capture the current Unicorn CPU state into a new reusable context.
    ///
    /// See [`CpuContext`] for the intentionally narrow snapshot scope.
    pub fn capture_cpu_context(&self) -> Result<CpuContext, EmuError> {
        let context = self
            .uc
            .context_init()
            .map_err(EmuError::CaptureCpuContext)?;
        Ok(CpuContext {
            context,
            owner: Rc::clone(&self.cpu_context_owner),
        })
    }

    /// Overwrite an owned context with the current Unicorn CPU state.
    ///
    /// A context from another [`Emu`] is rejected before calling Unicorn.
    pub fn save_cpu_context(&self, context: &mut CpuContext) -> Result<(), EmuError> {
        if !Rc::ptr_eq(&self.cpu_context_owner, &context.owner) {
            return Err(EmuError::ForeignCpuContext);
        }

        self.uc
            .context_save(&mut context.context)
            .map_err(EmuError::SaveCpuContext)
    }

    /// Restore Unicorn CPU state from an owned context.
    ///
    /// A context from another [`Emu`] is rejected before calling Unicorn. See
    /// [`CpuContext`] for state that deliberately remains live across restore.
    /// Because [`Emu::run`] and [`Emu::resume`] take an explicit start address,
    /// a caller resuming this state must read the restored `RIP` and pass it as
    /// that address.
    pub fn restore_cpu_context(&mut self, context: &CpuContext) -> Result<(), EmuError> {
        if !Rc::ptr_eq(&self.cpu_context_owner, &context.owner) {
            return Err(EmuError::ForeignCpuContext);
        }

        self.uc
            .context_restore(&context.context)
            .map_err(EmuError::RestoreCpuContext)
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

    pub(crate) fn write_mem(&mut self, addr: u64, bytes: &[u8]) -> Result<(), EmuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let size = bytes.len();
        let size_u64 = u64::try_from(size).map_err(|_| EmuError::CodeTooLarge)?;
        let end = addr
            .checked_add(size_u64 - 1)
            .ok_or(EmuError::AddressRangeOverflow {
                base: addr,
                size: size_u64,
            })?;
        let regions = self.uc.mem_regions().map_err(EmuError::MemoryRegions)?;
        let mut cursor = addr;
        while cursor <= end {
            let region = regions
                .iter()
                .find(|region| region.begin <= cursor && cursor <= region.end)
                .ok_or(EmuError::WriteUnmapped { addr: cursor, size })?;
            if region.perms & Prot::WRITE.0 == 0 {
                return Err(EmuError::WriteProt { addr: cursor, size });
            }
            if region.end >= end {
                break;
            }
            cursor = region
                .end
                .checked_add(1)
                .ok_or(EmuError::AddressRangeOverflow {
                    base: addr,
                    size: size_u64,
                })?;
        }
        self.uc
            .mem_write(addr, bytes)
            .map_err(|source| EmuError::WriteMem {
                addr,
                size: bytes.len(),
                source,
            })
    }

    fn write_u64(&mut self, addr: u64, value: u64) -> Result<(), EmuError> {
        write_u64_mem(&mut self.uc, addr, value)
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

    /// Resume execution with lightweight observation.
    ///
    /// `instructions_executed` is reset for each resume and reports only the
    /// current run slice.
    pub fn resume(&mut self, begin: u64, max_instructions: u64) -> Result<RunReport, EmuError> {
        self.ensure_observation_hooks()?;

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

        let run_result = if max_instructions == 0 {
            Ok(())
        } else {
            self.uc.emu_start(begin, 0, 0, count)
        };

        self.build_run_report(run_result, max_instructions)
    }

    /// Run with lightweight execution observation.
    pub fn run_observed(
        &mut self,
        begin: u64,
        max_instructions: u64,
    ) -> Result<RunReport, EmuError> {
        self.ensure_observation_hooks()?;
        self.resume(begin, max_instructions)
    }

    /// Configure a trap-aware memory watch that persists across [`Emu::resume`]
    /// calls.
    ///
    /// Ranges are half-open (`start..end`). Any memory access that overlaps a
    /// configured range is recorded until `hit_cap` hits have been retained.
    /// The underlying memory hook remains installed for this [`Emu`]'s
    /// lifetime; reconfiguration replaces the ranges and retained hits.
    pub fn configure_persistent_watch(
        &mut self,
        ranges: &[(u64, u64)],
        hit_cap: usize,
    ) -> Result<(), EmuError> {
        self.ensure_observation_hooks()?;
        self.ensure_persistent_watch_hook()?;

        let data = self.uc.get_data_mut();
        data.persistent_watch_ranges.clear();
        data.persistent_watch_ranges.extend_from_slice(ranges);
        data.persistent_watch_hits.clear();
        data.persistent_watch_hit_cap = hit_cap;
        Ok(())
    }

    pub fn clear_persistent_watch_hits(&mut self) {
        self.uc.get_data_mut().persistent_watch_hits.clear();
    }

    pub fn persistent_watch_hits(&self) -> Vec<PersistentWatchHit> {
        self.uc.get_data().persistent_watch_hits.clone()
    }

    /// Run with lightweight execution observation plus capped memory range hits.
    ///
    /// This installs hooks and leaves them installed, so it is intended to be
    /// called once per `Emu` instance. Use a fresh `Emu` for each watched run.
    pub fn run_watching(
        &mut self,
        begin: u64,
        max_instructions: u64,
        ranges: &[(u64, u64)],
        hit_cap: usize,
    ) -> Result<(RunReport, Vec<WatchHit>), EmuError> {
        let count =
            usize::try_from(max_instructions).map_err(|_| EmuError::InstructionCapTooLarge {
                count: max_instructions,
            })?;

        {
            let data = self.uc.get_data_mut();
            data.instr_count = 0;
            data.last_fault = None;
            data.recent_rips.clear();
            data.watch_ranges.clear();
            data.watch_ranges.extend_from_slice(ranges);
            data.watch_hits.clear();
            data.watch_hit_cap = hit_cap;
        }

        self.uc
            .add_mem_hook(
                HookType::MEM_READ | HookType::MEM_WRITE,
                0,
                u64::MAX,
                |uc, mem_type, address, size, _value| {
                    let should_record = {
                        let data = uc.get_data();
                        data.watch_hits.len() < data.watch_hit_cap
                            && access_overlaps_ranges(address, size, &data.watch_ranges)
                    };
                    if !should_record {
                        return false;
                    }

                    let is_write = match mem_type {
                        MemType::READ => false,
                        MemType::WRITE => true,
                        _ => return false,
                    };
                    let rip = uc.reg_read(RegisterX86::RIP).ok().map_or(0, |value| value);
                    let data = uc.get_data_mut();
                    let instruction_index = data.instr_count;
                    data.watch_hits.push(WatchHit {
                        instruction_index,
                        is_write,
                        address,
                        size,
                        rip,
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

        let report = self.build_run_report(run_result, max_instructions)?;
        let watch_hits = self.uc.get_data().watch_hits.clone();
        Ok((report, watch_hits))
    }

    /// Run with lightweight execution observation plus a windowed detailed trace.
    ///
    /// This installs hooks and leaves them installed, so it is intended to be
    /// called once per `Emu` instance, like [`Emu::run_observed`]. Use a fresh
    /// `Emu` for each traced run.
    ///
    /// Detailed logging starts once the observed instruction count is greater
    /// than or equal to `max_instructions.saturating_sub(trace_window)`. To trace
    /// the window immediately before a fault at an initially unknown count, first
    /// find the faulting instruction count with [`Emu::run_observed`], then call
    /// this method on a fresh `Emu` with `max_instructions` set to that known
    /// fault count and `trace_window` set to the desired window.
    pub fn run_traced(
        &mut self,
        begin: u64,
        max_instructions: u64,
        trace_window: u64,
    ) -> Result<(RunReport, Vec<TraceEvent>), EmuError> {
        let count =
            usize::try_from(max_instructions).map_err(|_| EmuError::InstructionCapTooLarge {
                count: max_instructions,
            })?;

        {
            let data = self.uc.get_data_mut();
            data.instr_count = 0;
            data.last_fault = None;
            data.recent_rips.clear();
            data.trace_from = max_instructions.saturating_sub(trace_window);
            data.trace_events.clear();
            data.trace_active = false;
        }

        self.uc
            .add_code_hook(0, u64::MAX, |uc, address, _size| {
                let data = uc.get_data_mut();
                if data.instr_count >= data.trace_from {
                    data.trace_active = true;
                    data.trace_events.push(TraceEvent::Insn { address });
                }
            })
            .map(|_| ())
            .map_err(EmuError::Hook)?;

        self.uc
            .add_mem_hook(
                HookType::MEM_READ | HookType::MEM_WRITE,
                0,
                u64::MAX,
                |uc, mem_type, address, size, value| {
                    if !uc.get_data().trace_active {
                        return false;
                    }

                    let event = match mem_type {
                        MemType::READ => TraceEvent::MemRead {
                            address,
                            size,
                            value: read_hook_value(uc, address, size),
                        },
                        MemType::WRITE => TraceEvent::MemWrite {
                            address,
                            size,
                            value: value as u64,
                        },
                        _ => return false,
                    };

                    uc.get_data_mut().trace_events.push(event);
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

        let report = self.build_run_report(run_result, max_instructions)?;
        let trace_events = self.uc.get_data().trace_events.clone();
        Ok((report, trace_events))
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

    fn build_run_report(
        &self,
        run_result: Result<(), uc_error>,
        max_instructions: u64,
    ) -> Result<RunReport, EmuError> {
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

    fn ensure_observation_hooks(&mut self) -> Result<(), EmuError> {
        if self.observation_hooks_installed {
            return Ok(());
        }

        self.uc
            .add_code_hook(0, u64::MAX, |uc, address, _size| {
                let data = uc.get_data_mut();
                data.instr_count += 1;
                data.total_instr_count += 1;
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

        self.observation_hooks_installed = true;
        Ok(())
    }

    fn ensure_persistent_watch_hook(&mut self) -> Result<(), EmuError> {
        if self.persistent_watch_hook_installed {
            return Ok(());
        }

        self.uc
            .add_mem_hook(
                HookType::MEM_READ | HookType::MEM_WRITE,
                0,
                u64::MAX,
                |uc, mem_type, address, size, value| {
                    let is_write = match mem_type {
                        MemType::READ => false,
                        MemType::WRITE => true,
                        _ => return false,
                    };

                    let should_record = {
                        let data = uc.get_data();
                        data.persistent_watch_hits.len() < data.persistent_watch_hit_cap
                            && access_overlaps_ranges(address, size, &data.persistent_watch_ranges)
                    };
                    if !should_record {
                        return false;
                    }

                    let value = if is_write {
                        write_hook_value_opt(value as u64, size)
                    } else {
                        read_hook_value_opt(uc, address, size)
                    };
                    let rip = uc.reg_read(RegisterX86::RIP).ok().map_or(0, |value| value);
                    let registers = snapshot_registers(uc);

                    let data = uc.get_data_mut();
                    data.persistent_watch_hits.push(PersistentWatchHit {
                        global_instruction_index: data.total_instr_count,
                        is_write,
                        address,
                        size,
                        rip,
                        value,
                        registers,
                    });
                    false
                },
            )
            .map(|_| ())
            .map_err(EmuError::Hook)?;

        self.persistent_watch_hook_installed = true;
        Ok(())
    }
}

fn read_hook_value(uc: &Unicorn<'_, EmuData>, address: u64, size: usize) -> u64 {
    read_hook_value_opt(uc, address, size.min(8)).unwrap_or(0)
}

fn read_hook_value_opt(uc: &Unicorn<'_, EmuData>, address: u64, size: usize) -> Option<u64> {
    if size > 8 {
        return None;
    }
    if size == 0 {
        return Some(0);
    }

    let mut bytes = [0u8; 8];
    if uc.mem_read(address, &mut bytes[..size]).is_ok() {
        Some(u64::from_le_bytes(bytes))
    } else {
        None
    }
}

fn write_hook_value_opt(value: u64, size: usize) -> Option<u64> {
    (size <= 8).then(|| mask_hook_value(value, size))
}

fn mask_hook_value(value: u64, size: usize) -> u64 {
    let bits = size.saturating_mul(8);
    if bits >= u64::BITS as usize {
        value
    } else if bits == 0 {
        0
    } else {
        value & ((1u64 << bits) - 1)
    }
}

fn access_overlaps_ranges(address: u64, size: usize, ranges: &[(u64, u64)]) -> bool {
    let Ok(size) = u64::try_from(size) else {
        return false;
    };
    if size == 0 {
        return false;
    }

    let Some(access_end) = address.checked_add(size) else {
        return ranges
            .iter()
            .any(|(start, end)| start < end && address < *end);
    };

    ranges
        .iter()
        .any(|(start, end)| start < end && address < *end && *start < access_end)
}

fn snapshot_registers(uc: &Unicorn<'_, EmuData>) -> Vec<(RegisterX86, u64)> {
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

fn write_u64_mem(
    uc: &mut Unicorn<'static, EmuData>,
    addr: u64,
    value: u64,
) -> Result<(), EmuError> {
    let bytes = value.to_le_bytes();
    uc.mem_write(addr, &bytes)
        .map_err(|source| EmuError::WriteMem {
            addr,
            size: bytes.len(),
            source,
        })
}

fn write_u8_mem(uc: &mut Unicorn<'static, EmuData>, addr: u64, value: u8) -> Result<(), EmuError> {
    let bytes = [value];
    uc.mem_write(addr, &bytes)
        .map_err(|source| EmuError::WriteMem {
            addr,
            size: bytes.len(),
            source,
        })
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

    use super::{
        access_overlaps_ranges, map_region, read_hook_value_opt, write_hook_value_opt, Emu,
        EmuError, FaultKind, RegisterX86, StopReason, TraceEvent, PAGE_SIZE, PEB_BASE,
        PEB_IMAGEBASE_OFFSET, RECENT_RIPS_CAP, REGISTER_SNAPSHOT_ORDER, STACK_BASE, STACK_SIZE,
        TEB_BASE, TEB_PEB_OFFSET, TEB_SELF_OFFSET, TEB_STACKBASE_OFFSET,
    };
    use unicorn_engine::unicorn_const::Prot;

    const CODE_BASE: u64 = 0x0000_0000_0040_0000;
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: u16 = 0xf0;

    const ARITHMETIC_SHELLCODE: &[u8] = &[
        0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, // mov rax, 2
        0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00, // mov rcx, 3
        0x48, 0x0f, 0xaf, 0xc1, // imul rax, rcx
        0x48, 0x83, 0xc0, 0x07, // add rax, 7
    ];
    const SEEDED_GPRS: [RegisterX86; 15] = [
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
    ];

    struct CpuStateSeed {
        gpr_base: u64,
        rsp: u64,
        rip: u64,
        eflags: u64,
        fs_base: u64,
        gs_base: u64,
        xmm0: [u8; 16],
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn read_u64_le(bytes: &[u8]) -> u64 {
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        u64::from_le_bytes(value)
    }

    fn trace_value_mask(size: usize) -> u64 {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    }

    fn write_cpu_state(emu: &mut Emu, seed: &CpuStateSeed) {
        for (index, &reg) in SEEDED_GPRS.iter().enumerate() {
            emu.write_reg(reg, seed.gpr_base + index as u64).unwrap();
        }
        emu.write_reg(RegisterX86::RSP, seed.rsp).unwrap();
        emu.write_reg(RegisterX86::RIP, seed.rip).unwrap();
        emu.write_reg(RegisterX86::EFLAGS, seed.eflags).unwrap();
        emu.write_reg(RegisterX86::FS_BASE, seed.fs_base).unwrap();
        emu.write_reg(RegisterX86::GS_BASE, seed.gs_base).unwrap();
        emu.uc
            .reg_write_long(RegisterX86::XMM0, &seed.xmm0)
            .unwrap();
    }

    fn assert_cpu_state(emu: &Emu, seed: &CpuStateSeed) {
        for (index, &reg) in SEEDED_GPRS.iter().enumerate() {
            assert_eq!(
                emu.read_reg(reg).unwrap(),
                seed.gpr_base + index as u64,
                "unexpected value for {reg:?}"
            );
        }
        assert_eq!(emu.read_reg(RegisterX86::RSP).unwrap(), seed.rsp);
        assert_eq!(emu.read_reg(RegisterX86::RIP).unwrap(), seed.rip);
        assert_eq!(emu.read_reg(RegisterX86::EFLAGS).unwrap(), seed.eflags);
        assert_eq!(emu.read_reg(RegisterX86::FS_BASE).unwrap(), seed.fs_base);
        assert_eq!(emu.read_reg(RegisterX86::GS_BASE).unwrap(), seed.gs_base);
        assert_eq!(
            emu.uc.reg_read_long(RegisterX86::XMM0).unwrap().as_ref(),
            seed.xmm0.as_slice()
        );
    }

    fn persistent_watch_shellcode(marker: u64, value: u64) -> Vec<u8> {
        let mut shellcode = Vec::new();
        shellcode.extend_from_slice(&[0x49, 0xb9]);
        shellcode.extend_from_slice(&marker.to_le_bytes());
        shellcode.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, 0xf8, 0, 0, 0, 0]);
        shellcode.extend_from_slice(&[0x48, 0x8b, 0x5c, 0x24, 0xf8]);
        shellcode.extend_from_slice(&[0x48, 0xb8]);
        shellcode.extend_from_slice(&value.to_le_bytes());
        shellcode.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0xf0]);
        shellcode.extend_from_slice(&[0x48, 0x8b, 0x4c, 0x24, 0xf0]);
        shellcode
    }

    fn register_value(registers: &[(RegisterX86, u64)], reg: RegisterX86) -> Option<u64> {
        registers
            .iter()
            .find_map(|(candidate, value)| (*candidate == reg).then_some(*value))
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
    fn new_populates_teb_self_and_peb_pointer() {
        let emu = Emu::new().unwrap();

        assert_eq!(
            read_u64_le(&emu.read_mem(TEB_BASE + TEB_SELF_OFFSET, 8).unwrap()),
            TEB_BASE
        );
        assert_eq!(
            read_u64_le(&emu.read_mem(TEB_BASE + TEB_PEB_OFFSET, 8).unwrap()),
            PEB_BASE
        );
        assert_eq!(
            read_u64_le(&emu.read_mem(TEB_BASE + TEB_STACKBASE_OFFSET, 8).unwrap()),
            STACK_BASE + STACK_SIZE
        );
        assert_eq!(emu.read_reg(RegisterX86::GS_BASE).unwrap(), TEB_BASE);
    }

    #[test]
    fn cpu_context_roundtrips_and_can_be_overwritten() {
        let captured = CpuStateSeed {
            gpr_base: 0x1111_0000_0000_0000,
            rsp: STACK_BASE + 0x1_0000,
            rip: CODE_BASE + 0x10,
            eflags: 0x202,
            fs_base: PEB_BASE,
            gs_base: TEB_BASE,
            xmm0: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        };
        let overwritten = CpuStateSeed {
            gpr_base: 0x2222_0000_0000_0000,
            rsp: STACK_BASE + 0x2_0000,
            rip: CODE_BASE + 0x20,
            eflags: 0x246,
            fs_base: STACK_BASE,
            gs_base: PEB_BASE,
            xmm0: [
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ],
        };
        let poison = CpuStateSeed {
            gpr_base: 0x3333_0000_0000_0000,
            rsp: STACK_BASE + 0x3_0000,
            rip: CODE_BASE + 0x30,
            eflags: 0x286,
            fs_base: TEB_BASE,
            gs_base: STACK_BASE,
            xmm0: [
                0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
                0x23, 0x01,
            ],
        };

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &[0x90; 0x40]).unwrap();

        write_cpu_state(&mut emu, &captured);
        let mut context = emu.capture_cpu_context().unwrap();

        write_cpu_state(&mut emu, &poison);
        emu.restore_cpu_context(&context).unwrap();
        assert_cpu_state(&emu, &captured);

        write_cpu_state(&mut emu, &overwritten);
        emu.save_cpu_context(&mut context).unwrap();
        write_cpu_state(&mut emu, &poison);
        emu.restore_cpu_context(&context).unwrap();
        assert_cpu_state(&emu, &overwritten);
    }

    #[test]
    fn cpu_context_restore_leaves_memory_observations_and_hooks_live() {
        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &[0x90; 3]).unwrap();

        let shared_address = STACK_BASE + 0x800;
        emu.write_mem(shared_address, &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        let context = emu.capture_cpu_context().unwrap();

        emu.install_code_trace_hook().unwrap();
        emu.write_mem(shared_address, &[0xaa, 0xbb, 0xcc, 0xdd])
            .unwrap();
        emu.run(CODE_BASE, CODE_BASE + 1, 1).unwrap();
        emu.run(CODE_BASE + 1, CODE_BASE + 2, 1).unwrap();

        let history_before_restore = vec![CODE_BASE, CODE_BASE + 1];
        assert_eq!(emu.executed_addresses(), history_before_restore);
        assert_eq!(emu.recent_rips(), vec![CODE_BASE, CODE_BASE + 1]);
        assert_eq!(emu.uc.get_data().instr_count, 2);

        emu.restore_cpu_context(&context).unwrap();

        assert_eq!(
            emu.read_mem(shared_address, 4).unwrap(),
            vec![0xaa, 0xbb, 0xcc, 0xdd]
        );
        assert_eq!(emu.executed_addresses(), history_before_restore);
        assert_eq!(emu.recent_rips(), vec![CODE_BASE, CODE_BASE + 1]);
        assert_eq!(emu.uc.get_data().instr_count, 2);

        emu.run(CODE_BASE + 2, CODE_BASE + 3, 1).unwrap();
        assert_eq!(
            emu.executed_addresses(),
            vec![CODE_BASE, CODE_BASE + 1, CODE_BASE + 2]
        );
        assert_eq!(
            emu.recent_rips(),
            vec![CODE_BASE, CODE_BASE + 1, CODE_BASE + 2]
        );
        assert_eq!(emu.uc.get_data().instr_count, 3);
    }

    #[test]
    fn foreign_cpu_context_is_rejected_without_side_effects() {
        let owner_captured = CpuStateSeed {
            gpr_base: 0x4444_0000_0000_0000,
            rsp: STACK_BASE + 0x4_0000,
            rip: CODE_BASE + 0x10,
            eflags: 0x202,
            fs_base: PEB_BASE,
            gs_base: TEB_BASE,
            xmm0: [0x44; 16],
        };
        let owner_poison = CpuStateSeed {
            gpr_base: 0x5555_0000_0000_0000,
            rsp: STACK_BASE + 0x5_0000,
            rip: CODE_BASE + 0x20,
            eflags: 0x246,
            fs_base: STACK_BASE,
            gs_base: PEB_BASE,
            xmm0: [0x55; 16],
        };
        let foreign_destination = CpuStateSeed {
            gpr_base: 0x6666_0000_0000_0000,
            rsp: STACK_BASE + 0x6_0000,
            rip: CODE_BASE + 0x30,
            eflags: 0x286,
            fs_base: TEB_BASE,
            gs_base: STACK_BASE,
            xmm0: [0x66; 16],
        };

        let mut owner = Emu::new().unwrap();
        owner.map_code(CODE_BASE, &[0x90; 0x40]).unwrap();
        write_cpu_state(&mut owner, &owner_captured);
        let mut context = owner.capture_cpu_context().unwrap();
        write_cpu_state(&mut owner, &owner_poison);

        let mut foreign = Emu::new().unwrap();
        foreign.map_code(CODE_BASE, &[0x90; 0x40]).unwrap();
        write_cpu_state(&mut foreign, &foreign_destination);

        assert!(matches!(
            foreign.save_cpu_context(&mut context),
            Err(EmuError::ForeignCpuContext)
        ));
        assert_cpu_state(&foreign, &foreign_destination);

        assert!(matches!(
            foreign.restore_cpu_context(&context),
            Err(EmuError::ForeignCpuContext)
        ));
        assert_cpu_state(&foreign, &foreign_destination);

        owner.restore_cpu_context(&context).unwrap();
        assert_cpu_state(&owner, &owner_captured);
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
    fn write_mem_writable_stack_roundtrip() {
        let mut emu = Emu::new().unwrap();
        let address = STACK_BASE + 0x100;
        emu.write_mem(address, &[1, 2, 3, 4]).unwrap();
        assert_eq!(emu.read_mem(address, 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn map_zeroed_rw_maps_writable_non_executable_pages() {
        let mut emu = Emu::new().unwrap();
        let base = 0x0000_0000_0700_0000;
        emu.map_zeroed_rw(base, PAGE_SIZE * 2).unwrap();

        assert_eq!(emu.read_mem(base, 16).unwrap(), vec![0; 16]);
        assert_eq!(emu.read_mem(base + PAGE_SIZE - 8, 16).unwrap(), vec![0; 16]);

        let address = base + PAGE_SIZE - 2;
        emu.write_mem(address, &[1, 2, 3, 4]).unwrap();
        assert_eq!(emu.read_mem(address, 4).unwrap(), vec![1, 2, 3, 4]);

        let report = emu.run_observed(base, 1).unwrap();
        assert_eq!(
            report.stop_reason,
            StopReason::MemoryFault(super::MemFault {
                kind: FaultKind::FetchProt,
                address: base,
            })
        );
    }

    #[test]
    fn write_mem_rejects_readonly_mapping() {
        let mut emu = Emu::new().unwrap();
        emu.map_readonly(CODE_BASE, &[0; 8]).unwrap();
        assert!(matches!(
            emu.write_mem(CODE_BASE, &[1]),
            Err(EmuError::WriteProt { .. })
        ));
    }

    #[test]
    fn write_mem_rejects_unmapped_range() {
        let mut emu = Emu::new().unwrap();
        let address = 0x0000_0000_1234_5000;
        assert!(matches!(
            emu.write_mem(address, &[1]),
            Err(EmuError::WriteUnmapped { .. })
        ));
    }

    #[test]
    fn write_mem_handles_adjacent_writable_regions() {
        let mut emu = Emu::new().unwrap();
        let base = 0x0000_0000_0800_0000;
        map_region(&mut emu.uc, base, PAGE_SIZE, Prot::READ | Prot::WRITE).unwrap();
        map_region(
            &mut emu.uc,
            base + PAGE_SIZE,
            PAGE_SIZE,
            Prot::READ | Prot::WRITE,
        )
        .unwrap();
        let address = base + PAGE_SIZE - 2;
        emu.write_mem(address, &[1, 2, 3, 4]).unwrap();
        assert_eq!(emu.read_mem(address, 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn write_mem_rejects_crossing_protected_range_without_partial_write() {
        let mut emu = Emu::new().unwrap();
        let base = 0x0000_0000_0900_0000;
        map_region(&mut emu.uc, base, PAGE_SIZE, Prot::READ | Prot::WRITE).unwrap();
        map_region(&mut emu.uc, base + PAGE_SIZE, PAGE_SIZE, Prot::READ).unwrap();
        let address = base + PAGE_SIZE - 2;
        assert!(matches!(
            emu.write_mem(address, &[1, 2, 3, 4]),
            Err(EmuError::WriteProt { .. })
        ));
        assert_eq!(emu.read_mem(address, 2).unwrap(), vec![0, 0]);
    }

    #[test]
    fn write_mem_rejects_crossing_unmapped_gap_without_partial_write() {
        let mut emu = Emu::new().unwrap();
        let base = 0x0000_0000_0a00_0000;
        map_region(&mut emu.uc, base, PAGE_SIZE, Prot::READ | Prot::WRITE).unwrap();
        let address = base + PAGE_SIZE - 2;
        emu.write_mem(address, &[0xaa, 0xbb]).unwrap();
        assert!(matches!(
            emu.write_mem(address, &[1, 2, 3, 4]),
            Err(EmuError::WriteUnmapped { .. })
        ));
        assert_eq!(emu.read_mem(address, 2).unwrap(), vec![0xaa, 0xbb]);
    }

    #[test]
    fn write_mem_rejects_address_range_overflow() {
        let mut emu = Emu::new().unwrap();
        let base = u64::MAX - 1;
        assert!(matches!(
            emu.write_mem(base, &[1, 2]),
            Err(EmuError::WriteUnmapped { addr, size: 2 }) if addr == base
        ));
        assert!(matches!(
            emu.write_mem(base, &[1, 2, 3]),
            Err(EmuError::AddressRangeOverflow {
                base: value,
                size: 3
            }) if value == base
        ));
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
    fn map_readonly_maps_readable_non_executable_memory() {
        let bytes = [0x90, 0x90, 0x90, 0x90];
        let mut emu = Emu::new().unwrap();
        emu.map_readonly(CODE_BASE, &bytes).unwrap();

        assert_eq!(emu.read_mem(CODE_BASE, bytes.len()).unwrap(), bytes);

        emu.write_reg(RegisterX86::RIP, CODE_BASE).unwrap();
        let report = emu.run_observed(CODE_BASE, 16).unwrap();

        match &report.stop_reason {
            StopReason::MemoryFault(fault) => {
                assert_eq!(fault.kind, FaultKind::FetchProt);
                assert_eq!(fault.address, CODE_BASE);
            }
            other => panic!("expected memory fault, got {other:?}"),
        }
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
    fn run_traced_captures_window() {
        let shellcode = [
            0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, // mov rax, 0x1122334455667788
            0x48, 0x89, 0x44, 0x24, 0xf8, // mov [rsp-8], rax
            0x48, 0x8b, 0x5c, 0x24, 0xf8, // mov rbx, [rsp-8]
            0x90, // nop
        ];

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();
        let stack_slot = emu.read_reg(RegisterX86::RSP).unwrap() - 8;

        let (report, trace_events) = emu.run_traced(CODE_BASE, 4, 4).unwrap();

        assert_eq!(report.stop_reason, StopReason::ReachedInstructionCap);
        assert_eq!(report.instructions_executed, 4);
        assert!(trace_events
            .iter()
            .any(|event| matches!(event, TraceEvent::Insn { address } if *address == CODE_BASE)));
        assert!(trace_events.iter().any(|event| {
            matches!(
                event,
                TraceEvent::MemWrite {
                    address,
                    size,
                    value,
                } if *address == stack_slot
                    && *size == 8
                    && (*value & trace_value_mask(*size)) == 0x1122_3344_5566_7788
            )
        }));
        assert!(trace_events.iter().any(|event| {
            matches!(
                event,
                TraceEvent::MemRead {
                    address,
                    size,
                    value,
                } if *address == stack_slot
                    && *size == 8
                    && (*value & trace_value_mask(*size)) == 0x1122_3344_5566_7788
            )
        }));
    }

    #[test]
    fn run_watching_records_access_overlapping_an_interior_watched_byte() {
        let shellcode = [
            0x48, 0xb8, 0xbe, 0xba, 0xfe, 0xca, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xCAFEBABE
            0x48, 0x89, 0x44, 0x24, 0xf0, // mov [rsp-16], rax
            0x48, 0x8b, 0x5c, 0x24, 0xf0, // mov rbx, [rsp-16]
            0x90, // nop
        ];

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();
        let stack_slot = emu.read_reg(RegisterX86::RSP).unwrap() - 16;

        let (report, watch_hits) = emu
            .run_watching(CODE_BASE, 4, &[(stack_slot + 4, stack_slot + 5)], 8)
            .unwrap();

        assert_eq!(report.stop_reason, StopReason::ReachedInstructionCap);
        assert!(watch_hits.iter().any(|hit| {
            hit.address == stack_slot
                && hit.is_write
                && hit.instruction_index != 0
                && (CODE_BASE..CODE_BASE + shellcode.len() as u64).contains(&hit.rip)
        }));
        assert!(watch_hits.iter().any(|hit| {
            hit.address == stack_slot
                && !hit.is_write
                && hit.instruction_index != 0
                && (CODE_BASE..CODE_BASE + shellcode.len() as u64).contains(&hit.rip)
        }));
    }

    #[test]
    fn persistent_watch_survives_resume_legs_and_records_values() {
        let marker = 0x1234_5678_9abc_def0;
        let stored_value = 0x1122_3344_5566_7788;
        let shellcode = persistent_watch_shellcode(marker, stored_value);

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();
        let rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let zero_slot = rsp - 8;
        let value_slot = rsp - 16;

        emu.configure_persistent_watch(
            &[
                (zero_slot + 4, zero_slot + 5),
                (value_slot + 4, value_slot + 8),
            ],
            8,
        )
        .unwrap();

        let first_report = emu.resume(CODE_BASE, 3).unwrap();
        assert_eq!(first_report.stop_reason, StopReason::ReachedInstructionCap);
        let first_hits = emu.persistent_watch_hits();
        assert_eq!(first_hits.len(), 2);
        assert_eq!(first_hits[0].address, zero_slot);
        assert!(first_hits[0].is_write);
        assert_eq!(first_hits[0].value, Some(0));
        assert_eq!(first_hits[0].registers.len(), REGISTER_SNAPSHOT_ORDER.len());
        assert_eq!(first_hits[1].address, zero_slot);
        assert!(!first_hits[1].is_write);
        assert_eq!(first_hits[1].value, Some(0));
        assert!(first_hits[0].global_instruction_index < first_hits[1].global_instruction_index);
        assert_eq!(
            register_value(&first_hits[0].registers, RegisterX86::R9),
            Some(marker)
        );
        assert_eq!(
            register_value(&first_hits[0].registers, RegisterX86::RSP),
            Some(rsp)
        );

        let second_report = emu.resume(first_report.final_rip, 3).unwrap();
        assert_eq!(second_report.stop_reason, StopReason::ReachedInstructionCap);
        let all_hits = emu.persistent_watch_hits();
        assert_eq!(all_hits.len(), 4);
        assert_eq!(&all_hits[..2], &first_hits[..]);
        assert_eq!(all_hits[2].address, value_slot);
        assert!(all_hits[2].is_write);
        assert_eq!(all_hits[2].value, Some(stored_value));
        assert_eq!(all_hits[3].address, value_slot);
        assert!(!all_hits[3].is_write);
        assert_eq!(all_hits[3].value, Some(stored_value));
        assert!(all_hits[1].global_instruction_index < all_hits[2].global_instruction_index);
        assert!(all_hits
            .iter()
            .all(|hit| (CODE_BASE..CODE_BASE + shellcode.len() as u64).contains(&hit.rip)));

        emu.clear_persistent_watch_hits();
        assert!(emu.persistent_watch_hits().is_empty());
    }

    #[test]
    fn persistent_watch_hit_cap_is_honored_across_resume_legs() {
        let shellcode = persistent_watch_shellcode(0x99, 0x88);

        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &shellcode).unwrap();
        let rsp = emu.read_reg(RegisterX86::RSP).unwrap();

        emu.configure_persistent_watch(&[(rsp - 16, rsp)], 3)
            .unwrap();

        let first_report = emu.resume(CODE_BASE, 3).unwrap();
        assert_eq!(emu.persistent_watch_hits().len(), 2);

        emu.resume(first_report.final_rip, 3).unwrap();
        let hits = emu.persistent_watch_hits();
        assert_eq!(hits.len(), 3);
        assert!(hits[0].global_instruction_index < hits[1].global_instruction_index);
        assert!(hits[1].global_instruction_index < hits[2].global_instruction_index);
    }

    #[test]
    fn access_overlap_covers_interior_adjacent_empty_reversed_and_overflow_ranges() {
        assert!(access_overlaps_ranges(0x1000, 8, &[(0x1004, 0x1005)]));
        assert!(!access_overlaps_ranges(0x1000, 8, &[(0x0fff, 0x1000)]));
        assert!(!access_overlaps_ranges(0x1000, 8, &[(0x1008, 0x1009)]));
        assert!(!access_overlaps_ranges(0x1000, 8, &[(0x1004, 0x1004)]));
        assert!(!access_overlaps_ranges(0x1000, 8, &[(0x1005, 0x1004)]));

        assert!(access_overlaps_ranges(
            u64::MAX - 3,
            8,
            &[(u64::MAX - 2, u64::MAX)]
        ));
        assert!(!access_overlaps_ranges(
            u64::MAX - 3,
            8,
            &[(0x1000, 0x2000)]
        ));
    }

    #[test]
    fn persistent_watch_value_helpers_preserve_zero_through_eight_and_reject_wider() {
        let value = 0x1122_3344_5566_7788_u64;
        let mut emu = Emu::new().unwrap();
        emu.write_mem(STACK_BASE, &value.to_le_bytes()).unwrap();

        for size in 0..=8 {
            let expected = if size == 0 {
                0
            } else if size == 8 {
                value
            } else {
                value & ((1_u64 << (size * 8)) - 1)
            };
            assert_eq!(write_hook_value_opt(value, size), Some(expected));
            assert_eq!(
                read_hook_value_opt(&emu.uc, STACK_BASE, size),
                Some(expected)
            );
        }

        assert_eq!(write_hook_value_opt(value, 9), None);
        assert_eq!(read_hook_value_opt(&emu.uc, STACK_BASE, 9), None);
        assert_eq!(read_hook_value_opt(&emu.uc, 0xdead_beef, 8), None);
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

    #[test]
    fn map_image_sets_peb_image_base() {
        let bytes = minimal_pe64_with_text_pattern();
        let image = pe::PeImage::parse(&bytes).unwrap();

        let mut emu = Emu::new().unwrap();
        emu.map_image(&image, &bytes, image.image_base).unwrap();

        assert_eq!(
            read_u64_le(&emu.read_mem(PEB_BASE + PEB_IMAGEBASE_OFFSET, 8).unwrap()),
            image.image_base
        );
    }
}
