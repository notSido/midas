//! Bounded diagnostic for the first runnable-unscheduled thread recorded by
//! the Win64 environment.
//!
//! This is not a scheduler or a Windows thread-start model. It runs a recorded
//! start address under explicit diagnostic-only stack/TEB conditions, restores
//! the stopped main CPU context, and gives terminal control transfers no
//! lifecycle meaning.
//!
//! `--production-terminal` is an additive exception to that hand-driven path:
//! it observes the production cooperative scheduler and retains a bounded
//! hook-time terminal tail without assigning lifecycle meaning to the stop.

use std::{env, fs, process};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, InstructionInfoFactory, NasmFormatter, OpAccess,
    OpKind, Register,
};
use midas::{
    emu::{
        Emu, EmuError, FrozenInstruction, PersistentWatchHit, RegisterX86, PEB_BASE, STACK_BASE,
        STACK_SIZE, TEB_BASE, TEB_PEB_OFFSET, TEB_SELF_OFFSET, TEB_SIZE, TEB_STACKBASE_OFFSET,
        TEB_STACKLIMIT_OFFSET,
    },
    pe::PeImage,
    win64::{
        run_with_cooperative_scheduler, run_with_import_trap, CooperativeTrapRun,
        RunnableUnscheduledThread, TrapRun, TrapStop, Win64Env,
    },
};

const DEFAULT_MAIN_PER_LEG_CAP: u64 = 60_000_000;
const DEFAULT_CHILD_PER_LEG_CAP: u64 = 100_000;
const MAX_CHILD_PER_LEG_CAP: u64 = 100_000;
const MAX_POLL_MAIN_TRACE_CAP: u64 = 1_000_000;
const DEFAULT_WATCH_HIT_CAP: usize = 4_096;
const MAX_WATCH_HIT_CAP: usize = 16_384;
const FROZEN_PATH_INSTRUCTION_CAP: usize = 4;
const PRODUCER_WATCH_INSTRUCTION_WINDOW: u64 = 4_096;
const MAIN_API_BOUND: usize = 128;
const CHILD_PREFIX_API_BOUND: usize = 16;
const CHILD_TAIL_API_BOUND: usize = 16;
const POST_POLL_API_BOUND: usize = 16;
const POST_POLL_TAIL_LEN: usize = 64;
const POST_POLL_API_NAME: &str = "GetCommandLineA";
const POST_CREATE_CHILD_API_NAME: &str = "RtlFreeHeap";
const PRODUCTION_API_BOUND: usize = 200;
const PRODUCTION_TERMINAL_SUFFIX_TRACE_CAP: u64 = 1_000_000;
const PRODUCTION_TERMINAL_TAIL_LEN: usize = 64;

const CHILD_STACK_BASE: u64 = 0x0000_000f_5000_0000;
const CHILD_STACK_SIZE: u64 = 0x0010_0000;
const CHILD_TEB_BASE: u64 = 0x0000_000f_5100_0000;
const CHILD_TEB_SIZE: u64 = 0x1000;
const CHILD_ENTRY_HEADROOM: u64 = 0x1000;
const CHILD_RETURN_SENTINEL: u64 = 0x0000_000e_dead_0000;
const DIAGNOSTIC_WINDOW_HANDLE: u64 = 0x0000_000f_3000_0020;

const DISPLAY_REGISTERS: [(RegisterX86, &str); 18] = [
    (RegisterX86::RAX, "rax"),
    (RegisterX86::RBX, "rbx"),
    (RegisterX86::RCX, "rcx"),
    (RegisterX86::RDX, "rdx"),
    (RegisterX86::RSI, "rsi"),
    (RegisterX86::RDI, "rdi"),
    (RegisterX86::RBP, "rbp"),
    (RegisterX86::RSP, "rsp"),
    (RegisterX86::R8, "r8"),
    (RegisterX86::R9, "r9"),
    (RegisterX86::R10, "r10"),
    (RegisterX86::R11, "r11"),
    (RegisterX86::R12, "r12"),
    (RegisterX86::R13, "r13"),
    (RegisterX86::R14, "r14"),
    (RegisterX86::R15, "r15"),
    (RegisterX86::RIP, "rip"),
    (RegisterX86::EFLAGS, "rflags"),
];

const CPU_STATE_REGISTERS: [RegisterX86; 20] = [
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
];

const CHILD_ZERO_REGISTERS: [RegisterX86; 15] = [
    RegisterX86::RAX,
    RegisterX86::RBX,
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
];

#[derive(Debug, Clone)]
struct Config {
    path: String,
    main_per_leg_cap: u64,
    child_per_leg_cap: u64,
    watch_hit_cap: usize,
    export_name_control: Option<ExportNameControl>,
    frontier_only: bool,
    poll_window_only: bool,
    production_terminal_only: bool,
}

#[derive(Debug, Clone)]
struct ExportNameControl {
    module_name: String,
    names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChildTerminal {
    NullControlTransfer,
    ReturnSentinel,
    UnhandledApi { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalTransfer {
    NearReturn {
        instruction_address: u64,
    },
    IndirectCall {
        instruction_address: u64,
        pointer_cell: u64,
        pushed_return_address: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchPhase {
    BeforeMain,
    CaptureMainLegWriting {
        address: u64,
        writer_rip: u64,
        global_instruction_index: u64,
        value: u64,
    },
    BeforeTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchSpec {
    ranges: Vec<(u64, u64)>,
    phase: WatchPhase,
    global_instruction_range: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalSource {
    writer_rip: u64,
    writer_global_instruction_index: u64,
    bytecode_cursor: u64,
    selector_address: u64,
    selector: u16,
    context_address: u64,
    handler_slot: u64,
    handler_value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HandlerWriterSource {
    writer_rip: u64,
    writer_global_instruction_index: u64,
    vm_context_base: u64,
    selector_field_address: u64,
    source_selector: u16,
    source_context_address: u64,
    source_value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceContextProducer {
    writer_rip: u64,
    writer_global_instruction_index: u64,
    context_address: u64,
    value: u64,
    stack_cell: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackCellProducer {
    writer_rip: u64,
    writer_global_instruction_index: u64,
    destination_cell: u64,
    value: u64,
    source_cell: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RaxStackProducer {
    path_start_rip: u64,
    path_start_global_instruction_index: u64,
    value: u64,
}

#[derive(Debug, Clone)]
struct FormattedWatchHit {
    hit: PersistentWatchHit,
    instruction: String,
    fallthrough: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionTerminalTransfer {
    NearReturn {
        global_instruction_index: u64,
        instruction_address: u64,
        consumed_cell: u64,
        target_value: u64,
    },
    RegisterCall(RegisterCallTerminal),
    IndirectCall {
        global_instruction_index: u64,
        instruction_address: u64,
        pointer_cell: u64,
        target_value: u64,
        pushed_return_cell: u64,
        pushed_return_address: u64,
    },
}

impl ProductionTerminalTransfer {
    fn instruction_address(self) -> u64 {
        match self {
            Self::NearReturn {
                instruction_address,
                ..
            }
            | Self::IndirectCall {
                instruction_address,
                ..
            } => instruction_address,
            Self::RegisterCall(call) => call.instruction_address,
        }
    }

    fn global_instruction_index(self) -> u64 {
        match self {
            Self::NearReturn {
                global_instruction_index,
                ..
            }
            | Self::IndirectCall {
                global_instruction_index,
                ..
            } => global_instruction_index,
            Self::RegisterCall(call) => call.global_instruction_index,
        }
    }

    fn target_value(self) -> u64 {
        match self {
            Self::NearReturn { target_value, .. } | Self::IndirectCall { target_value, .. } => {
                target_value
            }
            Self::RegisterCall(call) => call.target_value,
        }
    }

    fn consumed_cell(self) -> Option<u64> {
        match self {
            Self::NearReturn { consumed_cell, .. } => Some(consumed_cell),
            Self::RegisterCall(_) | Self::IndirectCall { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
struct ProductionConsumedCellEdge {
    writer: FormattedWatchHit,
    consumer: FormattedWatchHit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FormattedInstruction {
    global_instruction_index: u64,
    address: u64,
    instruction: String,
    writes_r13: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MainPollObservation {
    address: u64,
    compare_rip: u64,
    compared_value: u8,
    value_at_sleep: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreateWindowExAObservation {
    return_address: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisterCallTerminal {
    global_instruction_index: u64,
    instruction_address: u64,
    target_register: Register,
    target_value: u64,
    pushed_return_cell: u64,
    pushed_return_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZeroTargetProvenance {
    source_cell: u64,
    source_read_rip: u64,
    source_read_global_instruction_index: u64,
    source_value: u64,
    zero_writer_rip: u64,
    zero_writer_global_instruction_index: u64,
    zero_writer_input: u64,
    zero_writer_output: u64,
    zero_writer_instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticBoundary {
    Natural(TrapStop),
    PendingApi { name: String },
}

#[derive(Debug, Clone)]
struct PollWindowControls {
    baseline: ExportNameControl,
    treatment: ExportNameControl,
    added_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostPollTerminalObservation {
    boundary: DiagnosticBoundary,
    pending_api: Option<String>,
    pending_address: Option<u64>,
    call: Option<RegisterCallTerminal>,
    tail_rips: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostPollAbInvariant {
    baseline_call: RegisterCallTerminal,
    treatment_target: u64,
    tail_digest: u64,
}

#[derive(Debug, Clone)]
struct PollWindowEvidence {
    poll: MainPollObservation,
    main_prefix_handled: Vec<String>,
    thread_id: u32,
    thread: RunnableUnscheduledThread,
    child_handled: Vec<String>,
    create_window: CreateWindowExAObservation,
    window_procedure: u64,
    post_create_handled: Vec<String>,
    post_create_boundary: DiagnosticBoundary,
    post_create_rips: Vec<u64>,
    hits: Vec<FormattedWatchHit>,
    post_create_hit_start: usize,
    post_create_hit_end: usize,
    release_writer_index: Option<usize>,
    poll_final: u8,
    main_boundary: DiagnosticBoundary,
    main_handled: Vec<String>,
    main_pending_api: Option<String>,
    main_pending_address: Option<u64>,
    restored_main_cap: u64,
    main_rips: Vec<u64>,
    main_tail_instructions: Vec<FormattedInstruction>,
    main_terminal_call: Option<RegisterCallTerminal>,
    zero_target_provenance: Option<ZeroTargetProvenance>,
    instructions_past_poll: usize,
}

struct SummaryEvidence<'a> {
    terminal_watch: &'a PassEvidence,
    handler_writer: HandlerWriterSource,
    handler_watch: &'a PassEvidence,
    source_watch: &'a PassEvidence,
    source_producer: SourceContextProducer,
    stack_watch: &'a PassEvidence,
    stack_producer: StackCellProducer,
    upstream_stack_watch: &'a PassEvidence,
    rax_producer: RaxStackProducer,
}

#[derive(Debug, Clone)]
struct PassEvidence {
    main_handled: Vec<String>,
    thread_id: u32,
    thread: RunnableUnscheduledThread,
    entry_rsp: u64,
    child_prefix_handled: Vec<String>,
    time_return_address: u64,
    child_tail_handled: Vec<String>,
    registered_window_procedures: Vec<(u16, u64)>,
    window_procedure_trace_edges: Vec<(u64, Option<u64>)>,
    synthetic_module_image_ranges: Vec<(String, u64, u64)>,
    terminal: ChildTerminal,
    terminal_transfer: TerminalTransfer,
    terminal_registers: Vec<(RegisterX86, u64)>,
    terminal_stack_qwords: Vec<u64>,
    terminal_cell: u64,
    terminal_value: u64,
    child_rips: Vec<u64>,
    post_time_rips: Vec<u64>,
    tail_instructions: Vec<FormattedInstruction>,
    watch_spec: Option<WatchSpec>,
    watch_hits: Vec<FormattedWatchHit>,
    terminal_source: Option<TerminalSource>,
    main_stack_unchanged: bool,
    main_teb_unchanged: bool,
    main_cpu_restored: bool,
    main_sleep_handled: Vec<String>,
    main_sleep_rips: Vec<u64>,
}

impl PassEvidence {
    fn release_replay_traces(&mut self) {
        self.child_rips = Vec::new();
        self.post_time_rips = Vec::new();
        self.main_sleep_rips = Vec::new();
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = parse_args()?;
    let bytes = fs::read(&config.path)
        .map_err(|error| format!("failed to read {:?}: {error}", config.path))?;
    let image = PeImage::parse(&bytes)
        .map_err(|error| format!("failed to parse {:?}: {error}", config.path))?;

    if config.production_terminal_only {
        run_production_terminal(&config, &image, &bytes)?;
        return Ok(());
    }

    if config.poll_window_only {
        if config.export_name_control.is_some() {
            return Err(
                "--poll-window owns its frozen kernel32 baseline/treatment controls".to_owned(),
            );
        }
        let controls = frozen_poll_window_controls()?;
        let mut baseline_config = config.clone();
        baseline_config.export_name_control = Some(controls.baseline.clone());
        let poll = discover_main_poll(&baseline_config, &image, &bytes)?;
        let baseline = run_poll_window_return(&baseline_config, &image, &bytes, poll, None)?;

        let mut treatment_config = config.clone();
        treatment_config.export_name_control = Some(controls.treatment.clone());
        let treatment = run_poll_window_return(
            &treatment_config,
            &image,
            &bytes,
            poll,
            Some(&controls.added_name),
        )?;
        let invariant = validate_post_poll_ab(
            &post_poll_terminal_observation(&baseline),
            &post_poll_terminal_observation(&treatment),
            &controls.added_name,
        )?;
        print_poll_window_summary(&config, &image, &baseline, &controls, &invariant);
        return Ok(());
    }
    let first = run_pass(&config, &image, &bytes, None)?;
    if config.frontier_only {
        print_frontier_only_summary(&config, &image, &first);
        return Ok(());
    }
    let watch_end = first.terminal_cell.checked_add(8).ok_or_else(|| {
        format!(
            "terminal watch range overflows at {:#x}",
            first.terminal_cell
        )
    })?;
    if matches!(
        first.terminal_transfer,
        TerminalTransfer::IndirectCall { .. }
    ) {
        let mut whole_run = run_pass(
            &config,
            &image,
            &bytes,
            Some(WatchSpec {
                ranges: vec![(first.terminal_cell, watch_end)],
                phase: WatchPhase::BeforeMain,
                global_instruction_range: None,
            }),
        )?;
        compare_passes(&first, &whole_run)?;
        whole_run.release_replay_traces();
        validate_watched_replay(&whole_run, config.watch_hit_cap)?;
        let writer_index = validate_indirect_call_frontier(&whole_run)?;
        let module_watch = if config.export_name_control.is_some() {
            None
        } else if let Some(writer_index) = writer_index {
            let writer = &whole_run.watch_hits[writer_index].hit;
            let mut ranges = first
                .synthetic_module_image_ranges
                .iter()
                .map(|(_, start, end)| (*start, *end))
                .collect::<Vec<_>>();
            ranges.push((first.terminal_cell, watch_end));
            let mut module_config = config.clone();
            module_config.watch_hit_cap = MAX_WATCH_HIT_CAP;
            let mut pass = run_pass(
                &module_config,
                &image,
                &bytes,
                Some(WatchSpec {
                    ranges,
                    phase: WatchPhase::CaptureMainLegWriting {
                        address: first.terminal_cell,
                        writer_rip: writer.rip,
                        global_instruction_index: writer.global_instruction_index,
                        value: first.terminal_value,
                    },
                    global_instruction_range: None,
                }),
            )?;
            compare_passes(&first, &pass)?;
            pass.release_replay_traces();
            validate_watched_replay(&pass, module_config.watch_hit_cap)?;
            Some(pass)
        } else {
            None
        };
        print_indirect_call_frontier_summary(
            &config,
            &image,
            &first,
            &whole_run,
            writer_index,
            module_watch.as_ref(),
        );
        return Ok(());
    }

    let mut second = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![(first.terminal_cell, watch_end)],
            phase: WatchPhase::BeforeTime,
            global_instruction_range: None,
        }),
    )?;

    compare_passes(&first, &second)?;
    second.release_replay_traces();
    validate_watched_replay(&second, config.watch_hit_cap)?;
    let terminal_source = second.terminal_source.ok_or_else(|| {
        "terminal-cell replay did not expose the dispatcher source chain".to_owned()
    })?;
    let handler_watch_end = terminal_source.handler_slot.checked_add(8).ok_or_else(|| {
        format!(
            "handler-slot watch range overflows at {:#x}",
            terminal_source.handler_slot
        )
    })?;
    let mut third = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![(terminal_source.handler_slot, handler_watch_end)],
            phase: WatchPhase::BeforeMain,
            global_instruction_range: None,
        }),
    )?;
    compare_passes(&first, &third)?;
    third.release_replay_traces();
    validate_watched_replay(&third, config.watch_hit_cap)?;
    validate_handler_slot_replay(&third, terminal_source)?;
    validate_terminal_register_path(&third, terminal_source)?;
    let handler_writer_source =
        derive_handler_writer_source(&third, terminal_source)?.ok_or_else(|| {
            "handler-slot replay did not expose a prior whole-qword writer".to_owned()
        })?;
    let selector_watch_end = handler_writer_source
        .selector_field_address
        .checked_add(2)
        .ok_or_else(|| "source-selector watch range overflows".to_owned())?;
    let source_watch_end = handler_writer_source
        .source_context_address
        .checked_add(8)
        .ok_or_else(|| "source-context watch range overflows".to_owned())?;
    let mut fourth = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![
                (
                    handler_writer_source.selector_field_address,
                    selector_watch_end,
                ),
                (
                    handler_writer_source.source_context_address,
                    source_watch_end,
                ),
                (terminal_source.handler_slot, handler_watch_end),
            ],
            phase: WatchPhase::CaptureMainLegWriting {
                address: terminal_source.handler_slot,
                writer_rip: handler_writer_source.writer_rip,
                global_instruction_index: handler_writer_source.writer_global_instruction_index,
                value: handler_writer_source.source_value,
            },
            global_instruction_range: None,
        }),
    )?;
    compare_passes(&first, &fourth)?;
    fourth.release_replay_traces();
    validate_watched_replay(&fourth, config.watch_hit_cap)?;
    let source_edge_indices =
        validated_source_edge_indices(&fourth, terminal_source, handler_writer_source)?;
    let source_producer =
        derive_source_context_producer(&fourth, handler_writer_source, source_edge_indices[2])?;
    let stack_watch_end = source_producer
        .stack_cell
        .checked_add(8)
        .ok_or_else(|| "source stack-cell watch range overflows".to_owned())?;
    let mut fifth = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![
                (source_producer.stack_cell, stack_watch_end),
                (
                    handler_writer_source.source_context_address,
                    source_watch_end,
                ),
            ],
            phase: WatchPhase::CaptureMainLegWriting {
                address: source_producer.context_address,
                writer_rip: source_producer.writer_rip,
                global_instruction_index: source_producer.writer_global_instruction_index,
                value: source_producer.value,
            },
            global_instruction_range: None,
        }),
    )?;
    compare_passes(&first, &fifth)?;
    fifth.release_replay_traces();
    validate_watched_replay(&fifth, config.watch_hit_cap)?;
    let stack_producer = validate_source_stack_edge(&fifth, source_producer)?;
    let upstream_stack_watch_end = stack_producer
        .source_cell
        .checked_add(8)
        .ok_or_else(|| "upstream stack-cell watch range overflows".to_owned())?;
    let upstream_watch_global_end = stack_producer
        .writer_global_instruction_index
        .checked_add(1)
        .ok_or_else(|| "upstream producer watch range overflows".to_owned())?;
    let upstream_watch_global_start =
        upstream_watch_global_end.saturating_sub(PRODUCER_WATCH_INSTRUCTION_WINDOW);
    let mut sixth = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![
                (stack_producer.source_cell, upstream_stack_watch_end),
                (source_producer.stack_cell, stack_watch_end),
            ],
            phase: WatchPhase::CaptureMainLegWriting {
                address: stack_producer.destination_cell,
                writer_rip: stack_producer.writer_rip,
                global_instruction_index: stack_producer.writer_global_instruction_index,
                value: stack_producer.value,
            },
            global_instruction_range: Some((
                upstream_watch_global_start,
                upstream_watch_global_end,
            )),
        }),
    )?;
    compare_passes(&first, &sixth)?;
    sixth.release_replay_traces();
    validate_watched_replay(&sixth, config.watch_hit_cap)?;
    let rax_producer = validate_stack_value_from_rax(&sixth.watch_hits, stack_producer)?;
    let summary = SummaryEvidence {
        terminal_watch: &second,
        handler_writer: handler_writer_source,
        handler_watch: &third,
        source_watch: &fourth,
        source_producer,
        stack_watch: &fifth,
        stack_producer,
        upstream_stack_watch: &sixth,
        rax_producer,
    };
    print_summary(&config, &image, &first, &summary);
    Ok(())
}

fn parse_args() -> Result<Config, String> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "trace_child_postmortem".to_owned());
    let path = args.next().ok_or_else(|| usage(&program))?;
    let mut positional = args.collect::<Vec<_>>();
    let (frontier_only, poll_window_only, production_terminal_only) =
        parse_trailing_modes(&mut positional)?;
    let main_per_leg_cap = parse_optional(
        positional.first().cloned(),
        DEFAULT_MAIN_PER_LEG_CAP,
        "main-cap",
    )?;
    let child_per_leg_cap = parse_optional(
        positional.get(1).cloned(),
        DEFAULT_CHILD_PER_LEG_CAP,
        "child-cap",
    )?;
    let watch_hit_cap = validate_hit_cap(parse_optional(
        positional.get(2).cloned(),
        DEFAULT_WATCH_HIT_CAP,
        "watch-hit-cap",
    )?)?;
    let export_name_control = match positional.get(3..).unwrap_or_default() {
        [] => None,
        [module_name, names_path] => {
            let contents = fs::read_to_string(names_path).map_err(|error| {
                format!("failed to read export-name control {names_path:?}: {error}")
            })?;
            let names = parse_export_name_control(&contents)?;
            Some(ExportNameControl {
                module_name: module_name.to_owned(),
                names,
            })
        }
        _ => return Err(usage(&program)),
    };
    if main_per_leg_cap == 0 || child_per_leg_cap == 0 {
        return Err("instruction caps must be nonzero".to_owned());
    }
    if child_per_leg_cap > MAX_CHILD_PER_LEG_CAP {
        return Err(format!(
            "child-cap {child_per_leg_cap} exceeds maximum {MAX_CHILD_PER_LEG_CAP}; child RIPs are retained"
        ));
    }
    Ok(Config {
        path,
        main_per_leg_cap,
        child_per_leg_cap,
        watch_hit_cap,
        export_name_control,
        frontier_only,
        poll_window_only,
        production_terminal_only,
    })
}

fn parse_trailing_modes(positional: &mut Vec<String>) -> Result<(bool, bool, bool), String> {
    let mut frontier_only = false;
    let mut poll_window_only = false;
    let mut production_terminal_only = false;
    let mut mode_count = 0usize;
    while let Some(argument) = positional.last() {
        let selected = match argument.as_str() {
            "--frontier-only" if !frontier_only => {
                frontier_only = true;
                true
            }
            "--poll-window" if !poll_window_only => {
                poll_window_only = true;
                true
            }
            "--production-terminal" if !production_terminal_only => {
                production_terminal_only = true;
                true
            }
            "--frontier-only" | "--poll-window" | "--production-terminal" => {
                return Err(format!("duplicate diagnostic mode {argument}"));
            }
            _ => false,
        };
        if !selected {
            break;
        }
        positional.pop();
        mode_count += 1;
    }
    if mode_count > 1 {
        return Err(
            "--frontier-only, --poll-window, and --production-terminal are mutually exclusive"
                .to_owned(),
        );
    }
    Ok((frontier_only, poll_window_only, production_terminal_only))
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} <pe> [main-per-leg-cap] [child-per-leg-cap] [watch-hit-cap]\n\
         [export-control-module export-name-list] [--frontier-only|--poll-window|--production-terminal]\n\
         the diagnostic derives the pending Sleep, created thread, and timeGetTime stub at runtime;\n\
         an optional newline-delimited name list changes one synthetic module's names only;\n\
         --frontier-only prints the first child terminal without provenance replays;\n\
         --poll-window rejects an external name control, runs the frozen kernel32 A/B controls,\n\
         returns a diagnostic nonzero HWND at the confirmed CreateWindowExA boundary, and watches the child/main suffix;\n\
         --production-terminal replays the exact production cooperative scheduler and freezes its terminal 64-instruction tail"
    )
}

fn run_production_terminal(config: &Config, image: &PeImage, bytes: &[u8]) -> Result<(), String> {
    let (mut discovery_emu, mut discovery_env) = new_production_runtime(config, image, bytes)?;
    let discovery = run_with_cooperative_scheduler(
        &mut discovery_env,
        &mut discovery_emu,
        image,
        image.entry_point_va(),
        config.main_per_leg_cap,
        PRODUCTION_API_BOUND,
    )
    .map_err(|error| format!("failed to run production terminal discovery: {error}"))?;
    require_export_control_applied(config, &discovery_env, "production discovery")?;
    let discovery_total = discovery_emu.total_instructions_executed();
    if discovery.handled.is_empty() {
        return Err("production terminal discovery handled no APIs".to_owned());
    }
    let synthetic_module_image_ranges = discovery_env
        .synthetic_module_image_ranges()
        .map(|(name, start, end)| (name.to_owned(), start, end))
        .collect::<Vec<_>>();
    if matches!(&discovery.stop, TrapStop::InstructionCap)
        || matches!(&discovery.stop, TrapStop::Other(message) if message == "max_calls reached")
    {
        let registers = read_cpu_state(&discovery_emu)?;
        print_production_bounded_frontier_summary(
            config,
            image,
            &discovery,
            discovery_total,
            &synthetic_module_image_ranges,
            &registers,
        );
        return Ok(());
    }

    // A fresh replay stops immediately before the final handled API, then
    // enables hook-time byte retention only for the bounded suffix. This keeps
    // the exact production scheduler semantics while avoiding an unbounded
    // all-run RIP vector merely to retain the final 64 instructions.
    let prefix_call_bound = discovery.handled.len() - 1;
    let (mut traced_emu, mut traced_env) = new_production_runtime(config, image, bytes)?;
    let prefix = run_with_cooperative_scheduler(
        &mut traced_env,
        &mut traced_emu,
        image,
        image.entry_point_va(),
        config.main_per_leg_cap,
        prefix_call_bound,
    )
    .map_err(|error| format!("failed to run production terminal prefix replay: {error}"))?;
    if !matches!(&prefix.stop, TrapStop::Other(message) if message == "max_calls reached")
        || prefix.handled != discovery.handled[..prefix_call_bound]
        || prefix.cooperative_yields != discovery.cooperative_yields
    {
        return Err(format!(
            "production terminal prefix replay diverged: handled={:?}, yields={:?}, stop={:?}",
            prefix.handled, prefix.cooperative_yields, prefix.stop
        ));
    }
    let suffix_begin = traced_emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read production suffix RIP: {error}"))?;
    traced_emu
        .install_code_trace_hook()
        .map_err(|error| format!("failed to freeze production terminal tail: {error}"))?;
    let suffix_cap = config
        .main_per_leg_cap
        .min(PRODUCTION_TERMINAL_SUFFIX_TRACE_CAP);
    let suffix = run_with_cooperative_scheduler(
        &mut traced_env,
        &mut traced_emu,
        image,
        suffix_begin,
        suffix_cap,
        PRODUCTION_API_BOUND,
    )
    .map_err(|error| format!("failed to run bounded production terminal suffix: {error}"))?;
    require_export_control_applied(config, &traced_env, "production suffix replay")?;
    if suffix.handled != discovery.handled[prefix_call_bound..]
        || !suffix.cooperative_yields.is_empty()
        || suffix.stop != discovery.stop
    {
        return Err(format!(
            "production terminal suffix replay diverged: handled={:?}, yields={:?}, stop={:?}",
            suffix.handled, suffix.cooperative_yields, suffix.stop
        ));
    }
    let traced_total = traced_emu.total_instructions_executed();
    if traced_total != discovery_total {
        return Err(format!(
            "production terminal replay instruction count diverged: discovery={discovery_total}, replay={traced_total}"
        ));
    }
    let suffix_rips = traced_emu.executed_addresses();
    if suffix_rips.len() > usize::try_from(suffix_cap).unwrap_or(usize::MAX) {
        return Err(format!(
            "production terminal suffix retained {} RIPs beyond its {suffix_cap}-instruction bound",
            suffix_rips.len()
        ));
    }
    let frozen_tail = traced_emu.recent_instructions();
    if frozen_tail.len() != PRODUCTION_TERMINAL_TAIL_LEN
        || suffix_rips.len() < PRODUCTION_TERMINAL_TAIL_LEN
    {
        return Err(format!(
            "production terminal suffix retained {} frozen and {} executed instructions; exactly {PRODUCTION_TERMINAL_TAIL_LEN} frozen tail entries are required",
            frozen_tail.len(),
            suffix_rips.len()
        ));
    }
    let terminal_registers = read_cpu_state(&traced_emu)?;
    let transfer = classify_production_terminal_transfer(
        &traced_emu,
        &discovery.stop,
        &suffix_rips,
        &terminal_registers,
        &frozen_tail,
    )?;
    if transfer.global_instruction_index() != discovery_total {
        return Err(format!(
            "production terminal global index {} differs from total instruction count {discovery_total}",
            transfer.global_instruction_index()
        ));
    }
    let tail_instructions = format_tail(&frozen_tail, &suffix_rips, PRODUCTION_TERMINAL_TAIL_LEN)?;
    let terminal_stub_name = traced_env.callable_stub_name_at(transfer.target_value());
    let consumed_edge = match transfer.consumed_cell() {
        Some(consumed_cell) => Some(replay_production_consumed_cell(
            config,
            image,
            bytes,
            &discovery,
            discovery_total,
            &tail_instructions,
            transfer,
            consumed_cell,
        )?),
        None => None,
    };

    print_production_terminal_summary(
        config,
        image,
        &discovery,
        discovery_total,
        suffix_cap,
        &synthetic_module_image_ranges,
        &terminal_registers,
        &frozen_tail,
        &tail_instructions,
        transfer,
        terminal_stub_name.as_deref(),
        consumed_edge.as_ref(),
    );
    Ok(())
}

fn new_production_runtime(
    config: &Config,
    image: &PeImage,
    bytes: &[u8],
) -> Result<(Emu, Win64Env), String> {
    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(image, bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;
    let mut env = Win64Env::new(image.image_base);
    if let Some(control) = &config.export_name_control {
        if !env.configure_module_export_name_control(&control.module_name, &control.names) {
            return Err(format!(
                "rejected export-name control for {:?}",
                control.module_name
            ));
        }
    }
    Ok((emu, env))
}

fn require_export_control_applied(
    config: &Config,
    env: &Win64Env,
    phase: &str,
) -> Result<(), String> {
    if let Some(control) = &config.export_name_control {
        if !env.module_export_name_control_was_applied(&control.module_name) {
            return Err(format!(
                "export-name control for {:?} was not applied during {phase}",
                control.module_name
            ));
        }
    }
    Ok(())
}

fn classify_production_terminal_transfer(
    emu: &Emu,
    stop: &TrapStop,
    suffix_rips: &[u64],
    terminal_registers: &[(RegisterX86, u64)],
    frozen_tail: &[FrozenInstruction],
) -> Result<ProductionTerminalTransfer, String> {
    if frozen_tail.len() != PRODUCTION_TERMINAL_TAIL_LEN {
        return Err(format!(
            "production terminal classifier requires exactly {PRODUCTION_TERMINAL_TAIL_LEN} frozen instructions, got {}",
            frozen_tail.len()
        ));
    }
    let last_rip = suffix_rips
        .last()
        .copied()
        .ok_or_else(|| "production terminal suffix is empty".to_owned())?;
    let frozen = frozen_tail
        .last()
        .filter(|entry| entry.address == last_rip)
        .ok_or_else(|| {
            "production terminal instruction lacks matching hook-time bytes".to_owned()
        })?;
    let mut decoder = Decoder::with_ip(64, &frozen.bytes, last_rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() != frozen.bytes.len() {
        return Err(format!(
            "production terminal bytes at 0x{last_rip:016x} do not decode as one exact instruction"
        ));
    }
    let final_rip = register_value(terminal_registers, RegisterX86::RIP)
        .ok_or_else(|| "production terminal snapshot is missing RIP".to_owned())?;
    let final_rsp = register_value(terminal_registers, RegisterX86::RSP)
        .ok_or_else(|| "production terminal snapshot is missing RSP".to_owned())?;

    let transfer = if matches!(instruction.code(), Code::Retnq | Code::Retnq_imm16) {
        validate_terminal_ret_instruction(&instruction, &frozen.bytes, last_rip)?;
        let consumed_cell = terminal_cell(final_rsp)?;
        let target_value = read_u64(emu, consumed_cell)?;
        ProductionTerminalTransfer::NearReturn {
            global_instruction_index: frozen.global_instruction_index,
            instruction_address: last_rip,
            consumed_cell,
            target_value,
        }
    } else if instruction.code() == Code::Call_rm64 && instruction.op0_kind() == OpKind::Register {
        let call = derive_register_call_terminal(
            emu,
            suffix_rips,
            final_rsp,
            terminal_registers,
            frozen_tail,
        )?
        .ok_or_else(|| "production register-call classifier returned no call".to_owned())?;
        ProductionTerminalTransfer::RegisterCall(call)
    } else {
        let (transfer, pointer_cell) =
            derive_terminal_transfer(emu, suffix_rips, final_rsp, terminal_registers, frozen_tail)?;
        let TerminalTransfer::IndirectCall {
            instruction_address,
            pointer_cell: derived_pointer_cell,
            pushed_return_address,
        } = transfer
        else {
            return Err(format!(
                "unsupported production terminal instruction {}",
                format_instruction(&instruction)
            ));
        };
        if derived_pointer_cell != pointer_cell {
            return Err("production indirect-call pointer-cell derivation disagrees".to_owned());
        }
        ProductionTerminalTransfer::IndirectCall {
            global_instruction_index: frozen.global_instruction_index,
            instruction_address,
            pointer_cell,
            target_value: read_u64(emu, pointer_cell)?,
            pushed_return_cell: final_rsp,
            pushed_return_address,
        }
    };
    if final_rip != transfer.target_value() {
        return Err(format!(
            "production terminal target 0x{:016x} disagrees with final RIP 0x{final_rip:016x}",
            transfer.target_value()
        ));
    }
    if matches!(stop, TrapStop::NullControlTransfer) != (transfer.target_value() == 0) {
        return Err(format!(
            "production terminal stop {stop:?} disagrees with target 0x{:016x}",
            transfer.target_value()
        ));
    }
    Ok(transfer)
}

#[allow(clippy::too_many_arguments)]
fn replay_production_consumed_cell(
    config: &Config,
    image: &PeImage,
    bytes: &[u8],
    discovery: &CooperativeTrapRun,
    discovery_total: u64,
    tail: &[FormattedInstruction],
    transfer: ProductionTerminalTransfer,
    consumed_cell: u64,
) -> Result<ProductionConsumedCellEdge, String> {
    let watch_end = consumed_cell
        .checked_add(8)
        .ok_or_else(|| "production consumed-cell watch range overflows".to_owned())?;
    let tail_start = tail
        .first()
        .map(|entry| entry.global_instruction_index)
        .ok_or_else(|| "production terminal tail is empty".to_owned())?;
    let global_end = transfer
        .global_instruction_index()
        .checked_add(1)
        .ok_or_else(|| "production terminal global range overflows".to_owned())?;
    let (mut emu, mut env) = new_production_runtime(config, image, bytes)?;
    emu.configure_persistent_watch_in_global_range(
        &[(consumed_cell, watch_end)],
        config.watch_hit_cap,
        (tail_start, global_end),
    )
    .map_err(|error| format!("failed to arm production consumed-cell watch: {error}"))?;
    let replay = run_with_cooperative_scheduler(
        &mut env,
        &mut emu,
        image,
        image.entry_point_va(),
        config.main_per_leg_cap,
        PRODUCTION_API_BOUND,
    )
    .map_err(|error| format!("failed to run production consumed-cell replay: {error}"))?;
    require_export_control_applied(config, &env, "production consumed-cell replay")?;
    if replay != *discovery || emu.total_instructions_executed() != discovery_total {
        return Err(format!(
            "production consumed-cell replay diverged: total={}, stop={:?}",
            emu.total_instructions_executed(),
            replay.stop
        ));
    }
    let raw_hits = emu.persistent_watch_hits();
    if raw_hits.len() >= config.watch_hit_cap {
        return Err(format!(
            "production consumed-cell watch reached its {}-hit cap",
            config.watch_hit_cap
        ));
    }
    let hits = format_watch_hits(raw_hits)?;
    classify_production_consumed_cell_edge(&hits, transfer, tail_start)
}

fn classify_production_consumed_cell_edge(
    hits: &[FormattedWatchHit],
    transfer: ProductionTerminalTransfer,
    tail_start: u64,
) -> Result<ProductionConsumedCellEdge, String> {
    let ProductionTerminalTransfer::NearReturn {
        global_instruction_index,
        instruction_address,
        consumed_cell,
        target_value,
    } = transfer
    else {
        return Err("production consumed-cell edge requires a near return".to_owned());
    };
    let consumers = hits
        .iter()
        .filter(|entry| {
            !entry.hit.is_write
                && entry.hit.global_instruction_index == global_instruction_index
                && entry.hit.rip == instruction_address
                && entry.hit.address == consumed_cell
                && entry.hit.size == 8
                && entry.hit.value == Some(target_value)
        })
        .collect::<Vec<_>>();
    let [consumer] = consumers.as_slice() else {
        return Err(format!(
            "production consumed-cell replay retained {} matching terminal reads, expected one",
            consumers.len()
        ));
    };
    let writer = hits
        .iter()
        .rev()
        .find(|entry| {
            entry.hit.is_write
                && entry.hit.global_instruction_index >= tail_start
                && entry.hit.global_instruction_index < consumer.hit.global_instruction_index
                && entry.hit.address == consumed_cell
                && entry.hit.size == 8
                && entry.hit.value == Some(target_value)
        })
        .ok_or_else(|| {
            "production consumed-cell replay has no exact qword writer feeding the terminal read"
                .to_owned()
        })?;
    if consumer
        .hit
        .global_instruction_index
        .saturating_sub(writer.hit.global_instruction_index)
        >= PRODUCTION_TERMINAL_TAIL_LEN as u64
    {
        return Err("production consumed-cell writer lies outside the frozen tail".to_owned());
    }
    let writer_instruction = decode_watch_instruction(&writer.hit)
        .ok_or_else(|| "production consumed-cell writer has no exact instruction".to_owned())?;
    if writer_instruction.op0_kind() != OpKind::Memory {
        return Err("production consumed-cell writer does not write a memory operand".to_owned());
    }
    if writer_instruction.op1_kind() == OpKind::Register {
        let source_register = writer_instruction.op1_register().full_register();
        let source_value = iced_register_value(source_register, &writer.hit.registers)
            .ok_or_else(|| format!("unsupported consumed-cell source {source_register:?}"))?;
        if source_value != target_value {
            return Err(format!(
                "production consumed-cell writer source {source_register:?}=0x{source_value:016x} disagrees with written value 0x{target_value:016x}"
            ));
        }
    }
    Ok(ProductionConsumedCellEdge {
        writer: (*writer).clone(),
        consumer: (*consumer).clone(),
    })
}

fn parse_export_name_control(contents: &str) -> Result<Vec<String>, String> {
    let names = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Err("export-name control is empty".to_owned());
    }
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("export-name control must be strictly sorted and deduplicated".to_owned());
    }
    if names
        .iter()
        .any(|name| name.len() > 256 || !name.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))
    {
        return Err("export-name control contains an invalid name".to_owned());
    }
    Ok(names)
}

fn frozen_poll_window_controls() -> Result<PollWindowControls, String> {
    let baseline = ExportNameControl {
        module_name: "kernel32.dll".to_owned(),
        names: parse_export_name_control(include_str!(
            "../docs/controls/kernel32-with-widechar.txt"
        ))?,
    };
    let treatment = ExportNameControl {
        module_name: "kernel32.dll".to_owned(),
        names: parse_export_name_control(include_str!(
            "../docs/controls/kernel32-with-getcommandlinea.txt"
        ))?,
    };
    let added_name = single_added_export_name(&baseline, &treatment).ok_or_else(|| {
        "frozen post-poll controls do not differ by exactly one export name".to_owned()
    })?;
    if added_name != POST_POLL_API_NAME {
        return Err(format!(
            "frozen post-poll treatment adds {added_name:?}, expected {POST_POLL_API_NAME:?}"
        ));
    }
    Ok(PollWindowControls {
        baseline,
        treatment,
        added_name,
    })
}

fn parse_optional<T>(value: Option<String>, default: T, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match value {
        Some(value) => value
            .parse::<T>()
            .map_err(|error| format!("invalid {name} {value:?}: {error}")),
        None => Ok(default),
    }
}

fn validate_hit_cap(hit_cap: usize) -> Result<usize, String> {
    if hit_cap == 0 || hit_cap > MAX_WATCH_HIT_CAP {
        return Err(format!(
            "watch-hit-cap must be in 1..={MAX_WATCH_HIT_CAP}, got {hit_cap}"
        ));
    }
    Ok(hit_cap)
}

fn arm_persistent_watch(emu: &mut Emu, spec: &WatchSpec, hit_cap: usize) -> Result<(), EmuError> {
    match spec.global_instruction_range {
        Some(global_range) => {
            emu.configure_persistent_watch_in_global_range(&spec.ranges, hit_cap, global_range)
        }
        None => emu.configure_persistent_watch(&spec.ranges, hit_cap),
    }
}

fn discover_main_poll(
    config: &Config,
    image: &PeImage,
    bytes: &[u8],
) -> Result<MainPollObservation, String> {
    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(image, bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;
    let mut env = Win64Env::new(image.image_base);
    if let Some(control) = &config.export_name_control {
        if !env.configure_module_export_name_control(&control.module_name, &control.names) {
            return Err(format!(
                "rejected export-name control for {:?}",
                control.module_name
            ));
        }
    }

    // Install the persistent memory hook before any guest translation blocks
    // execute. The empty range retains no hits; the bounded Sleep-leg replay
    // below replaces it after reaching the discovery boundary.
    emu.configure_persistent_watch(&[], 0)
        .map_err(|error| format!("failed to install poll-discovery hook: {error}"))?;

    let main = run_until_pending_api(
        &mut env,
        &mut emu,
        image,
        image.entry_point_va(),
        "Sleep",
        config.main_per_leg_cap,
        MAIN_API_BOUND,
    )?;
    let image_end = image
        .image_base
        .checked_add(u64::from(image.size_of_image))
        .ok_or_else(|| "image watch range overflows".to_owned())?;
    emu.configure_persistent_watch(&[(image.image_base, image_end)], MAX_WATCH_HIT_CAP)
        .map_err(|error| format!("failed to arm poll-discovery watch: {error}"))?;
    let leg = run_with_import_trap(
        &mut env,
        &mut emu,
        image,
        main.pending_address,
        config.main_per_leg_cap,
        1,
    )
    .map_err(|error| format!("failed to run poll-discovery Sleep leg: {error}"))?;
    if leg.handled != ["Sleep"] || !is_call_bound_stop(&leg.stop) {
        return Err(format!(
            "poll discovery did not span one Sleep-to-Sleep leg: handled={:?}, stop={:?}",
            leg.handled, leg.stop
        ));
    }
    let hits = emu.persistent_watch_hits();
    if hits.len() >= MAX_WATCH_HIT_CAP {
        return Err(format!(
            "poll-discovery watch reached its {MAX_WATCH_HIT_CAP}-hit cap"
        ));
    }
    let formatted = format_watch_hits(hits)?;
    let mut candidates = formatted
        .iter()
        .filter_map(|entry| {
            let address = entry.hit.address;
            let compared_value = simple_byte_compare_value(entry)?;
            let observation = MainPollObservation {
                address,
                compare_rip: entry.hit.rip,
                compared_value,
                value_at_sleep: watched_byte(&entry.hit, address)?,
            };
            (!entry.hit.is_write
                && entry.hit.size == 1
                && is_simple_byte_poll_compare(entry)
                && observation.value_at_sleep == observation.compared_value)
                .then_some(observation)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|candidate| {
        (
            candidate.address,
            candidate.compare_rip,
            candidate.compared_value,
            candidate.value_at_sleep,
        )
    });
    candidates.dedup();
    let pending_rip = emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read post-discovery RIP: {error}"))?;
    let pending_name = env.callable_stub_name_at(pending_rip);
    if pending_name.as_deref() != Some("Sleep") {
        return Err(format!(
            "poll discovery ended at 0x{pending_rip:016x} {pending_name:?}, not the next Sleep"
        ));
    }
    match candidates.as_slice() {
        [poll] => Ok(*poll),
        [] => Err(format!(
            "poll discovery found no simple byte-compare candidate among {} image-memory hits",
            formatted.len()
        )),
        _ => Err(format!(
            "poll discovery found {} distinct simple byte-compare candidates",
            candidates.len()
        )),
    }
}

fn last_writer_before_releasing_compare(
    hits: &[PersistentWatchHit],
    poll: MainPollObservation,
    compare_range: std::ops::Range<usize>,
) -> Option<usize> {
    let compare_index = hits
        .get(compare_range.clone())?
        .iter()
        .position(|hit| {
            !hit.is_write
                && hit.size == 1
                && hit.address == poll.address
                && hit.rip == poll.compare_rip
                && is_simple_byte_poll_hit(hit)
                && simple_byte_compare_hit_value(hit) == Some(poll.compared_value)
                && watched_byte(hit, poll.address).is_some_and(|value| value != poll.compared_value)
        })
        .map(|offset| compare_range.start + offset)?;
    hits.get(..compare_index)?
        .iter()
        .rposition(|hit| hit.is_write && watched_byte(hit, poll.address).is_some())
        .filter(|index| {
            watched_byte(&hits[*index], poll.address)
                .is_some_and(|value| value != poll.compared_value)
        })
}

fn run_poll_window_return(
    config: &Config,
    image: &PeImage,
    bytes: &[u8],
    poll: MainPollObservation,
    treatment_pending_api: Option<&str>,
) -> Result<PollWindowEvidence, String> {
    if config
        .export_name_control
        .as_ref()
        .is_some_and(|control| control.module_name.eq_ignore_ascii_case("user32.dll"))
    {
        return Err(
            "--poll-window reserves USER32 for its narrow CreateWindowExA treatment".to_owned(),
        );
    }
    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(image, bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;
    let mut env = Win64Env::new(image.image_base);
    if let Some(control) = &config.export_name_control {
        if !env.configure_module_export_name_control(&control.module_name, &control.names) {
            return Err(format!(
                "rejected export-name control for {:?}",
                control.module_name
            ));
        }
    }
    let user32_names = [
        "CreateWindowExA".to_owned(),
        "LoadCursorA".to_owned(),
        "RegisterClassExA".to_owned(),
    ];
    if !env.configure_module_export_name_control("user32.dll", &user32_names) {
        return Err("failed to configure narrow USER32 CreateWindowExA treatment".to_owned());
    }
    let watch_end = poll
        .address
        .checked_add(1)
        .ok_or_else(|| "poll-cell watch range overflows".to_owned())?;
    emu.configure_persistent_watch(&[(poll.address, watch_end)], config.watch_hit_cap)
        .map_err(|error| format!("failed to arm post-CreateWindowExA poll watch: {error}"))?;

    let main = run_until_pending_api(
        &mut env,
        &mut emu,
        image,
        image.entry_point_va(),
        "Sleep",
        config.main_per_leg_cap,
        MAIN_API_BOUND,
    )?;
    if read_u8(&emu, poll.address)? != poll.value_at_sleep {
        return Err("post-CreateWindowExA replay changed the poll before Sleep".to_owned());
    }
    let (thread_id, thread) = sole_runnable_thread(&env)?;
    let main_cpu = emu
        .capture_cpu_context()
        .map_err(|error| format!("failed to capture post-CreateWindowExA main context: {error}"))?;
    configure_child_runtime(&mut emu, thread)?;
    emu.install_code_trace_hook()
        .map_err(|error| format!("failed to install post-CreateWindowExA code trace: {error}"))?;
    let child = run_until_pending_api(
        &mut env,
        &mut emu,
        image,
        thread.start_address,
        "CreateWindowExA",
        config.child_per_leg_cap,
        CHILD_PREFIX_API_BOUND + CHILD_TAIL_API_BOUND,
    )?;
    if !env.module_export_name_control_was_applied("user32.dll") {
        return Err("narrow USER32 CreateWindowExA treatment was not applied".to_owned());
    }
    let create_window = observe_create_window_ex_a(&emu)?;
    let procedures = env.registered_window_procedures().collect::<Vec<_>>();
    let [(_atom, window_procedure)] = procedures.as_slice() else {
        return Err(format!(
            "CreateWindowExA boundary requires one registered window procedure, got {}",
            procedures.len()
        ));
    };
    let window_procedure = *window_procedure;
    let post_create_hit_start = emu.persistent_watch_hits().len();
    let post_create_trace_start = emu.executed_addresses().len();
    diagnostic_scalar_return(&mut emu, DIAGNOSTIC_WINDOW_HANDLE)?;
    let post_create_begin = emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read post-CreateWindowExA RIP: {error}"))?;
    let post_create = run_until_pending_api(
        &mut env,
        &mut emu,
        image,
        post_create_begin,
        POST_CREATE_CHILD_API_NAME,
        config.child_per_leg_cap,
        CHILD_TAIL_API_BOUND,
    )
    .map_err(|error| format!("post-CreateWindowExA child treatment failed: {error}"))?;
    let post_create_pending_name = env
        .callable_stub_name_at(post_create.pending_address)
        .ok_or_else(|| {
            format!(
                "post-CreateWindowExA boundary 0x{:016x} is not a named stub",
                post_create.pending_address
            )
        })?;
    if post_create_pending_name != POST_CREATE_CHILD_API_NAME {
        return Err(format!(
            "post-CreateWindowExA child stopped at {post_create_pending_name:?}, expected {POST_CREATE_CHILD_API_NAME:?}"
        ));
    }
    let post_create_boundary = DiagnosticBoundary::PendingApi {
        name: post_create_pending_name,
    };
    let post_create_hit_end = emu.persistent_watch_hits().len();
    let post_create_trace_end = emu.executed_addresses().len();
    let pre_main_raw_hits = emu.persistent_watch_hits();
    if pre_main_raw_hits.len() >= config.watch_hit_cap {
        return Err(format!(
            "post-CreateWindowExA poll watch reached its {}-hit cap",
            config.watch_hit_cap
        ));
    }
    let post_create_rips = emu
        .executed_addresses()
        .get(post_create_trace_start..post_create_trace_end)
        .ok_or_else(|| "post-CreateWindowExA trace bounds are inconsistent".to_owned())?
        .to_vec();

    emu.restore_cpu_context(&main_cpu)
        .map_err(|error| format!("failed to restore post-CreateWindowExA main context: {error}"))?;
    let main_stack_end = STACK_BASE
        .checked_add(STACK_SIZE)
        .ok_or_else(|| "restored-main stack watch range overflows".to_owned())?;
    let capture_zero_provenance = treatment_pending_api.is_none();
    let restored_main_watch_ranges = if capture_zero_provenance {
        vec![(poll.address, watch_end), (STACK_BASE, main_stack_end)]
    } else {
        vec![(poll.address, watch_end)]
    };
    let restored_main_watch_hit_cap = if capture_zero_provenance {
        MAX_WATCH_HIT_CAP
    } else {
        config.watch_hit_cap
    };
    emu.configure_persistent_watch(&restored_main_watch_ranges, restored_main_watch_hit_cap)
        .map_err(|error| format!("failed to arm restored-main watch: {error}"))?;
    let main_begin = emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read restored main RIP: {error}"))?;
    let main_hit_start = pre_main_raw_hits.len();
    let main_trace_start = emu.executed_addresses().len();
    let restored_main_cap = config.main_per_leg_cap.min(MAX_POLL_MAIN_TRACE_CAP);
    let (main_handled, main_boundary) = match treatment_pending_api {
        None => {
            let main_leg = run_with_import_trap(
                &mut env,
                &mut emu,
                image,
                main_begin,
                restored_main_cap,
                POST_POLL_API_BOUND,
            )
            .map_err(|error| {
                format!("post-CreateWindowExA restored-main baseline failed: {error}")
            })?;
            (main_leg.handled, DiagnosticBoundary::Natural(main_leg.stop))
        }
        Some(pending_api) => {
            let main_leg = run_until_pending_api(
                &mut env,
                &mut emu,
                image,
                main_begin,
                pending_api,
                restored_main_cap,
                POST_POLL_API_BOUND,
            )
            .map_err(|error| {
                format!("post-CreateWindowExA restored-main treatment failed: {error}")
            })?;
            let pending_name = env
                .callable_stub_name_at(main_leg.pending_address)
                .ok_or_else(|| {
                    format!(
                        "restored-main treatment boundary 0x{:016x} is not a named stub",
                        main_leg.pending_address
                    )
                })?;
            if pending_name != pending_api {
                return Err(format!(
                    "restored-main treatment stopped at {pending_name:?}, expected {pending_api:?}"
                ));
            }
            (
                main_leg.handled,
                DiagnosticBoundary::PendingApi { name: pending_name },
            )
        }
    };
    let main_raw_hits = emu.persistent_watch_hits();
    let main_hit_end = main_hit_start + main_raw_hits.len();
    let main_trace_end = emu.executed_addresses().len();
    let main_pending_rip = emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read post-CreateWindowExA main stop RIP: {error}"))?;
    let main_pending_api = env.callable_stub_name_at(main_pending_rip);
    let main_pending_address = main_pending_api.as_ref().map(|_| main_pending_rip);
    if main_raw_hits.len() >= restored_main_watch_hit_cap {
        return Err(format!(
            "restored-main watch reached its {}-hit cap",
            restored_main_watch_hit_cap
        ));
    }
    let mut raw_hits = pre_main_raw_hits;
    raw_hits.extend(main_raw_hits);
    let release_writer_index =
        last_writer_before_releasing_compare(&raw_hits, poll, main_hit_start..main_hit_end);
    let main_rips = emu
        .executed_addresses()
        .get(main_trace_start..main_trace_end)
        .ok_or_else(|| "post-CreateWindowExA main trace bounds are inconsistent".to_owned())?
        .to_vec();
    let main_terminal_registers = read_cpu_state(&emu)?;
    let main_final_rsp = register_value(&main_terminal_registers, RegisterX86::RSP)
        .ok_or_else(|| "restored-main terminal snapshot is missing RSP".to_owned())?;
    let main_frozen_tail = emu.recent_instructions();
    let main_terminal_call = derive_register_call_terminal(
        &emu,
        &main_rips,
        main_final_rsp,
        &main_terminal_registers,
        &main_frozen_tail,
    )?;
    if matches!(
        &main_boundary,
        DiagnosticBoundary::Natural(TrapStop::NullControlTransfer)
    ) && main_terminal_call.is_none_or(|call| call.target_value != 0)
    {
        return Err("restored-main null is not a validated zero-target register call".to_owned());
    }
    let main_tail_instructions = format_tail(&main_frozen_tail, &main_rips, POST_POLL_TAIL_LEN)?;
    let main_loop_repeated = !main_handled.is_empty()
        && main_handled.iter().all(|name| name == "Sleep")
        && matches!(
            &main_boundary,
            DiagnosticBoundary::Natural(stop) if is_call_bound_stop(stop)
        )
        && main_pending_api.as_deref() == Some("Sleep");
    let instructions_past_poll = if main_loop_repeated {
        0
    } else {
        main_rips
            .iter()
            .rposition(|rip| *rip == poll.compare_rip)
            .map_or(0, |index| main_rips.len() - index - 1)
    };
    let poll_final = read_u8(&emu, poll.address)?;
    if (poll_final != poll.compared_value || instructions_past_poll > 0)
        && release_writer_index.is_none()
    {
        return Err(format!(
            "restored main advanced or left poll byte 0x{poll_final:02x} without a retained writer feeding its releasing comparison"
        ));
    }
    let hits = format_watch_hits(raw_hits)?;
    let zero_target_provenance = match main_terminal_call {
        Some(call) if call.target_value == 0 && capture_zero_provenance => {
            derive_zero_target_provenance(
                hits.get(main_hit_start..main_hit_end)
                    .ok_or_else(|| "restored-main watch-hit bounds are inconsistent".to_owned())?,
                &main_tail_instructions,
                call,
            )?
        }
        _ => None,
    };
    if matches!(
        &main_boundary,
        DiagnosticBoundary::Natural(TrapStop::NullControlTransfer)
    ) && capture_zero_provenance
        && zero_target_provenance.is_none()
    {
        return Err("restored-main null has no bounded deliberate-zero provenance".to_owned());
    }
    if let Some(control) = &config.export_name_control {
        if !env.module_export_name_control_was_applied(&control.module_name) {
            return Err(format!(
                "export-name control for {:?} was never applied",
                control.module_name
            ));
        }
    }
    if !hits[..post_create_hit_start]
        .iter()
        .any(|entry| is_main_poll_compare(entry, poll))
        || !hits[post_create_hit_end..]
            .iter()
            .any(|entry| is_main_poll_compare(entry, poll))
    {
        return Err(
            "post-CreateWindowExA replay did not retain both main poll comparisons".to_owned(),
        );
    }
    Ok(PollWindowEvidence {
        poll,
        main_prefix_handled: main.handled,
        thread_id,
        thread,
        child_handled: child.handled,
        create_window,
        window_procedure,
        post_create_handled: post_create.handled,
        post_create_boundary,
        post_create_rips,
        hits,
        post_create_hit_start,
        post_create_hit_end,
        release_writer_index,
        poll_final,
        main_boundary,
        main_handled,
        main_pending_api,
        main_pending_address,
        restored_main_cap,
        main_rips,
        main_tail_instructions,
        main_terminal_call,
        zero_target_provenance,
        instructions_past_poll,
    })
}

fn observe_create_window_ex_a(emu: &Emu) -> Result<CreateWindowExAObservation, String> {
    let rsp = emu
        .read_reg(RegisterX86::RSP)
        .map_err(|error| format!("failed to read CreateWindowExA RSP: {error}"))?;
    let stack = |offset: u64| -> Result<u64, String> {
        let address = rsp
            .checked_add(offset)
            .ok_or_else(|| "CreateWindowExA stack address overflows".to_owned())?;
        read_u64(emu, address)
    };
    Ok(CreateWindowExAObservation {
        return_address: stack(0)?,
        extended_style: emu
            .read_reg(RegisterX86::RCX)
            .map_err(|error| format!("failed to read CreateWindowExA RCX: {error}"))?,
        class_name: emu
            .read_reg(RegisterX86::RDX)
            .map_err(|error| format!("failed to read CreateWindowExA RDX: {error}"))?,
        window_name: emu
            .read_reg(RegisterX86::R8)
            .map_err(|error| format!("failed to read CreateWindowExA R8: {error}"))?,
        style: emu
            .read_reg(RegisterX86::R9)
            .map_err(|error| format!("failed to read CreateWindowExA R9: {error}"))?,
        x: stack(0x28)?,
        y: stack(0x30)?,
        width: stack(0x38)?,
        height: stack(0x40)?,
        parent: stack(0x48)?,
        menu: stack(0x50)?,
        instance: stack(0x58)?,
        parameter: stack(0x60)?,
    })
}

fn diagnostic_scalar_return(emu: &mut Emu, value: u64) -> Result<(), String> {
    let rsp = emu
        .read_reg(RegisterX86::RSP)
        .map_err(|error| format!("failed to read diagnostic return RSP: {error}"))?;
    let return_address = read_u64(emu, rsp)?;
    let new_rsp = rsp
        .checked_add(8)
        .ok_or_else(|| "diagnostic return RSP overflows".to_owned())?;
    emu.write_reg(RegisterX86::RAX, value)
        .map_err(|error| format!("failed to set diagnostic return value: {error}"))?;
    emu.write_reg(RegisterX86::RIP, return_address)
        .map_err(|error| format!("failed to set diagnostic return RIP: {error}"))?;
    emu.write_reg(RegisterX86::RSP, new_rsp)
        .map_err(|error| format!("failed to set diagnostic return RSP: {error}"))
}

fn run_pass(
    config: &Config,
    image: &PeImage,
    bytes: &[u8],
    watch_spec: Option<WatchSpec>,
) -> Result<PassEvidence, String> {
    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(image, bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;
    let mut env = Win64Env::new(image.image_base);
    if let Some(control) = &config.export_name_control {
        if !env.configure_module_export_name_control(&control.module_name, &control.names) {
            return Err(format!(
                "rejected export-name control for {:?}",
                control.module_name
            ));
        }
    }

    if let Some(spec) = watch_spec
        .as_ref()
        .filter(|spec| spec.phase == WatchPhase::BeforeMain)
    {
        arm_persistent_watch(&mut emu, spec, config.watch_hit_cap)
            .map_err(|error| format!("failed to arm whole-run handler-slot watch: {error}"))?;
    }

    let mut frozen_main_watch_hits = None;
    let main = if let Some((capture, ranges, global_range)) =
        watch_spec.as_ref().and_then(|spec| match spec.phase {
            WatchPhase::CaptureMainLegWriting {
                address,
                writer_rip,
                global_instruction_index,
                value,
            } => Some((
                WriterCapture {
                    address,
                    writer_rip,
                    global_instruction_index,
                    value,
                },
                spec.ranges.as_slice(),
                spec.global_instruction_range,
            )),
            WatchPhase::BeforeMain | WatchPhase::BeforeTime => None,
        }) {
        let (before_freeze, frozen_hits) = run_until_writer_leg(
            &mut env,
            &mut emu,
            image,
            image.entry_point_va(),
            "Sleep",
            ranges,
            global_range,
            capture,
            config.main_per_leg_cap,
            MAIN_API_BOUND,
            config.watch_hit_cap,
        )?;
        frozen_main_watch_hits = Some(frozen_hits);
        let remaining_bound = MAIN_API_BOUND
            .checked_sub(before_freeze.handled.len())
            .ok_or_else(|| "source-watch prefix exhausted the main API bound".to_owned())?;
        let mut after_freeze = run_until_pending_api(
            &mut env,
            &mut emu,
            image,
            before_freeze.pending_address,
            "Sleep",
            config.main_per_leg_cap,
            remaining_bound,
        )?;
        let mut handled = before_freeze.handled;
        handled.append(&mut after_freeze.handled);
        PendingApiRun {
            handled,
            pending_address: after_freeze.pending_address,
        }
    } else {
        run_until_pending_api(
            &mut env,
            &mut emu,
            image,
            image.entry_point_va(),
            "Sleep",
            config.main_per_leg_cap,
            MAIN_API_BOUND,
        )?
    };
    let (thread_id, thread) = sole_runnable_thread(&env)?;

    let main_cpu = emu
        .capture_cpu_context()
        .map_err(|error| format!("failed to capture main CPU context: {error}"))?;
    let main_registers = read_cpu_state(&emu)?;
    let main_stack_before = emu
        .read_mem(
            STACK_BASE,
            usize::try_from(STACK_SIZE).map_err(|error| format!("stack size: {error}"))?,
        )
        .map_err(|error| format!("failed to snapshot main stack: {error}"))?;
    let main_teb_before = emu
        .read_mem(
            TEB_BASE,
            usize::try_from(TEB_SIZE).map_err(|error| format!("TEB size: {error}"))?,
        )
        .map_err(|error| format!("failed to snapshot main TEB: {error}"))?;

    let entry_rsp = configure_child_runtime(&mut emu, thread)?;
    if watch_spec.is_none() {
        emu.configure_persistent_watch(
            &[(CHILD_TEB_BASE, CHILD_TEB_BASE + CHILD_TEB_SIZE)],
            config.watch_hit_cap,
        )
        .map_err(|error| format!("failed to arm child-TEB access watch: {error}"))?;
    }
    emu.install_code_trace_hook()
        .map_err(|error| format!("failed to install child code trace: {error}"))?;

    let child_prefix = run_until_pending_api(
        &mut env,
        &mut emu,
        image,
        thread.start_address,
        "timeGetTime",
        config.child_per_leg_cap,
        CHILD_PREFIX_API_BOUND,
    )?;
    let time_rsp = emu
        .read_reg(RegisterX86::RSP)
        .map_err(|error| format!("failed to read timeGetTime RSP: {error}"))?;
    let time_return_address = read_u64(&emu, time_rsp)?;
    let pre_time_rips = emu.executed_addresses();

    if let Some(spec) = watch_spec
        .as_ref()
        .filter(|spec| spec.phase == WatchPhase::BeforeTime)
    {
        arm_persistent_watch(&mut emu, spec, config.watch_hit_cap)
            .map_err(|error| format!("failed to arm terminal-cell watch: {error}"))?;
    }

    let child_tail = run_with_import_trap(
        &mut env,
        &mut emu,
        image,
        child_prefix.pending_address,
        config.child_per_leg_cap,
        CHILD_TAIL_API_BOUND,
    )
    .map_err(|error| format!("failed to run child timeGetTime suffix: {error}"))?;
    if child_tail.handled.first().map(String::as_str) != Some("timeGetTime") {
        return Err(format!(
            "expected the child suffix to begin with timeGetTime, got {:?}",
            child_tail.handled
        ));
    }
    let child_rips = emu.executed_addresses();
    let registered_window_procedures = env.registered_window_procedures().collect::<Vec<_>>();
    if let Some(control) = &config.export_name_control {
        if !env.module_export_name_control_was_applied(&control.module_name) {
            return Err(format!(
                "export-name control for {:?} was never applied",
                control.module_name
            ));
        }
    }
    let synthetic_module_image_ranges = env
        .synthetic_module_image_ranges()
        .map(|(name, start, end)| (name.to_owned(), start, end))
        .collect::<Vec<_>>();
    let window_procedure_trace_edges = registered_window_procedures
        .iter()
        .map(|(_, procedure)| {
            let predecessor = child_rips
                .iter()
                .position(|rip| rip == procedure)
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| child_rips.get(index))
                .copied();
            (*procedure, predecessor)
        })
        .collect();
    let post_time_rips = child_rips
        .get(pre_time_rips.len()..)
        .ok_or_else(|| "child trace shrank across timeGetTime".to_owned())?
        .to_vec();
    let final_rip = emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read child final RIP: {error}"))?;
    let final_rsp = emu
        .read_reg(RegisterX86::RSP)
        .map_err(|error| format!("failed to read child final RSP: {error}"))?;
    let terminal_registers = read_cpu_state(&emu)?;
    let terminal_stack_qwords = (0..=12)
        .map(|index| {
            let address = final_rsp
                .checked_add(index * 8)
                .ok_or_else(|| "terminal stack observation overflows".to_owned())?;
            read_u64(&emu, address)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let frozen_tail = emu.recent_instructions();
    let (terminal_transfer, terminal_cell) = derive_terminal_transfer(
        &emu,
        &post_time_rips,
        final_rsp,
        &terminal_registers,
        &frozen_tail,
    )?;
    let terminal_value = read_u64(&emu, terminal_cell)?;
    let terminal = classify_terminal(&child_tail, final_rip, terminal_value)?;
    let tail_instructions = format_tail(&frozen_tail, &post_time_rips, 64)?;

    let watch_hits = match frozen_main_watch_hits {
        Some(hits) => hits,
        None => format_watch_hits(emu.persistent_watch_hits())?,
    };
    if watch_spec.is_none() {
        if watch_hits.len() >= config.watch_hit_cap {
            return Err(format!(
                "child-TEB watch reached its {}-hit cap; access absence would be inconclusive",
                config.watch_hit_cap
            ));
        }
        if watch_hits.iter().any(|entry| {
            !access_overlaps(
                entry.hit.address,
                entry.hit.size,
                CHILD_TEB_BASE,
                CHILD_TEB_SIZE,
            )
        }) {
            return Err("child-TEB watch retained an access outside the child TEB".to_owned());
        }
    }
    let terminal_source = match terminal_transfer {
        TerminalTransfer::NearReturn { .. } => {
            derive_terminal_source(&emu, terminal_cell, terminal_value, &watch_hits)?
        }
        TerminalTransfer::IndirectCall { .. } => None,
    };

    let main_stack_after = emu
        .read_mem(STACK_BASE, main_stack_before.len())
        .map_err(|error| format!("failed to re-read main stack: {error}"))?;
    let main_teb_after = emu
        .read_mem(TEB_BASE, main_teb_before.len())
        .map_err(|error| format!("failed to re-read main TEB: {error}"))?;

    emu.restore_cpu_context(&main_cpu)
        .map_err(|error| format!("failed to restore main CPU context: {error}"))?;
    let restored_registers = read_cpu_state(&emu)?;
    let main_cpu_restored = restored_registers == main_registers;
    if !main_cpu_restored {
        return Err("main CPU register state differs after context restore".to_owned());
    }

    let trace_len_before_sleep = emu.executed_addresses().len();
    let restored_rip = emu
        .read_reg(RegisterX86::RIP)
        .map_err(|error| format!("failed to read restored main RIP: {error}"))?;
    let main_sleep = run_with_import_trap(
        &mut env,
        &mut emu,
        image,
        restored_rip,
        config.child_per_leg_cap,
        1,
    )
    .map_err(|error| format!("failed to replay restored main Sleep leg: {error}"))?;
    if main_sleep.handled != ["Sleep"] || !is_call_bound_stop(&main_sleep.stop) {
        return Err(format!(
            "restored main did not reach the next Sleep boundary: handled={:?}, stop={:?}",
            main_sleep.handled, main_sleep.stop
        ));
    }
    let all_rips = emu.executed_addresses();
    let main_sleep_rips = all_rips
        .get(trace_len_before_sleep..)
        .ok_or_else(|| "main trace shrank after context restore".to_owned())?
        .to_vec();
    Ok(PassEvidence {
        main_handled: main.handled,
        thread_id,
        thread,
        entry_rsp,
        child_prefix_handled: child_prefix.handled,
        time_return_address,
        child_tail_handled: child_tail.handled,
        registered_window_procedures,
        window_procedure_trace_edges,
        synthetic_module_image_ranges,
        terminal,
        terminal_transfer,
        terminal_registers,
        terminal_stack_qwords,
        terminal_cell,
        terminal_value,
        child_rips,
        post_time_rips,
        tail_instructions,
        watch_spec,
        watch_hits,
        terminal_source,
        main_stack_unchanged: main_stack_before == main_stack_after,
        main_teb_unchanged: main_teb_before == main_teb_after,
        main_cpu_restored,
        main_sleep_handled: main_sleep.handled,
        main_sleep_rips,
    })
}

#[derive(Debug, Clone)]
struct PendingApiRun {
    handled: Vec<String>,
    pending_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriterCapture {
    address: u64,
    writer_rip: u64,
    global_instruction_index: u64,
    value: u64,
}

#[allow(clippy::too_many_arguments)]
fn run_until_pending_api(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &PeImage,
    begin: u64,
    target: &str,
    per_leg_cap: u64,
    handled_bound: usize,
) -> Result<PendingApiRun, String> {
    let mut next = begin;
    let mut handled = Vec::new();

    loop {
        if env.callable_stub_name_at(next).as_deref() == Some(target) {
            return Ok(PendingApiRun {
                handled,
                pending_address: next,
            });
        }
        if handled.len() >= handled_bound {
            return Err(format!(
                "did not reach pending {target} within {handled_bound} handled APIs"
            ));
        }

        let leg = run_with_import_trap(env, emu, image, next, per_leg_cap, 1)
            .map_err(|error| format!("trap leg before {target} failed: {error}"))?;
        if leg.handled.len() != 1 || !is_call_bound_stop(&leg.stop) {
            return Err(format!(
                "stopped before pending {target}: handled={:?}, stop={:?}",
                leg.handled, leg.stop
            ));
        }
        handled.extend(leg.handled);
        next = emu
            .read_reg(RegisterX86::RIP)
            .map_err(|error| format!("failed to read pending API RIP: {error}"))?;
        let pending = env.callable_stub_name_at(next).ok_or_else(|| {
            format!("call-bound stop at 0x{next:016x} did not reverse-map to a callable stub")
        })?;
        if pending == target {
            return Ok(PendingApiRun {
                handled,
                pending_address: next,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_until_writer_leg(
    env: &mut Win64Env,
    emu: &mut Emu,
    image: &PeImage,
    begin: u64,
    target: &str,
    watch_ranges: &[(u64, u64)],
    watch_global_range: Option<(u64, u64)>,
    capture: WriterCapture,
    per_leg_cap: u64,
    handled_bound: usize,
    watch_hit_cap: usize,
) -> Result<(PendingApiRun, Vec<FormattedWatchHit>), String> {
    let mut next = begin;
    let mut handled = Vec::new();

    loop {
        let pending = env.callable_stub_name_at(next);
        if pending.as_deref() == Some(target) {
            return Err(format!(
                "reached pending {target} without observing the dynamically derived writer at global instruction {}",
                capture.global_instruction_index
            ));
        }
        if handled.len() >= handled_bound {
            return Err(format!(
                "did not reach pending {target} within {handled_bound} handled APIs"
            ));
        }

        match watch_global_range {
            Some(global_range) => emu.configure_persistent_watch_in_global_range(
                watch_ranges,
                watch_hit_cap,
                global_range,
            ),
            None => emu.configure_persistent_watch(watch_ranges, watch_hit_cap),
        }
        .map_err(|error| format!("failed to re-arm source watch for one API leg: {error}"))?;
        let leg = run_with_import_trap(env, emu, image, next, per_leg_cap, 1)
            .map_err(|error| format!("re-armed trap leg before {target} failed: {error}"))?;
        if leg.handled.len() != 1 || !is_call_bound_stop(&leg.stop) {
            return Err(format!(
                "stopped before pending {target}: handled={:?}, stop={:?}",
                leg.handled, leg.stop
            ));
        }
        handled.extend(leg.handled);
        next = emu
            .read_reg(RegisterX86::RIP)
            .map_err(|error| format!("failed to read pending API RIP: {error}"))?;
        if env.callable_stub_name_at(next).is_none() {
            return Err(format!(
                "call-bound stop at 0x{next:016x} did not reverse-map to a callable stub"
            ));
        }

        let hits = emu.persistent_watch_hits();
        if hits.len() >= watch_hit_cap {
            return Err(format!(
                "source watch reached its {watch_hit_cap}-hit cap in one API leg; writer discovery may be truncated"
            ));
        }
        if hits.iter().any(|hit| {
            hit.is_write
                && hit.address == capture.address
                && hit.size == 8
                && hit.rip == capture.writer_rip
                && hit.global_instruction_index == capture.global_instruction_index
                && hit.value == Some(capture.value)
        }) {
            let formatted = format_watch_hits(hits)?;
            return Ok((
                PendingApiRun {
                    handled,
                    pending_address: next,
                },
                formatted,
            ));
        }
    }
}

fn is_call_bound_stop(stop: &TrapStop) -> bool {
    matches!(stop, TrapStop::Other(message) if message == "max_calls reached")
}

fn sole_runnable_thread(env: &Win64Env) -> Result<(u32, RunnableUnscheduledThread), String> {
    let mut records = env.runnable_unscheduled_threads();
    let Some((thread_id, &thread)) = records.next() else {
        return Err("Sleep boundary has no runnable-unscheduled thread".to_owned());
    };
    if records.next().is_some() {
        return Err("Sleep boundary has more than one runnable-unscheduled thread".to_owned());
    }
    Ok((thread_id, thread))
}

fn configure_child_runtime(
    emu: &mut Emu,
    thread: RunnableUnscheduledThread,
) -> Result<u64, String> {
    emu.map_zeroed_rw(CHILD_STACK_BASE, CHILD_STACK_SIZE)
        .map_err(|error| format!("failed to map child stack: {error}"))?;
    emu.map_zeroed_rw(CHILD_TEB_BASE, CHILD_TEB_SIZE)
        .map_err(|error| format!("failed to map child TEB: {error}"))?;

    let stack_end = CHILD_STACK_BASE
        .checked_add(CHILD_STACK_SIZE)
        .ok_or_else(|| "child stack end overflows".to_owned())?;
    let entry_rsp = stack_end
        .checked_sub(CHILD_ENTRY_HEADROOM + 8)
        .ok_or_else(|| "child entry RSP underflows".to_owned())?;
    if entry_rsp & 0xf != 8 {
        return Err(format!(
            "child entry RSP is not Win64-call aligned: 0x{entry_rsp:016x}"
        ));
    }

    write_u64(emu, entry_rsp, CHILD_RETURN_SENTINEL)?;
    write_u64(emu, CHILD_TEB_BASE + TEB_STACKBASE_OFFSET, stack_end)?;
    write_u64(
        emu,
        CHILD_TEB_BASE + TEB_STACKLIMIT_OFFSET,
        CHILD_STACK_BASE,
    )?;
    write_u64(emu, CHILD_TEB_BASE + TEB_SELF_OFFSET, CHILD_TEB_BASE)?;
    write_u64(emu, CHILD_TEB_BASE + TEB_PEB_OFFSET, PEB_BASE)?;

    for register in CHILD_ZERO_REGISTERS {
        emu.write_reg(register, 0)
            .map_err(|error| format!("failed to zero {register:?}: {error}"))?;
    }
    emu.write_reg(RegisterX86::RCX, thread.parameter)
        .map_err(|error| format!("failed to set child parameter: {error}"))?;
    emu.write_reg(RegisterX86::RSP, entry_rsp)
        .map_err(|error| format!("failed to set child RSP: {error}"))?;
    emu.write_reg(RegisterX86::RIP, thread.start_address)
        .map_err(|error| format!("failed to set child RIP: {error}"))?;
    emu.write_reg(RegisterX86::GS_BASE, CHILD_TEB_BASE)
        .map_err(|error| format!("failed to select child TEB: {error}"))?;
    emu.write_reg(RegisterX86::EFLAGS, 2)
        .map_err(|error| format!("failed to initialize child flags: {error}"))?;
    Ok(entry_rsp)
}

fn write_u64(emu: &mut Emu, address: u64, value: u64) -> Result<(), String> {
    emu.write_mem(address, &value.to_le_bytes())
        .map_err(|error| format!("failed to write 0x{value:016x} at 0x{address:016x}: {error}"))
}

fn read_u8(emu: &Emu, address: u64) -> Result<u8, String> {
    emu.read_mem(address, 1)
        .map_err(|error| format!("failed to read byte at 0x{address:016x}: {error}"))?
        .first()
        .copied()
        .ok_or_else(|| format!("short byte read at 0x{address:016x}"))
}

fn read_u64(emu: &Emu, address: u64) -> Result<u64, String> {
    let bytes = emu
        .read_mem(address, 8)
        .map_err(|error| format!("failed to read qword at 0x{address:016x}: {error}"))?;
    let array: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("short qword read at 0x{address:016x}"))?;
    Ok(u64::from_le_bytes(array))
}

fn read_u16(emu: &Emu, address: u64) -> Result<u16, String> {
    let bytes = emu
        .read_mem(address, 2)
        .map_err(|error| format!("failed to read word at 0x{address:016x}: {error}"))?;
    let array: [u8; 2] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("short word read at 0x{address:016x}"))?;
    Ok(u16::from_le_bytes(array))
}

fn derive_terminal_source(
    emu: &Emu,
    terminal_cell: u64,
    terminal_value: u64,
    watch_hits: &[FormattedWatchHit],
) -> Result<Option<TerminalSource>, String> {
    let Some(writer) = watch_hits.iter().rev().find(|entry| {
        entry.hit.is_write && access_overlaps(entry.hit.address, entry.hit.size, terminal_cell, 8)
    }) else {
        return Ok(None);
    };
    if writer.hit.address != terminal_cell
        || writer.hit.size != 8
        || writer.hit.value != Some(terminal_value)
        || writer.instruction != "mov [rsi],r13"
        || register_value(&writer.hit.registers, RegisterX86::RSI) != Some(terminal_cell)
        || register_value(&writer.hit.registers, RegisterX86::R13) != Some(terminal_value)
    {
        return Err(format!(
            "terminal cell's last writer has an unmodeled shape: {writer:?}"
        ));
    }

    let rbp = register_value(&writer.hit.registers, RegisterX86::RBP)
        .ok_or_else(|| "terminal writer snapshot is missing RBP".to_owned())?;
    let selector_address = register_value(&writer.hit.registers, RegisterX86::RCX)
        .ok_or_else(|| "terminal writer snapshot is missing RCX".to_owned())?;
    let bytecode_cursor = selector_address.checked_sub(6).ok_or_else(|| {
        format!("terminal selector address is below +6: 0x{selector_address:016x}")
    })?;
    let selector = read_u16(emu, selector_address)?;
    let context_address = rbp
        .checked_add(u64::from(selector))
        .ok_or_else(|| format!("VM context selector overflows: RBP=0x{rbp:016x}, {selector:#x}"))?;
    let handler_slot = read_u64(emu, context_address)?;
    let handler_value = read_u64(emu, handler_slot)?;
    if handler_value != terminal_value {
        return Err(format!(
            "dispatcher source chain does not reproduce the terminal value: slot=0x{handler_slot:016x}, value=0x{handler_value:016x}, terminal=0x{terminal_value:016x}"
        ));
    }

    Ok(Some(TerminalSource {
        writer_rip: writer.hit.rip,
        writer_global_instruction_index: writer.hit.global_instruction_index,
        bytecode_cursor,
        selector_address,
        selector,
        context_address,
        handler_slot,
        handler_value,
    }))
}

fn register_value(registers: &[(RegisterX86, u64)], register: RegisterX86) -> Option<u64> {
    registers
        .iter()
        .find_map(|(candidate, value)| (*candidate == register).then_some(*value))
}

fn terminal_cell(final_rsp: u64) -> Result<u64, String> {
    final_rsp
        .checked_sub(8)
        .ok_or_else(|| format!("final RSP cannot identify a consumed qword: 0x{final_rsp:016x}"))
}

fn classify_terminal(
    tail: &TrapRun,
    final_rip: u64,
    terminal_value: u64,
) -> Result<ChildTerminal, String> {
    match &tail.stop {
        TrapStop::NullControlTransfer if final_rip == 0 && terminal_value == 0 => {
            Ok(ChildTerminal::NullControlTransfer)
        }
        TrapStop::UnexpectedFault { address }
            if *address == CHILD_RETURN_SENTINEL
                && final_rip == CHILD_RETURN_SENTINEL
                && terminal_value == CHILD_RETURN_SENTINEL =>
        {
            Ok(ChildTerminal::ReturnSentinel)
        }
        TrapStop::UnhandledApi { name, .. }
            if final_rip == terminal_value && terminal_value != 0 =>
        {
            Ok(ChildTerminal::UnhandledApi { name: name.clone() })
        }
        other => Err(format!(
            "child terminal transfer is outside the bounded classifier: stop={other:?}, RIP=0x{final_rip:016x}, consumed=0x{terminal_value:016x}"
        )),
    }
}

fn derive_terminal_transfer(
    emu: &Emu,
    post_time_rips: &[u64],
    final_rsp: u64,
    final_registers: &[(RegisterX86, u64)],
    frozen_tail: &[FrozenInstruction],
) -> Result<(TerminalTransfer, u64), String> {
    let last = post_time_rips
        .last()
        .copied()
        .ok_or_else(|| "post-time trace is empty".to_owned())?;
    let frozen = frozen_tail
        .last()
        .filter(|instruction| instruction.address == last)
        .ok_or_else(|| "terminal instruction has no matching hook-time snapshot".to_owned())?;
    let mut decoder = Decoder::with_ip(64, &frozen.bytes, last, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() != frozen.bytes.len() {
        return Err("terminal hook-time bytes do not decode as one exact instruction".to_owned());
    }
    let encoded = frozen.bytes.as_slice();

    if matches!(instruction.code(), Code::Retnq | Code::Retnq_imm16) {
        validate_terminal_ret_instruction(&instruction, encoded, last)?;
        return Ok((
            TerminalTransfer::NearReturn {
                instruction_address: last,
            },
            terminal_cell(final_rsp)?,
        ));
    }

    if instruction.code() != Code::Call_rm64
        || instruction.memory_base() != Register::RDI
        || instruction.memory_index() != Register::None
        // Iced reports an encoded disp32 as an 8-byte effective displacement
        // in 64-bit address size; disp8 remains 1 and is rejected here.
        || instruction.memory_displ_size() != 8
        || instruction.has_segment_prefix()
        || instruction.stack_pointer_increment() != -8
        || has_operand_size_override_prefix(encoded)
    {
        return Err(format!(
            "terminal-source derivation supports only a bounded qword RET or unsegmented call qword [rdi+disp], found {} at 0x{last:016x}",
            format_instruction(&instruction)
        ));
    }

    let rdi = register_value(final_registers, RegisterX86::RDI)
        .ok_or_else(|| "indirect-call terminal snapshot is missing RDI".to_owned())?;
    if register_value(final_registers, RegisterX86::RSP) != Some(final_rsp) {
        return Err("indirect-call terminal snapshot RSP disagrees with the final RSP".to_owned());
    }
    let displacement = instruction.memory_displacement64();
    if displacement == 0 || displacement > i32::MAX as u64 {
        return Err(format!(
            "indirect-call displacement is outside the bounded positive disp32 form: 0x{displacement:x}"
        ));
    }
    let pointer_cell = rdi.checked_add(displacement).ok_or_else(|| {
        format!(
            "indirect-call pointer cell overflows: RDI=0x{rdi:016x}, displacement=0x{displacement:x}"
        )
    })?;
    let pushed_return_address = read_u64(emu, final_rsp)?;
    if pushed_return_address != instruction.next_ip() {
        return Err(format!(
            "indirect call did not leave its fallthrough on the final stack: expected 0x{:016x}, got 0x{pushed_return_address:016x}",
            instruction.next_ip()
        ));
    }

    Ok((
        TerminalTransfer::IndirectCall {
            instruction_address: last,
            pointer_cell,
            pushed_return_address,
        },
        pointer_cell,
    ))
}

fn derive_register_call_terminal(
    emu: &Emu,
    rips: &[u64],
    final_rsp: u64,
    final_registers: &[(RegisterX86, u64)],
    frozen_tail: &[FrozenInstruction],
) -> Result<Option<RegisterCallTerminal>, String> {
    let Some(last) = rips.last().copied() else {
        return Ok(None);
    };
    let frozen = frozen_tail
        .last()
        .filter(|instruction| instruction.address == last)
        .ok_or_else(|| "restored-main terminal has no matching hook-time snapshot".to_owned())?;
    let mut decoder = Decoder::with_ip(64, &frozen.bytes, last, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() != frozen.bytes.len() {
        return Err(
            "restored-main terminal hook-time bytes do not decode as one exact instruction"
                .to_owned(),
        );
    }
    if instruction.code() != Code::Call_rm64 || instruction.op0_kind() != OpKind::Register {
        return Ok(None);
    }
    if instruction.stack_pointer_increment() != -8
        || instruction.has_segment_prefix()
        || has_operand_size_override_prefix(&frozen.bytes)
    {
        return Err(format!(
            "restored-main register call has an unsupported encoding: {}",
            format_instruction(&instruction)
        ));
    }
    let target_register = instruction.op0_register().full_register();
    if target_register == Register::RSP {
        return Err("restored-main register call uses RSP as its target".to_owned());
    }
    let target_value = iced_register_value(target_register, final_registers).ok_or_else(|| {
        format!("restored-main register call uses unsupported {target_register:?}")
    })?;
    if register_value(final_registers, RegisterX86::RIP) != Some(target_value) {
        return Err(format!(
            "restored-main register-call target 0x{target_value:016x} disagrees with final RIP"
        ));
    }
    if register_value(final_registers, RegisterX86::RSP) != Some(final_rsp) {
        return Err("restored-main register-call snapshot RSP disagrees with final RSP".to_owned());
    }
    let pushed_return_address = read_u64(emu, final_rsp)?;
    if pushed_return_address != instruction.next_ip() {
        return Err(format!(
            "restored-main register call did not push its fallthrough: expected 0x{:016x}, got 0x{pushed_return_address:016x}",
            instruction.next_ip()
        ));
    }
    Ok(Some(RegisterCallTerminal {
        global_instruction_index: frozen.global_instruction_index,
        instruction_address: last,
        target_register,
        target_value,
        pushed_return_cell: final_rsp,
        pushed_return_address,
    }))
}

fn decode_watch_instruction(hit: &PersistentWatchHit) -> Option<iced_x86::Instruction> {
    let mut decoder = Decoder::with_ip(64, &hit.code_window, hit.rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (!instruction.is_invalid() && instruction.ip() == hit.rip).then_some(instruction)
}

fn is_full_qword_frame_push(entry: &FormattedWatchHit, tail: &[FormattedInstruction]) -> bool {
    if entry.hit.is_write
        || entry.hit.size != 8
        || !tail.iter().any(|instruction| {
            instruction.global_instruction_index == entry.hit.global_instruction_index
                && instruction.address == entry.hit.rip
        })
    {
        return false;
    }
    let Some(instruction) = decode_watch_instruction(&entry.hit) else {
        return false;
    };
    if instruction.code() != Code::Push_rm64
        || instruction.memory_base() == Register::None
        || instruction.memory_base().full_register() == Register::RSP
        || instruction.memory_index() != Register::None
        || instruction.has_segment_prefix()
        || instruction.stack_pointer_increment() != -8
    {
        return false;
    }
    let Some(base) = iced_register_value(instruction.memory_base(), &entry.hit.registers) else {
        return false;
    };
    base.wrapping_add(instruction.memory_displacement64()) == entry.hit.address
}

fn derive_zero_target_provenance(
    main_hits: &[FormattedWatchHit],
    tail: &[FormattedInstruction],
    terminal: RegisterCallTerminal,
) -> Result<Option<ZeroTargetProvenance>, String> {
    if terminal.target_value != 0 {
        return Ok(None);
    }
    let main_stack_end = STACK_BASE
        .checked_add(STACK_SIZE)
        .ok_or_else(|| "main stack range overflows".to_owned())?;
    let mut candidates = Vec::new();
    for (consumer_index, consumer) in main_hits.iter().enumerate() {
        if consumer.hit.value != Some(terminal.target_value)
            || !(STACK_BASE..main_stack_end).contains(&consumer.hit.address)
            || !is_full_qword_frame_push(consumer, tail)
        {
            continue;
        }
        let Some(writer_index) = main_hits[..consumer_index].iter().rposition(|entry| {
            entry.hit.is_write && entry.hit.address == consumer.hit.address && entry.hit.size == 8
        }) else {
            continue;
        };
        let writer = &main_hits[writer_index];
        if writer.hit.value != Some(0) {
            continue;
        }
        let Some(writer_instruction) = decode_watch_instruction(&writer.hit) else {
            continue;
        };
        let mut info_factory = InstructionInfoFactory::new();
        if !info_factory
            .info(&writer_instruction)
            .used_memory()
            .iter()
            .any(|memory| {
                matches!(
                    memory.access(),
                    OpAccess::ReadWrite | OpAccess::ReadCondWrite
                )
            })
        {
            continue;
        }
        if main_hits[writer_index + 1..consumer_index]
            .iter()
            .any(|entry| {
                entry.hit.is_write
                    && access_overlaps(entry.hit.address, entry.hit.size, consumer.hit.address, 8)
            })
        {
            continue;
        }
        let input = main_hits[..writer_index].iter().rev().find(|entry| {
            !entry.hit.is_write
                && entry.hit.global_instruction_index == writer.hit.global_instruction_index
                && entry.hit.rip == writer.hit.rip
                && entry.hit.address == writer.hit.address
                && entry.hit.size == writer.hit.size
        });
        let Some(input) = input else {
            continue;
        };
        let Some(zero_writer_input) = input.hit.value.filter(|value| *value != 0) else {
            continue;
        };
        candidates.push(ZeroTargetProvenance {
            source_cell: consumer.hit.address,
            source_read_rip: consumer.hit.rip,
            source_read_global_instruction_index: consumer.hit.global_instruction_index,
            source_value: terminal.target_value,
            zero_writer_rip: writer.hit.rip,
            zero_writer_global_instruction_index: writer.hit.global_instruction_index,
            zero_writer_input,
            zero_writer_output: 0,
            zero_writer_instruction: writer.instruction.clone(),
        });
    }
    match candidates.as_slice() {
        [] => Ok(None),
        [candidate] => Ok(Some(candidate.clone())),
        _ => Err(format!(
            "restored-main zero provenance has {} source candidates",
            candidates.len()
        )),
    }
}

fn single_added_export_name(
    baseline: &ExportNameControl,
    treatment: &ExportNameControl,
) -> Option<String> {
    if !baseline.module_name.eq_ignore_ascii_case("kernel32.dll")
        || !baseline
            .module_name
            .eq_ignore_ascii_case(&treatment.module_name)
    {
        return None;
    }
    if treatment.names.len() != baseline.names.len() + 1
        || !baseline
            .names
            .iter()
            .all(|name| treatment.names.binary_search(name).is_ok())
    {
        return None;
    }
    treatment
        .names
        .iter()
        .find(|name| baseline.names.binary_search(name).is_err())
        .cloned()
}

fn post_poll_terminal_observation(evidence: &PollWindowEvidence) -> PostPollTerminalObservation {
    PostPollTerminalObservation {
        boundary: evidence.main_boundary.clone(),
        pending_api: evidence.main_pending_api.clone(),
        pending_address: evidence.main_pending_address,
        call: evidence.main_terminal_call,
        tail_rips: evidence
            .main_tail_instructions
            .iter()
            .map(|instruction| instruction.address)
            .collect(),
    }
}

fn validate_post_poll_ab(
    baseline: &PostPollTerminalObservation,
    treatment: &PostPollTerminalObservation,
    added_name: &str,
) -> Result<PostPollAbInvariant, String> {
    let require =
        |condition: bool, message: &str| condition.then_some(()).ok_or_else(|| message.to_owned());
    require(
        baseline.boundary == DiagnosticBoundary::Natural(TrapStop::NullControlTransfer),
        "post-poll baseline is not a natural null",
    )?;
    require(
        baseline.pending_api.is_none() && baseline.pending_address.is_none(),
        "post-poll baseline unexpectedly has a pending stub",
    )?;
    require(
        matches!(
            &treatment.boundary,
            DiagnosticBoundary::PendingApi { name } if name == added_name
        ),
        "post-poll treatment did not stop before the added API",
    )?;
    require(
        treatment.pending_api.as_deref() == Some(added_name),
        "post-poll treatment pending API does not match the added name",
    )?;
    let treatment_pending_address = treatment
        .pending_address
        .ok_or_else(|| "post-poll treatment has no pending stub address".to_owned())?;
    let baseline_call = baseline
        .call
        .ok_or_else(|| "post-poll baseline has no register-call terminal".to_owned())?;
    let treatment_call = treatment
        .call
        .ok_or_else(|| "post-poll treatment has no register-call terminal".to_owned())?;
    require(
        baseline_call.target_value == 0,
        "post-poll baseline target is nonzero",
    )?;
    require(
        treatment_call.target_value != 0
            && treatment_call.target_value == treatment_pending_address,
        "post-poll treatment target is not the named pending stub",
    )?;
    let shape = |call: RegisterCallTerminal| {
        (
            call.instruction_address,
            call.target_register,
            call.pushed_return_cell,
            call.pushed_return_address,
        )
    };
    require(
        shape(baseline_call) == shape(treatment_call),
        "post-poll A/B terminal call shapes differ",
    )?;
    require(
        baseline.tail_rips.len() == POST_POLL_TAIL_LEN
            && treatment.tail_rips.len() == POST_POLL_TAIL_LEN,
        "post-poll A/B terminal tail is not exactly 64 RIPs",
    )?;
    require(
        baseline.tail_rips == treatment.tail_rips,
        "post-poll A/B terminal tails differ",
    )?;
    Ok(PostPollAbInvariant {
        baseline_call,
        treatment_target: treatment_call.target_value,
        tail_digest: trace_digest(&baseline.tail_rips),
    })
}

#[cfg(test)]
fn require_terminal_ret(emu: &Emu, post_time_rips: &[u64]) -> Result<(), String> {
    let last = post_time_rips
        .last()
        .copied()
        .ok_or_else(|| "post-time trace is empty".to_owned())?;
    let bytes = emu
        .read_mem(last, 16)
        .map_err(|error| format!("failed to read final instruction at 0x{last:016x}: {error}"))?;
    let mut decoder = Decoder::with_ip(64, &bytes, last, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let encoded = bytes
        .get(..instruction.len())
        .ok_or_else(|| "decoded terminal instruction exceeds its read window".to_owned())?;
    validate_terminal_ret_instruction(&instruction, encoded, last)
}

fn validate_terminal_ret_instruction(
    instruction: &iced_x86::Instruction,
    encoded: &[u8],
    address: u64,
) -> Result<(), String> {
    let is_qword_near_return = matches!(instruction.code(), Code::Retnq | Code::Retnq_imm16);
    if !is_qword_near_return
        || instruction.stack_pointer_increment() != 8
        || has_operand_size_override_prefix(encoded)
    {
        return Err(format!(
            "terminal-cell derivation requires a qword near RET with zero extra stack adjustment and no operand-size override, found {} at 0x{address:016x}",
            format_instruction(instruction)
        ));
    }
    Ok(())
}

fn has_operand_size_override_prefix(encoded: &[u8]) -> bool {
    let mut operand_size_override = false;
    for byte in encoded {
        match *byte {
            0x66 => operand_size_override = true,
            0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x67 | 0x40..=0x4f => {}
            _ => break,
        }
    }
    operand_size_override
}

fn read_cpu_state(emu: &Emu) -> Result<Vec<(RegisterX86, u64)>, String> {
    CPU_STATE_REGISTERS
        .iter()
        .map(|&register| {
            emu.read_reg(register)
                .map(|value| (register, value))
                .map_err(|error| format!("failed to read {register:?}: {error}"))
        })
        .collect()
}

fn format_tail(
    frozen: &[FrozenInstruction],
    rips: &[u64],
    count: usize,
) -> Result<Vec<FormattedInstruction>, String> {
    let retained = rips.len().min(count);
    if frozen.len() < retained {
        return Err(format!(
            "hook-time instruction tail retained {} entries, expected {retained}",
            frozen.len()
        ));
    }
    let expected = &rips[rips.len() - retained..];
    let frozen = &frozen[frozen.len() - retained..];
    expected
        .iter()
        .zip(frozen)
        .map(|(&expected_address, instruction)| {
            if instruction.address != expected_address {
                return Err(format!(
                    "hook-time instruction tail diverges: expected 0x{expected_address:016x}, got 0x{:016x}",
                    instruction.address
                ));
            }
            format_frozen_instruction(instruction)
        })
        .collect()
}

fn format_frozen_instruction(frozen: &FrozenInstruction) -> Result<FormattedInstruction, String> {
    if frozen.bytes.is_empty() {
        return Err(format!(
            "instruction at 0x{:016x} has no hook-time bytes",
            frozen.address
        ));
    }
    let mut decoder = Decoder::with_ip(64, &frozen.bytes, frozen.address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() != frozen.bytes.len() {
        return Err(format!(
            "hook-time bytes at 0x{:016x} do not decode as one exact instruction",
            frozen.address
        ));
    }
    Ok(FormattedInstruction {
        global_instruction_index: frozen.global_instruction_index,
        address: frozen.address,
        instruction: format_instruction(&instruction),
        writes_r13: Some(instruction_writes_r13(&instruction)),
    })
}

fn instruction_writes_r13(instruction: &iced_x86::Instruction) -> bool {
    let mut factory = InstructionInfoFactory::new();
    factory
        .info(instruction)
        .used_registers()
        .iter()
        .any(|used| {
            used.register().full_register() == Register::R13
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        })
}

fn format_instruction(instruction: &iced_x86::Instruction) -> String {
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
}

fn format_watch_hits(hits: Vec<PersistentWatchHit>) -> Result<Vec<FormattedWatchHit>, String> {
    hits.into_iter()
        .map(|hit| {
            let fallthrough =
                format_instruction_window(&hit.code_window, hit.rip, FROZEN_PATH_INSTRUCTION_CAP);
            let instruction = fallthrough
                .first()
                .filter(|(address, _instruction)| *address == hit.rip)
                .map(|(_address, instruction)| instruction.clone())
                .ok_or_else(|| {
                    format!(
                        "persistent watch hit at 0x{:016x} has no hook-time instruction bytes",
                        hit.rip
                    )
                })?;
            Ok(FormattedWatchHit {
                hit,
                instruction,
                fallthrough,
            })
        })
        .collect()
}

fn format_instruction_window(
    bytes: &[u8],
    address: u64,
    instruction_cap: usize,
) -> Vec<(u64, String)> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() && instructions.len() < instruction_cap {
        let instruction = decoder.decode();
        instructions.push((instruction.ip(), format_instruction(&instruction)));
        if instruction.is_invalid() {
            break;
        }
    }
    instructions
}

fn compare_passes(first: &PassEvidence, second: &PassEvidence) -> Result<(), String> {
    let same = first.main_handled == second.main_handled
        && first.thread_id == second.thread_id
        && first.thread == second.thread
        && first.entry_rsp == second.entry_rsp
        && first.child_prefix_handled == second.child_prefix_handled
        && first.time_return_address == second.time_return_address
        && first.child_tail_handled == second.child_tail_handled
        && first.registered_window_procedures == second.registered_window_procedures
        && first.window_procedure_trace_edges == second.window_procedure_trace_edges
        && first.synthetic_module_image_ranges == second.synthetic_module_image_ranges
        && first.terminal == second.terminal
        && first.terminal_transfer == second.terminal_transfer
        && first.terminal_registers == second.terminal_registers
        && first.terminal_stack_qwords == second.terminal_stack_qwords
        && first.terminal_cell == second.terminal_cell
        && first.terminal_value == second.terminal_value
        && first.child_rips == second.child_rips
        && first.post_time_rips == second.post_time_rips
        && first.tail_instructions == second.tail_instructions
        && first.main_sleep_handled == second.main_sleep_handled
        && first.main_sleep_rips == second.main_sleep_rips;
    if !same {
        return Err("discovery and watched child replays diverged; no provenance claim".to_owned());
    }
    for (name, value) in [
        ("first main stack", first.main_stack_unchanged),
        ("first main TEB", first.main_teb_unchanged),
        ("first main CPU", first.main_cpu_restored),
        ("second main stack", second.main_stack_unchanged),
        ("second main TEB", second.main_teb_unchanged),
        ("second main CPU", second.main_cpu_restored),
    ] {
        if !value {
            return Err(format!("{name} preservation check failed"));
        }
    }
    Ok(())
}

fn validate_watched_replay(pass: &PassEvidence, hit_cap: usize) -> Result<(), String> {
    let spec = pass
        .watch_spec
        .as_ref()
        .ok_or_else(|| "watched replay has no watch specification".to_owned())?;
    if spec.ranges.is_empty() || spec.ranges.iter().any(|(start, end)| end <= start) {
        return Err("watched replay has an empty or reversed range".to_owned());
    }
    if pass.watch_hits.len() >= hit_cap {
        return Err(format!(
            "persistent watch reached its {hit_cap}-hit cap; capture may be truncated"
        ));
    }
    if pass.watch_hits.iter().any(|entry| {
        !spec.ranges.iter().any(|(start, end)| {
            access_overlaps(entry.hit.address, entry.hit.size, *start, *end - *start)
        })
    }) {
        return Err("persistent watch retained an access outside its configured range".to_owned());
    }
    if let Some((start, end)) = spec.global_instruction_range {
        if end <= start {
            return Err("watched replay has an empty global instruction range".to_owned());
        }
        if pass
            .watch_hits
            .iter()
            .any(|entry| !(start..end).contains(&entry.hit.global_instruction_index))
        {
            return Err(
                "persistent watch retained an access outside its global instruction range"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn is_main_poll_compare(entry: &FormattedWatchHit, poll: MainPollObservation) -> bool {
    !entry.hit.is_write
        && entry.hit.size == 1
        && entry.hit.address == poll.address
        && entry.hit.rip == poll.compare_rip
        && is_simple_byte_poll_compare(entry)
}

fn is_simple_byte_poll_compare(entry: &FormattedWatchHit) -> bool {
    is_simple_byte_poll_hit(&entry.hit)
}

fn is_simple_byte_poll_hit(hit: &PersistentWatchHit) -> bool {
    let mut decoder = Decoder::with_ip(64, &hit.code_window, hit.rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    instruction.ip() == hit.rip
        && instruction.code() == Code::Cmp_rm8_r8
        && instruction.memory_index() == Register::None
        && instruction.memory_displacement64() == 0
        && iced_register_value(instruction.memory_base(), &hit.registers) == Some(hit.address)
        && simple_byte_compare_hit_value(hit).is_some()
}

fn simple_byte_compare_value(entry: &FormattedWatchHit) -> Option<u8> {
    simple_byte_compare_hit_value(&entry.hit)
}

fn simple_byte_compare_hit_value(hit: &PersistentWatchHit) -> Option<u8> {
    let mut decoder = Decoder::with_ip(64, &hit.code_window, hit.rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (instruction.ip() == hit.rip && instruction.code() == Code::Cmp_rm8_r8)
        .then(|| iced_byte_register_value(instruction.op1_register(), &hit.registers))?
}

fn iced_register_value(register: Register, registers: &[(RegisterX86, u64)]) -> Option<u64> {
    let register = match register.full_register() {
        Register::RAX => RegisterX86::RAX,
        Register::RBX => RegisterX86::RBX,
        Register::RCX => RegisterX86::RCX,
        Register::RDX => RegisterX86::RDX,
        Register::RSI => RegisterX86::RSI,
        Register::RDI => RegisterX86::RDI,
        Register::RBP => RegisterX86::RBP,
        Register::RSP => RegisterX86::RSP,
        Register::R8 => RegisterX86::R8,
        Register::R9 => RegisterX86::R9,
        Register::R10 => RegisterX86::R10,
        Register::R11 => RegisterX86::R11,
        Register::R12 => RegisterX86::R12,
        Register::R13 => RegisterX86::R13,
        Register::R14 => RegisterX86::R14,
        Register::R15 => RegisterX86::R15,
        _ => return None,
    };
    register_value(registers, register)
}

fn iced_byte_register_value(register: Register, registers: &[(RegisterX86, u64)]) -> Option<u8> {
    let value = iced_register_value(register, registers)?;
    match register {
        Register::AH | Register::BH | Register::CH | Register::DH => Some((value >> 8) as u8),
        Register::AL
        | Register::BL
        | Register::CL
        | Register::DL
        | Register::SIL
        | Register::DIL
        | Register::BPL
        | Register::SPL
        | Register::R8L
        | Register::R9L
        | Register::R10L
        | Register::R11L
        | Register::R12L
        | Register::R13L
        | Register::R14L
        | Register::R15L => Some(value as u8),
        _ => None,
    }
}

fn watched_byte(hit: &PersistentWatchHit, watched_address: u64) -> Option<u8> {
    if hit.size == 0 || hit.size > 8 || watched_address < hit.address {
        return None;
    }
    let offset = usize::try_from(watched_address - hit.address).ok()?;
    if offset >= hit.size {
        return None;
    }
    let value = hit.value?;
    Some((value >> (offset * 8)) as u8)
}

struct IndirectCallObservation<'a> {
    transfer: TerminalTransfer,
    terminal: &'a ChildTerminal,
    terminal_cell: u64,
    terminal_value: u64,
    terminal_source: Option<TerminalSource>,
    watch_phase: Option<WatchPhase>,
    watch_hits: &'a [FormattedWatchHit],
    terminal_registers: &'a [(RegisterX86, u64)],
}

fn validate_indirect_call_frontier(pass: &PassEvidence) -> Result<Option<usize>, String> {
    validate_indirect_call_observation(IndirectCallObservation {
        transfer: pass.terminal_transfer,
        terminal: &pass.terminal,
        terminal_cell: pass.terminal_cell,
        terminal_value: pass.terminal_value,
        terminal_source: pass.terminal_source,
        watch_phase: pass.watch_spec.as_ref().map(|spec| spec.phase),
        watch_hits: &pass.watch_hits,
        terminal_registers: &pass.terminal_registers,
    })
}

fn validate_indirect_call_observation(
    observation: IndirectCallObservation<'_>,
) -> Result<Option<usize>, String> {
    let TerminalTransfer::IndirectCall {
        instruction_address,
        pointer_cell,
        pushed_return_address,
    } = observation.transfer
    else {
        return Err("call frontier is not an indirect call".to_owned());
    };
    let terminal_matches_value = matches!(
        (observation.terminal, observation.terminal_value),
        (ChildTerminal::NullControlTransfer, 0)
            | (ChildTerminal::UnhandledApi { .. }, 1..=u64::MAX)
    );
    if !terminal_matches_value
        || observation.terminal_cell != pointer_cell
        || observation.terminal_source.is_some()
    {
        return Err(format!(
            "indirect-call frontier has inconsistent terminal evidence: terminal={:?}, cell=0x{:016x}, pointer_cell=0x{pointer_cell:016x}, value=0x{:016x}, source={:?}",
            observation.terminal,
            observation.terminal_cell,
            observation.terminal_value,
            observation.terminal_source
        ));
    }
    if observation.watch_phase != Some(WatchPhase::BeforeMain) {
        return Err("indirect-call pointer watch was not active for the whole run".to_owned());
    }
    let matching_read_indices = observation
        .watch_hits
        .iter()
        .enumerate()
        .filter(|entry| {
            let entry = entry.1;
            !entry.hit.is_write
                && entry.hit.address == pointer_cell
                && entry.hit.size == 8
                && entry.hit.value == Some(observation.terminal_value)
                && entry.hit.rip == instruction_address
                && entry.instruction.starts_with("call qword [rdi+")
        })
        .map(|(index, _entry)| index)
        .collect::<Vec<_>>();
    if matching_read_indices.len() != 1
        || matching_read_indices[0].checked_add(1) != Some(observation.watch_hits.len())
    {
        return Err(format!(
            "whole-run watch did not isolate exactly one final indirect-call read: {matching_read_indices:?}"
        ));
    }
    let call_read_index = matching_read_indices[0];
    let call_read = &observation.watch_hits[call_read_index];
    let final_rsp = register_value(observation.terminal_registers, RegisterX86::RSP)
        .ok_or_else(|| "indirect-call terminal snapshot is missing RSP".to_owned())?;
    let expected_pre_call_rsp = final_rsp
        .checked_add(8)
        .ok_or_else(|| "indirect-call pre-call RSP overflows".to_owned())?;
    if register_value(&call_read.hit.registers, RegisterX86::RSP) != Some(expected_pre_call_rsp)
        || register_value(&call_read.hit.registers, RegisterX86::RDI)
            != register_value(observation.terminal_registers, RegisterX86::RDI)
        || pushed_return_address == 0
    {
        return Err(
            "indirect-call watch snapshot does not match the final call transition".to_owned(),
        );
    }
    let writer_index = observation.watch_hits[..call_read_index]
        .iter()
        .rposition(|entry| entry.hit.is_write);
    if let Some(writer_index) = writer_index {
        if observation.watch_hits[writer_index + 1..call_read_index]
            .iter()
            .any(|entry| entry.hit.is_write)
        {
            return Err("a later pointer-cell write follows the selected writer".to_owned());
        }
    }
    Ok(writer_index)
}

fn validate_handler_slot_replay(pass: &PassEvidence, source: TerminalSource) -> Result<(), String> {
    let final_read_index = pass
        .watch_hits
        .iter()
        .rposition(|entry| is_terminal_handler_read(entry, source));
    let Some(final_read_index) = final_read_index else {
        return Err(format!(
            "whole-run watch did not capture the terminal dispatcher read from 0x{:016x}",
            source.handler_slot
        ));
    };
    let writer_index = pass.watch_hits[..final_read_index]
        .iter()
        .rposition(|entry| entry.hit.is_write)
        .ok_or_else(|| {
            "handler-slot watch captured no writer before the terminal read".to_owned()
        })?;
    if pass.watch_hits[writer_index + 1..]
        .iter()
        .any(|entry| entry.hit.is_write)
    {
        return Err(
            "handler-slot watch captured a later write after the selected writer".to_owned(),
        );
    }
    Ok(())
}

fn validate_terminal_register_path(
    pass: &PassEvidence,
    source: TerminalSource,
) -> Result<(), String> {
    let handler_read = pass
        .watch_hits
        .iter()
        .rfind(|entry| is_terminal_handler_read(entry, source))
        .ok_or_else(|| "terminal R13 path has no exact handler-slot read".to_owned())?;
    let writer_index = pass
        .tail_instructions
        .iter()
        .rposition(|entry| {
            entry.address == source.writer_rip && entry.instruction == "mov [rsi],r13"
        })
        .ok_or_else(|| {
            "terminal R13 path has no terminal-cell writer in the frozen tail".to_owned()
        })?;
    let read_index = pass.tail_instructions[..writer_index]
        .iter()
        .rposition(|entry| {
            entry.address == handler_read.hit.rip && entry.instruction == handler_read.instruction
        })
        .ok_or_else(|| "terminal R13 path has no handler read in the frozen tail".to_owned())?;
    let trace_delta = u64::try_from(writer_index - read_index)
        .map_err(|error| format!("terminal R13 trace delta does not fit u64: {error}"))?;
    let global_delta = source
        .writer_global_instruction_index
        .checked_sub(handler_read.hit.global_instruction_index)
        .ok_or_else(|| "terminal-cell writer precedes its handler-slot read".to_owned())?;
    if trace_delta != global_delta {
        return Err(format!(
            "terminal R13 tail does not match watched global chronology: tail={trace_delta}, global={global_delta}"
        ));
    }
    for entry in &pass.tail_instructions[read_index + 1..writer_index] {
        match entry.writes_r13 {
            Some(false) => {}
            Some(true) => {
                return Err(format!(
                    "terminal R13 value is clobbered at 0x{:016x}: {}",
                    entry.address, entry.instruction
                ));
            }
            None => {
                return Err(format!(
                    "terminal R13 path is unreadable at 0x{:016x}",
                    entry.address
                ));
            }
        }
    }
    Ok(())
}

fn derive_handler_writer_source(
    pass: &PassEvidence,
    source: TerminalSource,
) -> Result<Option<HandlerWriterSource>, String> {
    let Some(writer) = last_write_before_terminal_read(pass, source) else {
        return Ok(None);
    };
    if writer.instruction != "mov [r9],rbx" {
        return Err(format!(
            "handler slot's last writer has an unmodeled instruction shape: {} at 0x{:016x}",
            writer.instruction, writer.hit.rip
        ));
    }
    let destination = register_value(&writer.hit.registers, RegisterX86::R9)
        .ok_or_else(|| "handler writer snapshot is missing R9".to_owned())?;
    let rbp = register_value(&writer.hit.registers, RegisterX86::RBP)
        .ok_or_else(|| "handler writer snapshot is missing RBP".to_owned())?;
    let selector_register = register_value(&writer.hit.registers, RegisterX86::R12)
        .ok_or_else(|| "handler writer snapshot is missing R12".to_owned())?;
    let selector_field_address = register_value(&writer.hit.registers, RegisterX86::RSI)
        .ok_or_else(|| "handler writer snapshot is missing RSI".to_owned())?;
    let source_value = register_value(&writer.hit.registers, RegisterX86::RBX)
        .ok_or_else(|| "handler writer snapshot is missing RBX".to_owned())?;
    if destination != source.handler_slot || source_value != source.handler_value {
        return Err(format!(
            "handler writer registers disagree with the watched edge: R9=0x{destination:016x}, RBX=0x{source_value:016x}"
        ));
    }
    let source_selector = selector_register as u16;
    let source_context_address = rbp
        .checked_add(u64::from(source_selector))
        .ok_or_else(|| "handler writer source selector overflows RBP".to_owned())?;
    Ok(Some(HandlerWriterSource {
        writer_rip: writer.hit.rip,
        writer_global_instruction_index: writer.hit.global_instruction_index,
        vm_context_base: rbp,
        selector_field_address,
        source_selector,
        source_context_address,
        source_value,
    }))
}

fn derive_source_context_producer(
    pass: &PassEvidence,
    source: HandlerWriterSource,
    source_read_index: usize,
) -> Result<SourceContextProducer, String> {
    let writer = pass.watch_hits[..source_read_index]
        .iter()
        .rfind(|entry| {
            entry.hit.is_write
                && access_overlaps(
                    entry.hit.address,
                    entry.hit.size,
                    source.source_context_address,
                    8,
                )
        })
        .ok_or_else(|| {
            "source-context watch captured no writer before its selected read".to_owned()
        })?;
    if writer.hit.address != source.source_context_address
        || writer.hit.size != 8
        || writer.hit.value != Some(source.source_value)
        || writer.instruction != "mov [rcx],r15"
        || register_value(&writer.hit.registers, RegisterX86::RCX)
            != Some(source.source_context_address)
        || register_value(&writer.hit.registers, RegisterX86::R15) != Some(source.source_value)
    {
        return Err(format!(
            "source context's last writer has an unmodeled shape: {writer:?}"
        ));
    }
    let rsp = register_value(&writer.hit.registers, RegisterX86::RSP)
        .ok_or_else(|| "source-context writer snapshot is missing RSP".to_owned())?;
    let stack_cell = rsp.checked_sub(8).ok_or_else(|| {
        format!("source-context writer RSP cannot identify a prior pop: 0x{rsp:016x}")
    })?;
    Ok(SourceContextProducer {
        writer_rip: writer.hit.rip,
        writer_global_instruction_index: writer.hit.global_instruction_index,
        context_address: source.source_context_address,
        value: source.source_value,
        stack_cell,
    })
}

fn validate_source_stack_edge(
    pass: &PassEvidence,
    source: SourceContextProducer,
) -> Result<StackCellProducer, String> {
    let context_writer_index = pass.watch_hits.iter().rposition(|entry| {
        entry.hit.is_write
            && entry.hit.address == source.context_address
            && entry.hit.size == 8
            && entry.hit.value == Some(source.value)
            && entry.hit.rip == source.writer_rip
            && entry.hit.global_instruction_index == source.writer_global_instruction_index
            && entry.instruction == "mov [rcx],r15"
            && register_value(&entry.hit.registers, RegisterX86::RCX)
                == Some(source.context_address)
            && register_value(&entry.hit.registers, RegisterX86::R15) == Some(source.value)
    });
    let Some(context_writer_index) = context_writer_index else {
        return Err("source stack replay did not capture the context writer".to_owned());
    };
    let pop_index = pass.watch_hits[..context_writer_index]
        .iter()
        .rposition(|entry| {
            !entry.hit.is_write
                && entry.hit.address == source.stack_cell
                && entry.hit.size == 8
                && entry.hit.value == Some(source.value)
                && entry.instruction == "pop r15"
                && register_value(&entry.hit.registers, RegisterX86::RSP) == Some(source.stack_cell)
        });
    let Some(pop_index) = pop_index else {
        return Err("source stack replay did not capture the pop into R15".to_owned());
    };
    let pop = &pass.watch_hits[pop_index];
    let context_writer = &pass.watch_hits[context_writer_index];
    if pop.hit.global_instruction_index.checked_add(1)
        != Some(context_writer.hit.global_instruction_index)
        || pop
            .fallthrough
            .get(1)
            .map(|(address, instruction)| (*address, instruction.as_str()))
            != Some((context_writer.hit.rip, context_writer.instruction.as_str()))
    {
        return Err("pop into R15 does not flow directly into the context writer".to_owned());
    }
    let expected_writer_rsp = source
        .stack_cell
        .checked_add(8)
        .ok_or_else(|| "source stack-cell pop overflows RSP".to_owned())?;
    if register_value(&context_writer.hit.registers, RegisterX86::RSP) != Some(expected_writer_rsp)
    {
        return Err("source context writer RSP does not reflect one consumed qword".to_owned());
    }

    let stack_writer = pass.watch_hits[..pop_index]
        .iter()
        .rfind(|entry| {
            entry.hit.is_write
                && access_overlaps(entry.hit.address, entry.hit.size, source.stack_cell, 8)
        })
        .ok_or_else(|| "source stack replay captured no prior stack-cell writer".to_owned())?;
    if stack_writer.hit.address != source.stack_cell
        || stack_writer.hit.size != 8
        || stack_writer.hit.value != Some(source.value)
        || stack_writer.instruction != "pop qword [rsp+80h]"
    {
        return Err(format!(
            "source stack cell's last writer has an unmodeled shape: {stack_writer:?}"
        ));
    }
    let source_cell = register_value(&stack_writer.hit.registers, RegisterX86::RSP)
        .ok_or_else(|| "stack-cell writer snapshot is missing RSP".to_owned())?;
    Ok(StackCellProducer {
        writer_rip: stack_writer.hit.rip,
        writer_global_instruction_index: stack_writer.hit.global_instruction_index,
        destination_cell: source.stack_cell,
        value: source.value,
        source_cell,
    })
}

fn validate_stack_value_from_rax(
    hits: &[FormattedWatchHit],
    producer: StackCellProducer,
) -> Result<RaxStackProducer, String> {
    let global = producer.writer_global_instruction_index;
    let final_read_index = hits.iter().position(|entry| {
        !entry.hit.is_write
            && entry.hit.global_instruction_index == global
            && entry.hit.rip == producer.writer_rip
            && entry.hit.address == producer.source_cell
            && entry.hit.size == 8
            && entry.hit.value == Some(producer.value)
    });
    let Some(final_read_index) = final_read_index else {
        return Err("upstream replay did not capture the selected stack-transfer read".to_owned());
    };
    let final_write_index = hits.iter().position(|entry| {
        entry.hit.is_write
            && entry.hit.global_instruction_index == global
            && entry.hit.rip == producer.writer_rip
            && entry.hit.address == producer.destination_cell
            && entry.hit.size == 8
            && entry.hit.value == Some(producer.value)
    });
    let Some(final_write_index) = final_write_index else {
        return Err("upstream replay did not capture the selected stack-transfer write".to_owned());
    };
    if final_read_index >= final_write_index {
        return Err("stack-transfer write was not observed after its source read".to_owned());
    }
    let final_read = &hits[final_read_index];
    let final_write = &hits[final_write_index];
    if final_read.instruction != final_write.instruction
        || final_read.hit.registers != final_write.hit.registers
    {
        return Err("stack-transfer read/write halves have divergent instruction state".to_owned());
    }
    let displacement = parse_pop_rsp_displacement(&final_read.instruction).ok_or_else(|| {
        format!(
            "stack transfer is not a modeled qword pop through RSP: {}",
            final_read.instruction
        )
    })?;
    let expected_destination = producer
        .source_cell
        .checked_add(8)
        .and_then(|rsp_after_pop| rsp_after_pop.checked_add(displacement))
        .ok_or_else(|| "stack-transfer destination arithmetic overflows".to_owned())?;
    if expected_destination != producer.destination_cell {
        return Err(format!(
            "stack-transfer destination does not match post-pop RSP plus displacement: expected 0x{expected_destination:016x}, got 0x{:016x}",
            producer.destination_cell
        ));
    }
    for register in [RegisterX86::RAX, RegisterX86::R8] {
        if register_value(&final_read.hit.registers, register) != Some(producer.value) {
            return Err(format!(
                "stack-transfer snapshot does not carry the selected value in {register:?}"
            ));
        }
    }
    if register_value(&final_read.hit.registers, RegisterX86::RSP) != Some(producer.source_cell) {
        return Err("stack-transfer snapshot RSP does not identify its source cell".to_owned());
    }

    let source_write_index = hits[..final_read_index]
        .iter()
        .rposition(|entry| {
            entry.hit.is_write
                && access_overlaps(entry.hit.address, entry.hit.size, producer.source_cell, 8)
        })
        .ok_or_else(|| "upstream replay captured no write to the transfer source".to_owned())?;
    let source_write = &hits[source_write_index];
    if source_write.hit.global_instruction_index.checked_add(1) != Some(global)
        || source_write.hit.address != producer.source_cell
        || source_write.hit.size != 8
        || source_write.hit.value != Some(producer.value)
        || source_write.instruction != "mov [rsp],r8"
        || register_value(&source_write.hit.registers, RegisterX86::RSP)
            != Some(producer.source_cell)
        || register_value(&source_write.hit.registers, RegisterX86::RAX) != Some(producer.value)
        || register_value(&source_write.hit.registers, RegisterX86::R8) != Some(producer.value)
        || source_write
            .fallthrough
            .get(1)
            .map(|(rip, instruction)| (*rip, instruction.as_str()))
            != Some((producer.writer_rip, final_read.instruction.as_str()))
    {
        return Err(format!(
            "stack-transfer source writer has an unmodeled shape: {source_write:?}"
        ));
    }

    let immediate_push_index = hits[..source_write_index]
        .iter()
        .rposition(|entry| {
            entry.hit.is_write
                && access_overlaps(entry.hit.address, entry.hit.size, producer.source_cell, 8)
        })
        .ok_or_else(|| {
            "upstream replay captured no scaffolding push before the source writer".to_owned()
        })?;
    let immediate_push = &hits[immediate_push_index];
    let pre_push_rsp = producer
        .source_cell
        .checked_add(8)
        .ok_or_else(|| "scaffolding push RSP overflows".to_owned())?;
    if immediate_push.hit.global_instruction_index.checked_add(2) != Some(global)
        || immediate_push.hit.address != producer.source_cell
        || immediate_push.hit.size != 8
        || !immediate_push.instruction.starts_with("push ")
        || immediate_push.instruction == "push r8"
        || register_value(&immediate_push.hit.registers, RegisterX86::RSP) != Some(pre_push_rsp)
        || register_value(&immediate_push.hit.registers, RegisterX86::RAX) != Some(producer.value)
        || register_value(&immediate_push.hit.registers, RegisterX86::R8) != Some(producer.value)
    {
        return Err(format!(
            "stack-transfer scaffolding push has an unmodeled shape: {immediate_push:?}"
        ));
    }
    let immediate_path = immediate_push
        .fallthrough
        .get(..3)
        .ok_or_else(|| "scaffolding push has an incomplete frozen fallthrough".to_owned())?;
    if immediate_path[0].0 != immediate_push.hit.rip
        || immediate_path[0].1 != immediate_push.instruction
        || immediate_path[1] != (source_write.hit.rip, source_write.instruction.clone())
        || immediate_path[2] != (producer.writer_rip, final_read.instruction.clone())
    {
        return Err(
            "scaffolding push does not flow through the selected stack transfer".to_owned(),
        );
    }

    let preserve_read_index = hits[..immediate_push_index]
        .iter()
        .rposition(|entry| {
            !entry.hit.is_write
                && access_overlaps(entry.hit.address, entry.hit.size, producer.source_cell, 8)
        })
        .ok_or_else(|| "upstream replay captured no R8-preservation pop".to_owned())?;
    let preserve_read = &hits[preserve_read_index];
    let preserve_write_index = hits[..preserve_read_index]
        .iter()
        .rposition(|entry| {
            entry.hit.is_write
                && access_overlaps(entry.hit.address, entry.hit.size, producer.source_cell, 8)
        })
        .ok_or_else(|| "upstream replay captured no R8-preservation push".to_owned())?;
    let preserve_write = &hits[preserve_write_index];
    if preserve_write.hit.global_instruction_index.checked_add(5) != Some(global)
        || preserve_read.hit.global_instruction_index.checked_add(4) != Some(global)
        || preserve_write.hit.address != producer.source_cell
        || preserve_write.hit.size != 8
        || preserve_write.instruction != "push r8"
        || register_value(&preserve_write.hit.registers, RegisterX86::RSP) != Some(pre_push_rsp)
        || register_value(&preserve_write.hit.registers, RegisterX86::RAX) != Some(producer.value)
        || preserve_write.hit.value
            != register_value(&preserve_write.hit.registers, RegisterX86::R8)
        || preserve_read.hit.address != producer.source_cell
        || preserve_read.hit.size != 8
        || preserve_read.instruction != "pop qword [rsp]"
        || preserve_read.hit.value != preserve_write.hit.value
        || register_value(&preserve_read.hit.registers, RegisterX86::RSP)
            != Some(producer.source_cell)
        || register_value(&preserve_read.hit.registers, RegisterX86::RAX) != Some(producer.value)
    {
        return Err("R8 preservation around the RAX transfer has an unmodeled shape".to_owned());
    }
    let preserve_path = preserve_write
        .fallthrough
        .get(..4)
        .ok_or_else(|| "R8-preservation push has an incomplete frozen fallthrough".to_owned())?;
    if preserve_path[0] != (preserve_write.hit.rip, "push r8".to_owned())
        || preserve_path[1] != (preserve_read.hit.rip, "pop qword [rsp]".to_owned())
        || preserve_path[2].1 != "mov r8,rax"
        || preserve_path[3].0 != immediate_push.hit.rip
        || preserve_path[3].1 != immediate_push.instruction
    {
        return Err("frozen path does not carry RAX through R8 into the stack transfer".to_owned());
    }

    let expected_writes = [
        (
            preserve_write.hit.global_instruction_index,
            producer.source_cell,
        ),
        (
            immediate_push.hit.global_instruction_index,
            producer.source_cell,
        ),
        (
            source_write.hit.global_instruction_index,
            producer.source_cell,
        ),
        (global, producer.destination_cell),
    ];
    let observed_writes = hits
        .iter()
        .filter(|entry| {
            entry.hit.is_write
                && (preserve_write.hit.global_instruction_index..=global)
                    .contains(&entry.hit.global_instruction_index)
                && (access_overlaps(entry.hit.address, entry.hit.size, producer.source_cell, 8)
                    || access_overlaps(
                        entry.hit.address,
                        entry.hit.size,
                        producer.destination_cell,
                        8,
                    ))
        })
        .map(|entry| (entry.hit.global_instruction_index, entry.hit.address))
        .collect::<Vec<_>>();
    if observed_writes != expected_writes {
        return Err(format!(
            "stack-transfer path contains conflicting watched writes: {observed_writes:?}"
        ));
    }

    Ok(RaxStackProducer {
        path_start_rip: preserve_write.hit.rip,
        path_start_global_instruction_index: preserve_write.hit.global_instruction_index,
        value: producer.value,
    })
}

fn parse_pop_rsp_displacement(instruction: &str) -> Option<u64> {
    let digits = instruction
        .strip_prefix("pop qword [rsp+")?
        .strip_suffix("h]")?;
    u64::from_str_radix(digits, 16).ok()
}

fn validated_source_edge_indices(
    pass: &PassEvidence,
    terminal: TerminalSource,
    source: HandlerWriterSource,
) -> Result<[usize; 4], String> {
    let slot_index = pass.watch_hits.iter().rposition(|entry| {
        entry.hit.is_write
            && entry.instruction == "mov [r9],rbx"
            && entry.hit.address == terminal.handler_slot
            && entry.hit.size == 8
            && entry.hit.value == Some(source.source_value)
            && entry.hit.rip == source.writer_rip
            && entry.hit.global_instruction_index == source.writer_global_instruction_index
            && register_value(&entry.hit.registers, RegisterX86::RBP)
                == Some(source.vm_context_base)
            && register_value(&entry.hit.registers, RegisterX86::R9) == Some(terminal.handler_slot)
            && register_value(&entry.hit.registers, RegisterX86::RBX) == Some(source.source_value)
    });
    let Some(slot_index) = slot_index else {
        return Err(
            "dynamically rearmed source watch did not capture the handler-slot store".to_owned(),
        );
    };
    let source_read_index = pass.watch_hits[..slot_index].iter().rposition(|entry| {
        !entry.hit.is_write
            && entry.instruction == "mov rbx,[rbx]"
            && entry.hit.address == source.source_context_address
            && entry.hit.size == 8
            && entry.hit.value == Some(source.source_value)
            && register_value(&entry.hit.registers, RegisterX86::RBP)
                == Some(source.vm_context_base)
            && register_value(&entry.hit.registers, RegisterX86::RBX)
                == Some(source.source_context_address)
    });
    let Some(source_read_index) = source_read_index else {
        return Err(
            "dynamically rearmed source watch did not capture the source-context read".to_owned(),
        );
    };
    let selector_read_index = pass.watch_hits[..source_read_index]
        .iter()
        .rposition(|entry| {
            !entry.hit.is_write
                && entry.instruction == "movzx rbx,word [rbx]"
                && entry.hit.address == source.selector_field_address
                && entry.hit.size == 2
                && entry.hit.value == Some(u64::from(source.source_selector))
                && register_value(&entry.hit.registers, RegisterX86::RBP)
                    == Some(source.vm_context_base)
                && register_value(&entry.hit.registers, RegisterX86::RBX)
                    == Some(source.selector_field_address)
        });
    let Some(selector_read_index) = selector_read_index else {
        return Err(
            "dynamically rearmed source watch did not capture the selector-field read".to_owned(),
        );
    };
    let selector_write_index = pass.watch_hits[..selector_read_index]
        .iter()
        .rposition(|entry| {
            entry.hit.is_write
                && entry.instruction == "mov [rsi],r12w"
                && entry.hit.address == source.selector_field_address
                && entry.hit.size == 2
                && entry.hit.value == Some(u64::from(source.source_selector))
                && register_value(&entry.hit.registers, RegisterX86::RBP)
                    == Some(source.vm_context_base)
                && register_value(&entry.hit.registers, RegisterX86::RSI)
                    == Some(source.selector_field_address)
                && register_value(&entry.hit.registers, RegisterX86::R12).map(|value| value as u16)
                    == Some(source.source_selector)
        });
    let Some(selector_write_index) = selector_write_index else {
        return Err(
            "dynamically rearmed source watch did not capture the complete selector/read/store edge"
                .to_owned(),
        );
    };

    let indices = [
        pass.watch_hits[selector_write_index]
            .hit
            .global_instruction_index,
        pass.watch_hits[selector_read_index]
            .hit
            .global_instruction_index,
        pass.watch_hits[source_read_index]
            .hit
            .global_instruction_index,
        pass.watch_hits[slot_index].hit.global_instruction_index,
    ];
    if !indices.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(format!(
            "source-edge events are not strictly ordered: {indices:?}"
        ));
    }
    if pass.watch_hits[selector_write_index + 1..selector_read_index]
        .iter()
        .any(|entry| {
            entry.hit.is_write
                && access_overlaps(
                    entry.hit.address,
                    entry.hit.size,
                    source.selector_field_address,
                    2,
                )
        })
    {
        return Err("source selector was overwritten before its read".to_owned());
    }
    if pass.watch_hits[selector_read_index + 1..source_read_index]
        .iter()
        .any(|entry| {
            entry.hit.is_write
                && access_overlaps(
                    entry.hit.address,
                    entry.hit.size,
                    source.source_context_address,
                    8,
                )
        })
    {
        return Err("source context was overwritten before its read".to_owned());
    }
    if pass.watch_hits[source_read_index + 1..slot_index]
        .iter()
        .any(|entry| {
            entry.hit.is_write
                && access_overlaps(entry.hit.address, entry.hit.size, terminal.handler_slot, 8)
        })
    {
        return Err(
            "handler slot was written between the source read and selected store".to_owned(),
        );
    }
    validate_source_register_path(
        &pass.watch_hits[selector_read_index],
        &pass.watch_hits[source_read_index],
        &pass.watch_hits[slot_index],
    )?;
    Ok([
        selector_write_index,
        selector_read_index,
        source_read_index,
        slot_index,
    ])
}

fn validate_source_register_path(
    selector_read: &FormattedWatchHit,
    source_read: &FormattedWatchHit,
    slot_write: &FormattedWatchHit,
) -> Result<(), String> {
    let expected = [
        (selector_read.hit.rip, selector_read.instruction.as_str()),
        (0, "add rbx,rbp"),
        (source_read.hit.rip, source_read.instruction.as_str()),
        (slot_write.hit.rip, slot_write.instruction.as_str()),
    ];
    if selector_read.fallthrough.len() < expected.len() {
        return Err("source-edge frozen instruction path is incomplete".to_owned());
    }
    for (position, ((actual_address, actual), (expected_address, expected))) in
        selector_read.fallthrough.iter().zip(expected).enumerate()
    {
        if (expected_address != 0 && *actual_address != expected_address) || actual != expected {
            return Err(format!(
                "source-edge frozen instruction {position} has unexpected shape: 0x{actual_address:016x}: {actual}"
            ));
        }
    }
    let selector_global = selector_read.hit.global_instruction_index;
    let expected_source_global = selector_global
        .checked_add(2)
        .ok_or_else(|| "source-edge instruction index overflows".to_owned())?;
    let expected_slot_global = selector_global
        .checked_add(3)
        .ok_or_else(|| "source-edge instruction index overflows".to_owned())?;
    if source_read.hit.global_instruction_index != expected_source_global
        || slot_write.hit.global_instruction_index != expected_slot_global
    {
        return Err(format!(
            "source-edge watch events do not follow the frozen straight-line path: selector={}, source={}, slot={}",
            selector_global,
            source_read.hit.global_instruction_index,
            slot_write.hit.global_instruction_index
        ));
    }
    Ok(())
}

fn is_terminal_handler_read(entry: &FormattedWatchHit, source: TerminalSource) -> bool {
    !entry.hit.is_write
        && entry.hit.address == source.handler_slot
        && entry.hit.size == 8
        && entry.hit.value == Some(source.handler_value)
        && entry.instruction == "mov r13,[r13]"
        && register_value(&entry.hit.registers, RegisterX86::R13) == Some(source.handler_slot)
}

fn access_overlaps(address: u64, size: usize, watched: u64, watched_size: u64) -> bool {
    let Ok(size) = u64::try_from(size) else {
        return false;
    };
    let Some(access_end) = address.checked_add(size) else {
        return watched >= address;
    };
    let Some(watched_end) = watched.checked_add(watched_size) else {
        return access_end > watched;
    };
    address < watched_end && watched < access_end
}

fn trace_digest(rips: &[u64]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325u64;
    for rip in rips {
        digest = fnv1a_update(digest, &rip.to_le_bytes());
    }
    digest
}

fn fnv1a_update(mut digest: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

fn print_indirect_call_frontier_summary(
    config: &Config,
    image: &PeImage,
    first: &PassEvidence,
    whole_run: &PassEvidence,
    writer_index: Option<usize>,
    module_watch: Option<&PassEvidence>,
) {
    let TerminalTransfer::IndirectCall {
        instruction_address,
        pointer_cell,
        pushed_return_address,
    } = first.terminal_transfer
    else {
        unreachable!("indirect-call summary requires an indirect-call terminal");
    };
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("child_per_leg_cap:     {}", config.child_per_leg_cap);
    println!("watch_hit_cap:         {}", config.watch_hit_cap);
    print_export_name_control(config);
    println!("main_prefix_calls:     {}", first.main_handled.len());
    println!("main_pending_api:      Sleep");
    println!("thread_id:             {}", first.thread_id);
    println!(
        "thread_start:          0x{:016x}",
        first.thread.start_address
    );
    println!("thread_parameter:      0x{:016x}", first.thread.parameter);
    println!("child_entry_rsp:       0x{:016x}", first.entry_rsp);
    println!("child_prefix_apis:     {:?}", first.child_prefix_handled);
    println!("child_tail_apis:       {:?}", first.child_tail_handled);
    println!(
        "registered_wndprocs:    {:?}",
        first.registered_window_procedures
    );
    println!(
        "wndproc_trace_edges:    {:?}",
        first.window_procedure_trace_edges
    );
    println!("child_terminal:        {:?}", first.terminal);
    println!("terminal_transfer:     indirect qword call");
    println!("terminal_instruction:  0x{instruction_address:016x}");
    println!("terminal_pointer_cell: 0x{pointer_cell:016x}");
    println!("terminal_value:        0x{:016x}", first.terminal_value);
    println!("pushed_return_address: 0x{pushed_return_address:016x}");
    println!(
        "terminal_stack_qwords: [{}]",
        format_qwords(&first.terminal_stack_qwords)
    );
    for (label, register) in [
        ("terminal_rax", RegisterX86::RAX),
        ("terminal_rcx", RegisterX86::RCX),
        ("terminal_rdx", RegisterX86::RDX),
        ("terminal_r8", RegisterX86::R8),
        ("terminal_r9", RegisterX86::R9),
        ("terminal_rdi", RegisterX86::RDI),
        ("terminal_rsp", RegisterX86::RSP),
        ("terminal_rip", RegisterX86::RIP),
    ] {
        if let Some(value) = register_value(&first.terminal_registers, register) {
            println!("{label:<22} 0x{value:016x}");
        }
    }
    println!("child_rips:            {}", first.child_rips.len());
    println!(
        "child_digest:          0x{:016x}",
        trace_digest(&first.child_rips)
    );
    println!("post_time_rips:        {}", first.post_time_rips.len());
    println!(
        "post_time_digest:      0x{:016x}",
        trace_digest(&first.post_time_rips)
    );
    println!("main_stack_unchanged:  {}", first.main_stack_unchanged);
    println!("main_teb_unchanged:    {}", first.main_teb_unchanged);
    println!("main_cpu_restored:     {}", first.main_cpu_restored);
    println!("main_sleep_rips:       {}", first.main_sleep_rips.len());
    println!(
        "main_sleep_digest:     0x{:016x}",
        trace_digest(&first.main_sleep_rips)
    );
    println!("terminal tail:");
    for entry in &first.tail_instructions {
        println!("  0x{:016x}: {}", entry.address, entry.instruction);
    }
    print_watch_hits("child-TEB access hits", &first.watch_hits);
    print_watch_hits(
        "whole-run indirect-call pointer watch hits",
        &whole_run.watch_hits,
    );
    match writer_index.map(|index| &whole_run.watch_hits[index]) {
        Some(writer) => {
            println!("last_guest_writer:     0x{:016x}", writer.hit.rip);
            println!(
                "last_writer_global:     {}",
                writer.hit.global_instruction_index
            );
            println!(
                "last_writer_value:      {}",
                format_optional_value(writer.hit.value)
            );
            println!("last_writer_insn:       {}", writer.instruction);
        }
        None => println!("last_guest_writer:     <none observed after watch arming>"),
    }
    println!(
        "pointer_cell_writes:   {}",
        whole_run
            .watch_hits
            .iter()
            .filter(|entry| entry.hit.is_write)
            .count()
    );
    println!(
        "pointer_cell_reads:    {}",
        whole_run
            .watch_hits
            .iter()
            .filter(|entry| !entry.hit.is_write)
            .count()
    );
    println!("whole_run_watch:       true");
    match (module_watch, config.export_name_control.as_ref()) {
        (Some(pass), _) => {
            print_module_writer_provenance(pass, &first.synthetic_module_image_ranges)
        }
        (None, Some(_)) => {
            println!("resolver_module_watch: skipped under export-name control")
        }
        (None, None) => {}
    }
    println!("replays_identical:     true");
}

fn print_module_writer_provenance(pass: &PassEvidence, modules: &[(String, u64, u64)]) {
    let Some(writer_index) = pass.watch_hits.iter().rposition(|entry| {
        entry.hit.is_write
            && entry.hit.address == pass.terminal_cell
            && entry.hit.size == 8
            && entry.hit.value == Some(pass.terminal_value)
    }) else {
        println!("resolver_module_watch: <terminal writer absent>");
        return;
    };

    let mut counts = vec![0usize; modules.len()];
    let mut last = None;
    for entry in &pass.watch_hits[..writer_index] {
        if let Some((module_index, module)) =
            modules.iter().enumerate().find(|(_, (_, start, end))| {
                access_overlaps(
                    entry.hit.address,
                    entry.hit.size,
                    *start,
                    end.saturating_sub(*start),
                )
            })
        {
            counts[module_index] += 1;
            last = Some((module, entry));
        }
    }

    println!("resolver_watch_hits:   {}", pass.watch_hits.len());
    println!("resolver_watch_cap:    {MAX_WATCH_HIT_CAP}");
    let summary = modules
        .iter()
        .zip(counts)
        .filter(|(_, count)| *count != 0)
        .map(|((name, _, _), count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("resolver_module_hits:  [{summary}]");
    match last {
        Some(((name, start, _), entry)) => {
            println!("last_resolver_module:  {name:?}");
            println!(
                "last_resolver_access:  global {} addr 0x{:016x} rva 0x{:x}",
                entry.hit.global_instruction_index,
                entry.hit.address,
                entry.hit.address.saturating_sub(*start)
            );
            println!("last_resolver_insn:    {}", entry.instruction);
        }
        None => println!("last_resolver_module:  <none in writer leg>"),
    }
}

fn print_poll_window_summary(
    config: &Config,
    image: &PeImage,
    evidence: &PollWindowEvidence,
    controls: &PollWindowControls,
    invariant: &PostPollAbInvariant,
) {
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("child_per_leg_cap:     {}", config.child_per_leg_cap);
    println!("watch_hit_cap:         {}", config.watch_hit_cap);
    println!("poll_window_only:      true");
    println!("window_control_module: \"user32.dll\"");
    println!("window_control_names:  3");
    println!(
        "ab_controls:           module={:?} names={}->{} added={:?}",
        controls.baseline.module_name,
        controls.baseline.names.len(),
        controls.treatment.names.len(),
        controls.added_name
    );
    println!(
        "main_prefix_calls:     {}",
        evidence.main_prefix_handled.len()
    );
    println!("main_pending_api:      Sleep");
    println!("poll_cell:             0x{:016x}", evidence.poll.address);
    println!(
        "poll_compare_rip:      0x{:016x}",
        evidence.poll.compare_rip
    );
    println!(
        "poll_compared_value:   0x{:02x}",
        evidence.poll.compared_value
    );
    println!("poll_final:            0x{:02x}", evidence.poll_final);
    println!("thread_id:             {}", evidence.thread_id);
    println!(
        "thread_start:          0x{:016x}",
        evidence.thread.start_address
    );
    println!("child_apis:            {:?}", evidence.child_handled);
    println!("child_pending_api:     CreateWindowExA");
    println!(
        "create_window_args:    ex=0x{:x} class=0x{:016x} title=0x{:016x} style=0x{:x} x=0x{:x} y=0x{:x} width=0x{:x} height=0x{:x} parent=0x{:016x} menu=0x{:016x} instance=0x{:016x} param=0x{:016x}",
        evidence.create_window.extended_style,
        evidence.create_window.class_name,
        evidence.create_window.window_name,
        evidence.create_window.style,
        evidence.create_window.x,
        evidence.create_window.y,
        evidence.create_window.width,
        evidence.create_window.height,
        evidence.create_window.parent,
        evidence.create_window.menu,
        evidence.create_window.instance,
        evidence.create_window.parameter,
    );
    println!(
        "create_window_return:  0x{:016x}",
        evidence.create_window.return_address
    );
    println!(
        "registered_wndproc:    0x{:016x}",
        evidence.window_procedure
    );
    println!(
        "writer_classification: {}",
        match evidence.release_writer_index {
            Some(index)
                if (evidence.post_create_hit_start..evidence.post_create_hit_end)
                    .contains(&index)
                    && evidence.poll_final != evidence.poll.compared_value
                    && evidence.instructions_past_poll > 0 =>
            {
                "post-CreateWindowExA child store"
            }
            Some(index)
                if (evidence.post_create_hit_start..evidence.post_create_hit_end)
                    .contains(&index) =>
            {
                "post-CreateWindowExA child transient store; main release not observed"
            }
            Some(_) => "non-child release-valued store",
            None => "no release-valued guest writer observed",
        }
    );
    println!(
        "release_writer_index:  {}",
        evidence
            .release_writer_index
            .map_or_else(|| "<none>".to_owned(), |index| index.to_string())
    );
    println!("diagnostic_hwnd:       0x{DIAGNOSTIC_WINDOW_HANDLE:016x}");
    println!("post_create_handled:   {:?}", evidence.post_create_handled);
    println!("post_create_boundary:  {:?}", evidence.post_create_boundary);
    println!(
        "post_create_hits:      {}..{}",
        evidence.post_create_hit_start, evidence.post_create_hit_end
    );
    println!("post_create_rips:      {}", evidence.post_create_rips.len());
    println!(
        "post_create_digest:    0x{:016x}",
        trace_digest(&evidence.post_create_rips)
    );
    println!("main_boundary:         {:?}", evidence.main_boundary);
    println!("main_handled:          {:?}", evidence.main_handled);
    println!("main_pending_api:      {:?}", evidence.main_pending_api);
    println!("restored_main_cap:     {}", evidence.restored_main_cap);
    println!("main_rips:             {}", evidence.main_rips.len());
    println!(
        "main_digest:           0x{:016x}",
        trace_digest(&evidence.main_rips)
    );
    println!(
        "instructions_past_poll: {}",
        evidence.instructions_past_poll
    );
    let tail_rips = evidence
        .main_tail_instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect::<Vec<_>>();
    println!("main_tail_rips:        {}", tail_rips.len());
    println!("main_tail_digest:      0x{:016x}", trace_digest(&tail_rips));
    match evidence.main_terminal_call {
        Some(call) => {
            println!(
                "main_terminal_call:    global {} 0x{:016x}: call {:?} -> 0x{:016x}",
                call.global_instruction_index,
                call.instruction_address,
                call.target_register,
                call.target_value
            );
            println!(
                "main_call_fallthrough: cell=0x{:016x} value=0x{:016x}",
                call.pushed_return_cell, call.pushed_return_address
            );
        }
        None => println!("main_terminal_call:    <not a register call>"),
    }
    match &evidence.zero_target_provenance {
        Some(source) => {
            println!(
                "zero_target_writer:    global {} 0x{:016x}: {} input=0x{:016x} output=0x{:016x}",
                source.zero_writer_global_instruction_index,
                source.zero_writer_rip,
                source.zero_writer_instruction,
                source.zero_writer_input,
                source.zero_writer_output
            );
            println!(
                "zero_target_consumer:  global {} 0x{:016x} cell=0x{:016x} value=0x{:016x}",
                source.source_read_global_instruction_index,
                source.source_read_rip,
                source.source_cell,
                source.source_value
            );
        }
        None => println!("zero_target_writer:    <not applicable>"),
    }
    println!(
        "ab_terminal:           call=0x{:016x} register={:?} cell=0x{:016x} fallthrough=0x{:016x} target=0x{:016x}->0x{:016x}",
        invariant.baseline_call.instruction_address,
        invariant.baseline_call.target_register,
        invariant.baseline_call.pushed_return_cell,
        invariant.baseline_call.pushed_return_address,
        invariant.baseline_call.target_value,
        invariant.treatment_target
    );
    println!("ab_tail_digest:        0x{:016x}", invariant.tail_digest);
    println!(
        "post_poll_ab_invariant: same call site/register/pushed cell/fallthrough/exact 64-RIP tail; only target changed zero-to-named-stub"
    );
    println!(
        "post_poll_classification: (b) missing API/return: {}",
        controls.added_name
    );
    println!("poll watch hits:");
    for (index, entry) in evidence.hits.iter().enumerate() {
        let Some(watched_value) = watched_byte(&entry.hit, evidence.poll.address) else {
            continue;
        };
        let phase = if index < evidence.post_create_hit_start {
            "main-or-child-prefix".to_owned()
        } else if (evidence.post_create_hit_start..evidence.post_create_hit_end).contains(&index) {
            "post-CreateWindowExA-child".to_owned()
        } else {
            "restored-main".to_owned()
        };
        let operation = if entry.hit.is_write { "W" } else { "R" };
        println!(
            "  [{:>12}] phase={phase} {operation} addr=0x{:016x} size={} access_value={} poll_byte=0x{watched_value:02x} rip=0x{:016x}",
            entry.hit.global_instruction_index,
            entry.hit.address,
            entry.hit.size,
            format_optional_value(entry.hit.value),
            entry.hit.rip,
        );
        println!("      insn: {}", entry.instruction);
        println!("      regs: {}", format_registers(&entry.hit.registers));
    }
}

#[allow(clippy::too_many_arguments)]
fn print_production_bounded_frontier_summary(
    config: &Config,
    image: &PeImage,
    discovery: &CooperativeTrapRun,
    total_instructions: u64,
    synthetic_module_image_ranges: &[(String, u64, u64)],
    registers: &[(RegisterX86, u64)],
) {
    let rip = register_value(registers, RegisterX86::RIP).unwrap_or(0);
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("production_terminal:   not reached before bound");
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("production_api_bound:  {PRODUCTION_API_BOUND}");
    print_export_name_control(config);
    println!("handled_apis:          {:?}", discovery.handled);
    println!("cooperative_yields:    {:?}", discovery.cooperative_yields);
    println!(
        "main_after_yield:      {}",
        discovery.main_instructions_after_first_yield
    );
    println!("stop:                  {:?}", discovery.stop);
    println!("total_instructions:    {total_instructions}");
    println!("frontier_rip:          0x{rip:016x}");
    println!(
        "frontier_provenance:   {}",
        format_runtime_address_provenance(image, synthetic_module_image_ranges, rip)
    );
    println!("frontier_registers:    {}", format_registers(registers));
    println!(
        "frontier_fs_gs:        fs_base=0x{:016x} gs_base=0x{:016x}",
        register_value(registers, RegisterX86::FS_BASE).unwrap_or(0),
        register_value(registers, RegisterX86::GS_BASE).unwrap_or(0),
    );
    println!("terminal_tail:         unavailable because discovery stopped at a bound");
}

#[allow(clippy::too_many_arguments)]
fn print_production_terminal_summary(
    config: &Config,
    image: &PeImage,
    discovery: &CooperativeTrapRun,
    total_instructions: u64,
    suffix_cap: u64,
    synthetic_module_image_ranges: &[(String, u64, u64)],
    terminal_registers: &[(RegisterX86, u64)],
    frozen_tail: &[FrozenInstruction],
    tail: &[FormattedInstruction],
    transfer: ProductionTerminalTransfer,
    terminal_stub_name: Option<&str>,
    consumed_edge: Option<&ProductionConsumedCellEdge>,
) {
    let terminal_frozen = frozen_tail
        .last()
        .expect("production terminal tail was validated before printing");
    let tail_rips = tail.iter().map(|entry| entry.address).collect::<Vec<_>>();
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("production_terminal:   true");
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("suffix_trace_cap:      {suffix_cap}");
    println!("production_api_bound:  {PRODUCTION_API_BOUND}");
    print_export_name_control(config);
    println!("handled_apis:          {:?}", discovery.handled);
    println!("cooperative_yields:    {:?}", discovery.cooperative_yields);
    println!(
        "main_after_yield:      {}",
        discovery.main_instructions_after_first_yield
    );
    println!("stop:                  {:?}", discovery.stop);
    println!("total_instructions:    {total_instructions}");
    println!("terminal_tail_rips:    {}", tail.len());
    println!("terminal_tail_digest:  0x{:016x}", trace_digest(&tail_rips));
    println!(
        "terminal_source:       global {} 0x{:016x}: {}",
        transfer.global_instruction_index(),
        transfer.instruction_address(),
        tail.last()
            .map(|entry| entry.instruction.as_str())
            .unwrap_or("<missing>")
    );
    println!(
        "terminal_source_bytes: {}",
        format_hex_bytes(&terminal_frozen.bytes)
    );
    println!(
        "source_provenance:     {}",
        format_runtime_address_provenance(
            image,
            synthetic_module_image_ranges,
            transfer.instruction_address(),
        )
    );
    match transfer {
        ProductionTerminalTransfer::NearReturn {
            consumed_cell,
            target_value,
            ..
        } => {
            println!("terminal_transfer:     qword near return");
            println!("consumed_cell:         0x{consumed_cell:016x}");
            println!("consumed_value:        0x{target_value:016x}");
        }
        ProductionTerminalTransfer::RegisterCall(call) => {
            println!(
                "terminal_transfer:     call {:?} -> 0x{:016x}",
                call.target_register, call.target_value
            );
            println!(
                "pushed_return:         cell=0x{:016x} value=0x{:016x}",
                call.pushed_return_cell, call.pushed_return_address
            );
        }
        ProductionTerminalTransfer::IndirectCall {
            pointer_cell,
            target_value,
            pushed_return_cell,
            pushed_return_address,
            ..
        } => {
            println!("terminal_transfer:     indirect qword call");
            println!("pointer_cell:          0x{pointer_cell:016x}");
            println!("pointer_value:         0x{target_value:016x}");
            println!(
                "pushed_return:         cell=0x{pushed_return_cell:016x} value=0x{pushed_return_address:016x}"
            );
        }
    }
    match terminal_stub_name {
        Some(name) => println!(
            "target_provenance:     synthetic callable stub name={name:?} address=0x{:016x}",
            transfer.target_value()
        ),
        None => println!(
            "target_provenance:     {}",
            format_runtime_address_provenance(
                image,
                synthetic_module_image_ranges,
                transfer.target_value(),
            )
        ),
    }
    println!(
        "terminal_registers:    {}",
        format_registers(terminal_registers)
    );
    println!(
        "terminal_fs_gs:        fs_base=0x{:016x} gs_base=0x{:016x}",
        register_value(terminal_registers, RegisterX86::FS_BASE).unwrap_or(0),
        register_value(terminal_registers, RegisterX86::GS_BASE).unwrap_or(0),
    );
    match consumed_edge {
        Some(edge) => {
            println!(
                "consumed_writer:       global {} 0x{:016x}: {} value={}",
                edge.writer.hit.global_instruction_index,
                edge.writer.hit.rip,
                edge.writer.instruction,
                format_optional_value(edge.writer.hit.value),
            );
            println!(
                "writer_provenance:     {}",
                format_runtime_address_provenance(
                    image,
                    synthetic_module_image_ranges,
                    edge.writer.hit.rip,
                )
            );
            println!(
                "writer_registers:      {}",
                format_registers(&edge.writer.hit.registers)
            );
            println!(
                "consumed_reader:       global {} 0x{:016x}: {} value={}",
                edge.consumer.hit.global_instruction_index,
                edge.consumer.hit.rip,
                edge.consumer.instruction,
                format_optional_value(edge.consumer.hit.value),
            );
            println!(
                "writer_to_reader:      {} instructions",
                edge.consumer
                    .hit
                    .global_instruction_index
                    .saturating_sub(edge.writer.hit.global_instruction_index)
            );
        }
        None => println!("consumed_writer:       <transfer has no consumed return cell>"),
    }
    println!("terminal tail:");
    for entry in tail {
        println!(
            "  global {} 0x{:016x}: {}",
            entry.global_instruction_index, entry.address, entry.instruction
        );
    }
}

fn format_runtime_address_provenance(
    image: &PeImage,
    synthetic_module_image_ranges: &[(String, u64, u64)],
    address: u64,
) -> String {
    if let Some(rva) = address.checked_sub(image.image_base) {
        if rva < u64::from(image.size_of_image) {
            if let Ok(rva32) = u32::try_from(rva) {
                if let Some(section) = image.section_containing_rva(rva32) {
                    return format!(
                        "image section={:?} rva=0x{rva32:08x} characteristics=0x{:08x}",
                        section.name, section.characteristics
                    );
                }
            }
            return format!("image headers/gap rva=0x{rva:08x}");
        }
    }
    if let Some((name, start, _end)) = synthetic_module_image_ranges
        .iter()
        .find(|(_name, start, end)| *start <= address && address < *end)
    {
        return format!("synthetic module={name:?} offset=0x{:x}", address - start);
    }
    "outside image and synthetic modules".to_owned()
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn print_frontier_only_summary(config: &Config, image: &PeImage, first: &PassEvidence) {
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("child_per_leg_cap:     {}", config.child_per_leg_cap);
    println!("watch_hit_cap:         {}", config.watch_hit_cap);
    println!("frontier_only:         true");
    print_export_name_control(config);
    println!("main_prefix_calls:     {}", first.main_handled.len());
    println!("main_pending_api:      Sleep");
    println!("thread_id:             {}", first.thread_id);
    println!(
        "thread_start:          0x{:016x}",
        first.thread.start_address
    );
    println!("thread_parameter:      0x{:016x}", first.thread.parameter);
    println!("child_entry_rsp:       0x{:016x}", first.entry_rsp);
    println!("child_prefix_apis:     {:?}", first.child_prefix_handled);
    println!("child_tail_apis:       {:?}", first.child_tail_handled);
    println!(
        "registered_wndprocs:    {:?}",
        first.registered_window_procedures
    );
    println!(
        "wndproc_trace_edges:    {:?}",
        first.window_procedure_trace_edges
    );
    println!("child_terminal:        {:?}", first.terminal);
    println!("terminal_transfer:     {:?}", first.terminal_transfer);
    println!("terminal_cell:         0x{:016x}", first.terminal_cell);
    println!("terminal_value:        0x{:016x}", first.terminal_value);
    println!(
        "terminal_stack_qwords: [{}]",
        format_qwords(&first.terminal_stack_qwords)
    );
    for (label, register) in [
        ("terminal_rax", RegisterX86::RAX),
        ("terminal_rcx", RegisterX86::RCX),
        ("terminal_rdx", RegisterX86::RDX),
        ("terminal_r8", RegisterX86::R8),
        ("terminal_r9", RegisterX86::R9),
        ("terminal_rdi", RegisterX86::RDI),
        ("terminal_rsp", RegisterX86::RSP),
        ("terminal_rip", RegisterX86::RIP),
    ] {
        println!(
            "{label:<22}0x{:016x}",
            register_value(&first.terminal_registers, register).unwrap_or(0)
        );
    }
    println!("child_rips:            {}", first.child_rips.len());
    println!(
        "child_digest:          0x{:016x}",
        trace_digest(&first.child_rips)
    );
    println!("post_time_rips:        {}", first.post_time_rips.len());
    println!(
        "post_time_digest:      0x{:016x}",
        trace_digest(&first.post_time_rips)
    );
    println!("main_stack_unchanged:  {}", first.main_stack_unchanged);
    println!("main_teb_unchanged:    {}", first.main_teb_unchanged);
    println!("main_cpu_restored:     {}", first.main_cpu_restored);
    println!("main_sleep_rips:       {}", first.main_sleep_rips.len());
    println!(
        "main_sleep_digest:     0x{:016x}",
        trace_digest(&first.main_sleep_rips)
    );
    println!("terminal tail:");
    for entry in &first.tail_instructions {
        println!("  0x{:016x}: {}", entry.address, entry.instruction);
    }
    print_watch_hits("child-TEB access hits", &first.watch_hits);
    println!("provenance_replays:    skipped by --frontier-only");
}

fn print_summary(
    config: &Config,
    image: &PeImage,
    first: &PassEvidence,
    evidence: &SummaryEvidence<'_>,
) {
    let source = evidence
        .terminal_watch
        .terminal_source
        .expect("terminal source was validated before summary output");
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("child_per_leg_cap:     {}", config.child_per_leg_cap);
    println!("watch_hit_cap:         {}", config.watch_hit_cap);
    print_export_name_control(config);
    println!("main_prefix_calls:     {}", first.main_handled.len());
    println!("main_pending_api:      Sleep");
    println!("thread_id:             {}", first.thread_id);
    println!(
        "thread_start:          0x{:016x}",
        first.thread.start_address
    );
    println!("thread_parameter:      0x{:016x}", first.thread.parameter);
    println!("child_entry_rsp:       0x{:016x}", first.entry_rsp);
    println!("child_return_sentinel: 0x{CHILD_RETURN_SENTINEL:016x}");
    println!("child_prefix_apis:     {:?}", first.child_prefix_handled);
    println!(
        "time_return_address:   0x{:016x}",
        first.time_return_address
    );
    println!("child_tail_apis:       {:?}", first.child_tail_handled);
    println!("child_terminal:        {:?}", first.terminal);
    println!("terminal_transfer:     {:?}", first.terminal_transfer);
    for (label, register) in [
        ("terminal_rax", RegisterX86::RAX),
        ("terminal_rcx", RegisterX86::RCX),
        ("terminal_rdx", RegisterX86::RDX),
        ("terminal_r8", RegisterX86::R8),
        ("terminal_r9", RegisterX86::R9),
        ("terminal_rsp", RegisterX86::RSP),
        ("terminal_rip", RegisterX86::RIP),
    ] {
        if let Some(value) = register_value(&first.terminal_registers, register) {
            println!("{label:<22} 0x{value:016x}");
        }
    }
    println!("terminal_cell:         0x{:016x}", first.terminal_cell);
    println!("terminal_value:        0x{:016x}", first.terminal_value);
    println!("terminal_writer:       0x{:016x}", source.writer_rip);
    println!("terminal_bytecode:     0x{:016x}", source.bytecode_cursor);
    println!("selector_address:      0x{:016x}", source.selector_address);
    println!("terminal_selector:     0x{:04x}", source.selector);
    println!("context_address:       0x{:016x}", source.context_address);
    println!("handler_slot:          0x{:016x}", source.handler_slot);
    println!("handler_value:         0x{:016x}", source.handler_value);
    println!(
        "handler_last_writer:   0x{:016x}",
        evidence.handler_writer.writer_rip
    );
    println!(
        "handler_writer_global: {}",
        evidence.handler_writer.writer_global_instruction_index
    );
    println!(
        "source_selector:       0x{:04x}",
        evidence.handler_writer.source_selector
    );
    println!(
        "source_context:        0x{:016x}",
        evidence.handler_writer.source_context_address
    );
    println!(
        "source_value:          0x{:016x}",
        evidence.handler_writer.source_value
    );
    println!(
        "source_last_writer:    0x{:016x}",
        evidence.source_producer.writer_rip
    );
    println!(
        "source_writer_global:  {}",
        evidence.source_producer.writer_global_instruction_index
    );
    println!(
        "source_stack_cell:     0x{:016x}",
        evidence.source_producer.stack_cell
    );
    println!(
        "stack_last_writer:     0x{:016x}",
        evidence.stack_producer.writer_rip
    );
    println!(
        "stack_writer_global:   {}",
        evidence.stack_producer.writer_global_instruction_index
    );
    println!(
        "upstream_stack_cell:   0x{:016x}",
        evidence.stack_producer.source_cell
    );
    println!(
        "rax_path_start:        0x{:016x}",
        evidence.rax_producer.path_start_rip
    );
    println!(
        "rax_path_global:       {}",
        evidence.rax_producer.path_start_global_instruction_index
    );
    println!(
        "rax_path_value:        0x{:016x}",
        evidence.rax_producer.value
    );
    println!("child_rips:            {}", first.child_rips.len());
    println!(
        "child_digest:          0x{:016x}",
        trace_digest(&first.child_rips)
    );
    println!("post_time_rips:        {}", first.post_time_rips.len());
    println!(
        "post_time_digest:      0x{:016x}",
        trace_digest(&first.post_time_rips)
    );
    println!("main_stack_unchanged:  {}", first.main_stack_unchanged);
    println!("main_teb_unchanged:    {}", first.main_teb_unchanged);
    println!("main_cpu_restored:     {}", first.main_cpu_restored);
    println!("main_sleep_rips:       {}", first.main_sleep_rips.len());
    println!(
        "main_sleep_digest:     0x{:016x}",
        trace_digest(&first.main_sleep_rips)
    );

    println!("terminal tail:");
    for entry in &first.tail_instructions {
        println!("  0x{:016x}: {}", entry.address, entry.instruction);
    }

    print_watch_hits(
        "terminal-cell watch hits",
        &evidence.terminal_watch.watch_hits,
    );
    let terminal_writes = evidence
        .terminal_watch
        .watch_hits
        .iter()
        .filter(|entry| entry.hit.is_write)
        .count();
    let terminal_reads = evidence
        .terminal_watch
        .watch_hits
        .iter()
        .filter(|entry| !entry.hit.is_write)
        .count();
    println!("terminal_cell_writes:  {terminal_writes}");
    println!("terminal_cell_reads:   {terminal_reads}");

    print_watch_hits(
        "handler-slot whole-run watch hits",
        &evidence.handler_watch.watch_hits,
    );
    let handler_writes = evidence
        .handler_watch
        .watch_hits
        .iter()
        .filter(|entry| entry.hit.is_write)
        .count();
    let handler_reads = evidence
        .handler_watch
        .watch_hits
        .iter()
        .filter(|entry| !entry.hit.is_write)
        .count();
    println!("handler_slot_writes:   {handler_writes}");
    println!("handler_slot_reads:    {handler_reads}");
    if let Some(writer) = last_write_before_terminal_read(evidence.handler_watch, source) {
        println!("handler_watch_writer:  0x{:016x}", writer.hit.rip);
        println!(
            "handler_watch_value:   {}",
            format_optional_value(writer.hit.value)
        );
    } else {
        println!("handler_watch_writer:  <none observed>");
    }
    let source_edge_indices =
        validated_source_edge_indices(evidence.source_watch, source, evidence.handler_writer)
            .expect("source edge was validated before summary output");
    let source_edge_hits = source_edge_indices
        .into_iter()
        .map(|index| evidence.source_watch.watch_hits[index].clone())
        .collect::<Vec<_>>();
    print_watch_hits(
        "source-edge dynamically rearmed watch hits",
        &source_edge_hits,
    );
    let stack_edge_hits = evidence
        .stack_watch
        .watch_hits
        .iter()
        .filter(|entry| {
            entry.hit.global_instruction_index
                >= evidence
                    .source_producer
                    .writer_global_instruction_index
                    .saturating_sub(16)
                && entry.hit.global_instruction_index
                    <= evidence.source_producer.writer_global_instruction_index
        })
        .cloned()
        .collect::<Vec<_>>();
    print_watch_hits("source stack-edge watch hits", &stack_edge_hits);
    let source_pop_index = evidence.stack_watch.watch_hits.iter().rposition(|entry| {
        !entry.hit.is_write
            && entry.hit.address == evidence.source_producer.stack_cell
            && entry.hit.size == 8
            && entry.hit.value == Some(evidence.source_producer.value)
            && entry.instruction == "pop r15"
            && entry.hit.global_instruction_index + 1
                == evidence.source_producer.writer_global_instruction_index
    });
    if let Some(source_pop_index) = source_pop_index {
        let stack_cell_writer = evidence.stack_watch.watch_hits[..source_pop_index]
            .iter()
            .rfind(|entry| {
                entry.hit.is_write
                    && access_overlaps(
                        entry.hit.address,
                        entry.hit.size,
                        evidence.source_producer.stack_cell,
                        8,
                    )
            })
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        print_watch_hits("source stack-cell last writer", &stack_cell_writer);
    }
    println!(
        "stack_watch_retained:   {}",
        evidence.stack_watch.watch_hits.len()
    );
    let upstream_edge_hits = evidence
        .upstream_stack_watch
        .watch_hits
        .iter()
        .filter(|entry| {
            entry.hit.global_instruction_index
                == evidence.stack_producer.writer_global_instruction_index
        })
        .cloned()
        .collect::<Vec<_>>();
    print_watch_hits("upstream stack-edge watch hits", &upstream_edge_hits);
    if let Some(source_read_index) =
        evidence
            .upstream_stack_watch
            .watch_hits
            .iter()
            .rposition(|entry| {
                !entry.hit.is_write
                    && entry.hit.address == evidence.stack_producer.source_cell
                    && entry.hit.size == 8
                    && entry.hit.value == Some(evidence.stack_producer.value)
                    && entry.hit.global_instruction_index
                        == evidence.stack_producer.writer_global_instruction_index
            })
    {
        let upstream_writer = evidence.upstream_stack_watch.watch_hits[..source_read_index]
            .iter()
            .rfind(|entry| {
                entry.hit.is_write
                    && access_overlaps(
                        entry.hit.address,
                        entry.hit.size,
                        evidence.stack_producer.source_cell,
                        8,
                    )
            })
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        print_watch_hits("upstream stack-cell last writer", &upstream_writer);
    }
    println!(
        "upstream_watch_retained: {}",
        evidence.upstream_stack_watch.watch_hits.len()
    );
    println!(
        "source_watch_retained:  {}",
        evidence.source_watch.watch_hits.len()
    );
    println!("replays_identical:     true");
}

fn print_watch_hits(label: &str, hits: &[FormattedWatchHit]) {
    println!("{label}:");
    if hits.is_empty() {
        println!("  <none>");
        return;
    }
    for entry in hits {
        let operation = if entry.hit.is_write { "W" } else { "R" };
        println!(
            "  [{:>12}] {operation} addr=0x{:016x} size={} value={} rip=0x{:016x}",
            entry.hit.global_instruction_index,
            entry.hit.address,
            entry.hit.size,
            format_optional_value(entry.hit.value),
            entry.hit.rip,
        );
        println!("      insn: {}", entry.instruction);
        println!("      regs: {}", format_registers(&entry.hit.registers));
    }
}

fn last_write_before_terminal_read(
    pass: &PassEvidence,
    source: TerminalSource,
) -> Option<&FormattedWatchHit> {
    let read_index = pass
        .watch_hits
        .iter()
        .rposition(|entry| is_terminal_handler_read(entry, source))?;
    pass.watch_hits[..read_index]
        .iter()
        .rev()
        .find(|entry| entry.hit.is_write)
}

fn format_optional_value(value: Option<u64>) -> String {
    value.map_or_else(|| "None".to_owned(), |value| format!("Some(0x{value:x})"))
}

fn print_export_name_control(config: &Config) {
    match &config.export_name_control {
        Some(control) => {
            println!("export_control_module: {:?}", control.module_name);
            println!("export_control_names:  {}", control.names.len());
        }
        None => println!("export_control_module: <none>"),
    }
}

fn format_qwords(values: &[u64]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:016x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_registers(registers: &[(RegisterX86, u64)]) -> String {
    let mut output = String::new();
    for (index, (register, name)) in DISPLAY_REGISTERS.iter().enumerate() {
        if index != 0 {
            output.push(' ');
        }
        let value = registers
            .iter()
            .find_map(|(candidate, value)| (candidate == register).then_some(*value));
        match value {
            Some(value) => output.push_str(&format!("{name}=0x{value:016x}")),
            None => output.push_str(&format!("{name}=<missing>")),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_layout_is_disjoint_aligned_and_has_shadow_space() {
        let stack_end = CHILD_STACK_BASE + CHILD_STACK_SIZE;
        let entry_rsp = stack_end - CHILD_ENTRY_HEADROOM - 8;
        assert_eq!(entry_rsp & 0xf, 8);
        assert!(entry_rsp >= CHILD_STACK_BASE);
        assert!(entry_rsp + 0x28 < stack_end);
        assert!(CHILD_TEB_BASE >= stack_end);
        assert!(CHILD_TEB_BASE + CHILD_TEB_SIZE <= STACK_BASE);
        assert_ne!(CHILD_RETURN_SENTINEL, 0);
    }

    #[test]
    fn trailing_mode_parser_accepts_only_one_production_terminal_mode() {
        let mut production = vec!["60000000".to_owned(), "--production-terminal".to_owned()];
        assert_eq!(
            parse_trailing_modes(&mut production).unwrap(),
            (false, false, true)
        );
        assert_eq!(production, ["60000000"]);

        let mut combined = vec![
            "--poll-window".to_owned(),
            "--production-terminal".to_owned(),
        ];
        assert!(parse_trailing_modes(&mut combined).is_err());

        let mut duplicate = vec![
            "--production-terminal".to_owned(),
            "--production-terminal".to_owned(),
        ];
        assert!(parse_trailing_modes(&mut duplicate).is_err());
    }

    #[test]
    fn production_terminal_classifier_requires_frozen_zero_near_return() {
        const CODE_BASE: u64 = 0x0000_0000_0110_0000;
        let initial_rsp = STACK_BASE + 0x8000;
        let mut code = vec![0x90; PRODUCTION_TERMINAL_TAIL_LEN - 1];
        code.extend_from_slice(&[0xc2, 0x00, 0x00]);
        let image = PeImage {
            image_base: CODE_BASE,
            entry_point_rva: 0,
            base_of_code: 0,
            size_of_code: 0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_headers: 0,
            size_of_image: 0x1000,
            subsystem: 3,
            sections: Vec::new(),
        };
        let mut emu = Emu::new().unwrap();
        emu.map_code(CODE_BASE, &code).unwrap();
        emu.write_mem(initial_rsp, &0u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RSP, initial_rsp).unwrap();
        emu.install_code_trace_hook().unwrap();
        let mut env = Win64Env::new(CODE_BASE);
        let result = run_with_import_trap(&mut env, &mut emu, &image, CODE_BASE, 128, 1).unwrap();
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        let rips = emu.executed_addresses();
        let registers = read_cpu_state(&emu).unwrap();
        let frozen = emu.recent_instructions();
        assert_eq!(rips.len(), PRODUCTION_TERMINAL_TAIL_LEN);
        assert_eq!(frozen.len(), PRODUCTION_TERMINAL_TAIL_LEN);
        assert_eq!(
            classify_production_terminal_transfer(&emu, &result.stop, &rips, &registers, &frozen,)
                .unwrap(),
            ProductionTerminalTransfer::NearReturn {
                global_instruction_index: PRODUCTION_TERMINAL_TAIL_LEN as u64,
                instruction_address: CODE_BASE + (PRODUCTION_TERMINAL_TAIL_LEN - 1) as u64,
                consumed_cell: initial_rsp,
                target_value: 0,
            }
        );

        assert!(classify_production_terminal_transfer(
            &emu,
            &TrapStop::InstructionCap,
            &rips,
            &registers,
            &frozen[..frozen.len() - 1],
        )
        .is_err());
    }

    #[test]
    fn production_consumed_edge_requires_exact_writer_and_reader() {
        let cell = STACK_BASE + 0x9000;
        let writer_index = 70;
        let reader_index = 101;
        let transfer = ProductionTerminalTransfer::NearReturn {
            global_instruction_index: reader_index,
            instruction_address: 0x2000,
            consumed_cell: cell,
            target_value: 0,
        };
        let raw_hits = vec![
            PersistentWatchHit {
                global_instruction_index: writer_index,
                is_write: true,
                address: cell,
                size: 8,
                rip: 0x1000,
                value: Some(0),
                registers: vec![(RegisterX86::RSI, cell), (RegisterX86::R13, 0)],
                code_window: vec![0x4c, 0x89, 0x2e], // mov [rsi],r13
            },
            PersistentWatchHit {
                global_instruction_index: reader_index,
                is_write: false,
                address: cell,
                size: 8,
                rip: 0x2000,
                value: Some(0),
                registers: vec![(RegisterX86::RSP, cell)],
                code_window: vec![0xc2, 0x00, 0x00], // ret 0
            },
        ];
        let hits = format_watch_hits(raw_hits).unwrap();
        let edge = classify_production_consumed_cell_edge(&hits, transfer, 64).unwrap();
        assert_eq!(edge.writer.hit.global_instruction_index, writer_index);
        assert_eq!(edge.consumer.hit.global_instruction_index, reader_index);

        let mut wrong_source = hits.clone();
        wrong_source[0].hit.registers[1].1 = 1;
        assert!(classify_production_consumed_cell_edge(&wrong_source, transfer, 64).is_err());

        let mut wrong_reader = hits;
        wrong_reader[1].hit.value = Some(1);
        assert!(classify_production_consumed_cell_edge(&wrong_reader, transfer, 64).is_err());
    }

    #[test]
    fn terminal_cell_requires_space_for_a_consumed_qword() {
        assert_eq!(terminal_cell(0x1008).unwrap(), 0x1000);
        assert!(terminal_cell(7).is_err());
    }

    #[test]
    fn fnv1a_update_matches_published_byte_vector() {
        assert_eq!(
            fnv1a_update(0xcbf2_9ce4_8422_2325, b"hello"),
            0xa430_d846_80aa_bd0b
        );
    }

    #[test]
    fn hit_cap_is_nonzero_and_bounded() {
        assert_eq!(validate_hit_cap(1).unwrap(), 1);
        assert_eq!(
            validate_hit_cap(MAX_WATCH_HIT_CAP).unwrap(),
            MAX_WATCH_HIT_CAP
        );
        assert!(validate_hit_cap(0).is_err());
        assert!(validate_hit_cap(MAX_WATCH_HIT_CAP + 1).is_err());
    }

    #[test]
    fn export_name_control_parser_requires_sorted_unique_printable_names() {
        assert_eq!(
            parse_export_name_control("Alpha\nBeta\n").unwrap(),
            vec!["Alpha".to_owned(), "Beta".to_owned()]
        );
        assert!(parse_export_name_control("").is_err());
        assert!(parse_export_name_control("Beta\nAlpha\n").is_err());
        assert!(parse_export_name_control("Alpha\nAlpha\n").is_err());
        assert!(parse_export_name_control("Alpha Beta\n").is_err());
    }

    #[test]
    fn committed_post_poll_controls_add_only_getcommandlinea() {
        let controls = frozen_poll_window_controls().unwrap();
        assert_eq!(controls.added_name, "GetCommandLineA");

        let mut same_length_replacement = controls.treatment.clone();
        same_length_replacement.names.retain(|name| name != "Sleep");
        same_length_replacement
            .names
            .push("ZZZReplacement".to_owned());
        assert_eq!(
            single_added_export_name(&controls.baseline, &same_length_replacement),
            None
        );

        let mut two_additions = controls.treatment.clone();
        two_additions.names.push("ZZZSecondAddition".to_owned());
        assert_eq!(
            single_added_export_name(&controls.baseline, &two_additions),
            None
        );

        let mut wrong_module = controls.treatment;
        wrong_module.module_name = "user32.dll".to_owned();
        assert_eq!(
            single_added_export_name(&controls.baseline, &wrong_module),
            None
        );
    }

    #[test]
    fn post_poll_ab_validator_rejects_every_composition_mutation() {
        let tail_rips = (0..POST_POLL_TAIL_LEN)
            .map(|index| 0x0000_0001_4000_0000 + index as u64)
            .collect::<Vec<_>>();
        let baseline_call = RegisterCallTerminal {
            global_instruction_index: 100,
            instruction_address: 0x0000_0001_4020_0000,
            target_register: Register::RAX,
            target_value: 0,
            pushed_return_cell: STACK_BASE + 0x1000,
            pushed_return_address: 0x0000_0001_4020_0002,
        };
        let treatment_call = RegisterCallTerminal {
            global_instruction_index: 200,
            target_value: 0x0000_7fff_0000_1020,
            ..baseline_call
        };
        let baseline = PostPollTerminalObservation {
            boundary: DiagnosticBoundary::Natural(TrapStop::NullControlTransfer),
            pending_api: None,
            pending_address: None,
            call: Some(baseline_call),
            tail_rips: tail_rips.clone(),
        };
        let treatment = PostPollTerminalObservation {
            boundary: DiagnosticBoundary::PendingApi {
                name: POST_POLL_API_NAME.to_owned(),
            },
            pending_api: Some(POST_POLL_API_NAME.to_owned()),
            pending_address: Some(treatment_call.target_value),
            call: Some(treatment_call),
            tail_rips,
        };
        let invariant = validate_post_poll_ab(&baseline, &treatment, POST_POLL_API_NAME).unwrap();
        assert_eq!(invariant.baseline_call, baseline_call);
        assert_eq!(invariant.treatment_target, treatment_call.target_value);

        type Mutation = fn(&mut PostPollTerminalObservation, &mut PostPollTerminalObservation);
        let mutations: &[Mutation] = &[
            |baseline, _| baseline.boundary = DiagnosticBoundary::Natural(TrapStop::InstructionCap),
            |baseline, _| baseline.pending_api = Some(POST_POLL_API_NAME.to_owned()),
            |baseline, _| baseline.pending_address = Some(0x1000),
            |_, treatment| {
                treatment.boundary = DiagnosticBoundary::Natural(TrapStop::NullControlTransfer)
            },
            |_, treatment| {
                treatment.boundary = DiagnosticBoundary::PendingApi {
                    name: "WrongName".to_owned(),
                }
            },
            |_, treatment| treatment.pending_api = Some("WrongName".to_owned()),
            |_, treatment| treatment.pending_api = None,
            |_, treatment| treatment.pending_address = None,
            |_, treatment| treatment.pending_address = Some(0x0000_7fff_0000_1030),
            |baseline, _| baseline.call = None,
            |_, treatment| treatment.call = None,
            |baseline, _| baseline.call.as_mut().unwrap().target_value = 1,
            |_, treatment| treatment.call.as_mut().unwrap().target_value = 0,
            |_, treatment| treatment.call.as_mut().unwrap().target_value += 0x10,
            |_, treatment| treatment.call.as_mut().unwrap().instruction_address += 1,
            |_, treatment| treatment.call.as_mut().unwrap().target_register = Register::R10,
            |_, treatment| treatment.call.as_mut().unwrap().pushed_return_cell += 8,
            |_, treatment| treatment.call.as_mut().unwrap().pushed_return_address += 1,
            |_, treatment| treatment.tail_rips[0] += 1,
            |_, treatment| {
                treatment.tail_rips.pop();
            },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut mutated_baseline = baseline.clone();
            let mut mutated_treatment = treatment.clone();
            mutate(&mut mutated_baseline, &mut mutated_treatment);
            assert!(
                validate_post_poll_ab(&mutated_baseline, &mutated_treatment, POST_POLL_API_NAME)
                    .is_err(),
                "validator accepted mutation {index}"
            );
        }
    }

    #[test]
    fn watch_hit_formatting_requires_hook_time_code_bytes() {
        let hit = PersistentWatchHit {
            global_instruction_index: 7,
            is_write: true,
            address: 0x2000,
            size: 8,
            rip: 0x1000,
            value: Some(0),
            registers: Vec::new(),
            code_window: vec![0x90, 0xc3],
        };
        let formatted = format_watch_hits(vec![hit.clone()]).unwrap();
        assert_eq!(formatted[0].instruction, "nop");
        assert_eq!(
            formatted[0].fallthrough,
            vec![(0x1000, "nop".to_owned()), (0x1001, "ret".to_owned())]
        );

        let mut missing = hit;
        missing.code_window.clear();
        assert!(format_watch_hits(vec![missing]).is_err());
    }

    #[test]
    fn poll_compare_and_overlapping_writer_are_classified_from_hook_state() {
        let poll = MainPollObservation {
            address: 0x2003,
            compare_rip: 0x1000,
            compared_value: 0,
            value_at_sleep: 0,
        };
        let compare = PersistentWatchHit {
            global_instruction_index: 10,
            is_write: false,
            address: poll.address,
            size: 1,
            rip: poll.compare_rip,
            value: Some(0),
            registers: vec![(RegisterX86::R12, poll.address), (RegisterX86::RDI, 0)],
            code_window: vec![0x41, 0x38, 0x3c, 0x24],
        };
        let formatted = format_watch_hits(vec![compare.clone()]).unwrap().remove(0);
        assert!(is_main_poll_compare(&formatted, poll));
        assert_eq!(simple_byte_compare_value(&formatted), Some(0));

        let alternate_poll = MainPollObservation {
            address: 0x3000,
            compare_rip: 0x1100,
            ..poll
        };
        let alternate_compare = PersistentWatchHit {
            global_instruction_index: 10,
            is_write: false,
            address: alternate_poll.address,
            size: 1,
            rip: alternate_poll.compare_rip,
            value: Some(0),
            registers: vec![
                (RegisterX86::RSI, alternate_poll.address),
                (RegisterX86::RAX, 0),
            ],
            code_window: vec![0x38, 0x06],
        };
        let formatted = format_watch_hits(vec![alternate_compare])
            .unwrap()
            .remove(0);
        assert!(is_main_poll_compare(&formatted, alternate_poll));
        assert_eq!(simple_byte_compare_value(&formatted), Some(0));

        let zero = PersistentWatchHit {
            global_instruction_index: 11,
            is_write: true,
            address: 0x2000,
            size: 8,
            rip: 0x1010,
            value: Some(0),
            registers: Vec::new(),
            code_window: vec![0x90],
        };
        let release = PersistentWatchHit {
            global_instruction_index: 12,
            value: Some(0x8877_6655_4433_2211),
            rip: 0x1020,
            ..zero.clone()
        };
        assert_eq!(watched_byte(&zero, poll.address), Some(0));
        assert_eq!(watched_byte(&release, poll.address), Some(0x44));
        let releasing_compare = PersistentWatchHit {
            global_instruction_index: 13,
            value: Some(0x44),
            ..compare
        };
        assert_eq!(
            last_writer_before_releasing_compare(
                &[zero.clone(), release.clone(), releasing_compare.clone()],
                poll,
                2..3,
            ),
            Some(1)
        );
        assert_eq!(
            last_writer_before_releasing_compare(
                &[zero.clone(), release, zero, releasing_compare],
                poll,
                3..4,
            ),
            None
        );
    }

    #[test]
    fn plain_ret_reaches_sentinel_and_nonzero_cleanup_is_rejected() {
        const RET_BASE: u64 = 0x0000_0000_0100_0000;
        const RET_GUARD_BASE: u64 = RET_BASE + 0x1000;
        let rsp = STACK_BASE + 0x2000;
        let image = PeImage {
            image_base: RET_BASE,
            entry_point_rva: 0,
            base_of_code: 0,
            size_of_code: 0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_headers: 0,
            size_of_image: 0x1000,
            subsystem: 3,
            sections: Vec::new(),
        };

        let mut emu = Emu::new().unwrap();
        emu.map_code(RET_BASE, &[0xc3]).unwrap();
        emu.write_mem(rsp, &CHILD_RETURN_SENTINEL.to_le_bytes())
            .unwrap();
        emu.write_reg(RegisterX86::RSP, rsp).unwrap();
        emu.install_code_trace_hook().unwrap();

        let mut env = Win64Env::new(RET_BASE);
        let result = run_with_import_trap(&mut env, &mut emu, &image, RET_BASE, 16, 1).unwrap();
        assert!(result.handled.is_empty());
        assert_eq!(
            result.stop,
            TrapStop::UnexpectedFault {
                address: CHILD_RETURN_SENTINEL
            }
        );

        let final_rip = emu.read_reg(RegisterX86::RIP).unwrap();
        let final_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        assert_eq!(final_rip, CHILD_RETURN_SENTINEL);
        assert_eq!(final_rsp, rsp + 8);
        let rips = emu.executed_addresses();
        assert_eq!(rips, vec![RET_BASE]);
        require_terminal_ret(&emu, &rips).unwrap();

        let consumed_cell = terminal_cell(final_rsp).unwrap();
        assert_eq!(
            derive_terminal_transfer(
                &emu,
                &rips,
                final_rsp,
                &read_cpu_state(&emu).unwrap(),
                &emu.recent_instructions(),
            )
            .unwrap(),
            (
                TerminalTransfer::NearReturn {
                    instruction_address: RET_BASE,
                },
                consumed_cell,
            )
        );
        assert_eq!(consumed_cell, rsp);
        let consumed_value = read_u64(&emu, consumed_cell).unwrap();
        assert_eq!(consumed_value, CHILD_RETURN_SENTINEL);
        assert_eq!(
            classify_terminal(&result, final_rip, consumed_value).unwrap(),
            ChildTerminal::ReturnSentinel
        );

        let named_stub = 0x0000_7fff_0010_1000;
        let named = TrapRun {
            handled: vec!["timeGetTime".to_owned()],
            stop: TrapStop::UnhandledApi {
                name: "ObservedName".to_owned(),
                rva: 0x1000,
            },
        };
        assert_eq!(
            classify_terminal(&named, named_stub, named_stub).unwrap(),
            ChildTerminal::UnhandledApi {
                name: "ObservedName".to_owned(),
            }
        );

        let mut return_guards = Emu::new().unwrap();
        return_guards
            .map_code(
                RET_GUARD_BASE,
                &[
                    0xc2, 0x00, 0x00, // qword ret 0
                    0x66, 0xc3, // operand-size-prefixed near ret
                    0x66, 0xc2, 0x00, 0x00, // operand-size-prefixed near ret 0
                    0xc2, 0x10, 0x00, // qword ret 0x10
                    0xcb, // far ret
                ],
            )
            .unwrap();
        require_terminal_ret(&return_guards, &[RET_GUARD_BASE]).unwrap();
        // Iced-x86 classifies these as qword returns, but Unicorn consumes a
        // 16-bit target. The diagnostic rejects the ambiguous encoding.
        assert!(require_terminal_ret(&return_guards, &[RET_GUARD_BASE + 3]).is_err());
        assert!(require_terminal_ret(&return_guards, &[RET_GUARD_BASE + 5]).is_err());
        return_guards
            .write_mem(rsp, &CHILD_RETURN_SENTINEL.to_le_bytes())
            .unwrap();
        return_guards.write_reg(RegisterX86::RSP, rsp).unwrap();
        return_guards.resume(RET_GUARD_BASE + 3, 16).unwrap();
        assert_eq!(return_guards.read_reg(RegisterX86::RIP).unwrap(), 0);
        assert_eq!(return_guards.read_reg(RegisterX86::RSP).unwrap(), rsp + 2);
        assert!(require_terminal_ret(&return_guards, &[RET_GUARD_BASE + 9]).is_err());
        assert!(require_terminal_ret(&return_guards, &[RET_GUARD_BASE + 12]).is_err());
        assert!(!has_operand_size_override_prefix(&[0xc2, 0x66, 0x00]));
    }

    #[test]
    fn indirect_call_terminal_derives_pointer_and_pushed_return() {
        const CALL_BASE: u64 = 0x0000_0000_0102_0000;
        const CALL_DISPLACEMENT: u64 = 0x108;
        let rdi = STACK_BASE + 0x6000;
        let pointer_cell = rdi + CALL_DISPLACEMENT;
        let initial_rsp = STACK_BASE + 0x8000;
        let image = PeImage {
            image_base: CALL_BASE,
            entry_point_rva: 0,
            base_of_code: 0,
            size_of_code: 0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_headers: 0,
            size_of_image: 0x1000,
            subsystem: 3,
            sections: Vec::new(),
        };

        let mut emu = Emu::new().unwrap();
        emu.map_code(
            CALL_BASE,
            &[
                0xff, 0x97, 0x08, 0x01, 0x00, 0x00, // call qword [rdi+108h]
            ],
        )
        .unwrap();
        emu.write_mem(pointer_cell, &0u64.to_le_bytes()).unwrap();
        emu.write_reg(RegisterX86::RDI, rdi).unwrap();
        emu.write_reg(RegisterX86::RSP, initial_rsp).unwrap();
        emu.configure_persistent_watch(&[(pointer_cell, pointer_cell + 8)], 8)
            .unwrap();
        emu.install_code_trace_hook().unwrap();

        let mut env = Win64Env::new(CALL_BASE);
        let result = run_with_import_trap(&mut env, &mut emu, &image, CALL_BASE, 16, 1).unwrap();
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        let final_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        assert_eq!(final_rsp, initial_rsp - 8);
        assert_eq!(read_u64(&emu, final_rsp).unwrap(), CALL_BASE + 6);
        let rips = emu.executed_addresses();
        let terminal_registers = read_cpu_state(&emu).unwrap();
        let frozen_tail = emu.recent_instructions();
        let (transfer, source_cell) =
            derive_terminal_transfer(&emu, &rips, final_rsp, &terminal_registers, &frozen_tail)
                .unwrap();
        assert_eq!(
            transfer,
            TerminalTransfer::IndirectCall {
                instruction_address: CALL_BASE,
                pointer_cell,
                pushed_return_address: CALL_BASE + 6,
            }
        );
        assert_eq!(source_cell, pointer_cell);
        assert_eq!(
            classify_terminal(&result, 0, read_u64(&emu, source_cell).unwrap()).unwrap(),
            ChildTerminal::NullControlTransfer
        );
        let hits = emu.persistent_watch_hits();
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].is_write);
        assert_eq!(hits[0].address, pointer_cell);
        assert_eq!(hits[0].size, 8);
        assert_eq!(hits[0].value, Some(0));
        assert_eq!(hits[0].rip, CALL_BASE);
        assert_eq!(
            register_value(&hits[0].registers, RegisterX86::RSP),
            Some(initial_rsp)
        );

        emu.write_mem(final_rsp, &0u64.to_le_bytes()).unwrap();
        assert!(derive_terminal_transfer(
            &emu,
            &rips,
            final_rsp,
            &terminal_registers,
            &frozen_tail,
        )
        .is_err());

        let register_call_base = CALL_BASE + 0x1000;
        let mut register_call = Emu::new().unwrap();
        register_call
            .map_code(register_call_base, &[0xff, 0xd7])
            .unwrap();
        let register_frozen = [FrozenInstruction {
            global_instruction_index: 1,
            address: register_call_base,
            bytes: vec![0xff, 0xd7],
        }];
        assert!(derive_terminal_transfer(
            &register_call,
            &[register_call_base],
            initial_rsp,
            &terminal_registers,
            &register_frozen,
        )
        .is_err());

        let disp8_call = [FrozenInstruction {
            global_instruction_index: 1,
            address: register_call_base,
            bytes: vec![0xff, 0x57, 0x08],
        }];
        assert!(derive_terminal_transfer(
            &register_call,
            &[register_call_base],
            initial_rsp,
            &terminal_registers,
            &disp8_call,
        )
        .is_err());
    }

    #[test]
    fn register_call_terminal_derives_runtime_register_and_fallthrough() {
        const CALL_BASE: u64 = 0x0000_0000_0104_0000;
        let initial_rsp = STACK_BASE + 0xa000;
        let image = PeImage {
            image_base: CALL_BASE,
            entry_point_rva: 0,
            base_of_code: 0,
            size_of_code: 0,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_headers: 0,
            size_of_image: 0x1000,
            subsystem: 3,
            sections: Vec::new(),
        };
        let mut emu = Emu::new().unwrap();
        emu.map_code(CALL_BASE, &[0x41, 0xff, 0xd2]).unwrap(); // call r10
        emu.write_reg(RegisterX86::R10, 0).unwrap();
        emu.write_reg(RegisterX86::RSP, initial_rsp).unwrap();
        emu.install_code_trace_hook().unwrap();

        let mut env = Win64Env::new(CALL_BASE);
        let result = run_with_import_trap(&mut env, &mut emu, &image, CALL_BASE, 16, 1).unwrap();
        assert_eq!(result.stop, TrapStop::NullControlTransfer);
        let final_rsp = emu.read_reg(RegisterX86::RSP).unwrap();
        let registers = read_cpu_state(&emu).unwrap();
        let terminal = derive_register_call_terminal(
            &emu,
            &emu.executed_addresses(),
            final_rsp,
            &registers,
            &emu.recent_instructions(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(terminal.instruction_address, CALL_BASE);
        assert_eq!(terminal.target_register, Register::R10);
        assert_eq!(terminal.target_value, 0);
        assert_eq!(terminal.pushed_return_cell, initial_rsp - 8);
        assert_eq!(terminal.pushed_return_address, CALL_BASE + 3);

        emu.write_mem(final_rsp, &0u64.to_le_bytes()).unwrap();
        assert!(derive_register_call_terminal(
            &emu,
            &emu.executed_addresses(),
            final_rsp,
            &registers,
            &emu.recent_instructions(),
        )
        .is_err());
    }

    #[test]
    fn full_qword_frame_push_rejects_rsp_and_unresolved_bases() {
        let source_cell = STACK_BASE + 0x5008;
        let consumer_rip = 0x1010;
        let global_instruction_index = 20;
        let tail = vec![FormattedInstruction {
            global_instruction_index,
            address: consumer_rip,
            instruction: "push qword [rbp-8]".to_owned(),
            writes_r13: Some(false),
        }];
        let format_read =
            |address: u64, registers: Vec<(RegisterX86, u64)>, code_window: Vec<u8>| {
                format_watch_hits(vec![PersistentWatchHit {
                    global_instruction_index,
                    is_write: false,
                    address,
                    size: 8,
                    rip: consumer_rip,
                    value: Some(0),
                    registers,
                    code_window,
                }])
                .unwrap()
                .remove(0)
            };

        let valid = format_read(
            source_cell,
            vec![(RegisterX86::RBP, source_cell + 8)],
            vec![0xff, 0x75, 0xf8],
        );
        assert!(is_full_qword_frame_push(&valid, &tail));

        let invalid = [
            format_read(
                source_cell,
                vec![(RegisterX86::RSP, source_cell - 8)],
                vec![0xff, 0x74, 0x24, 0x08],
            ),
            format_read(
                0x5000,
                Vec::new(),
                vec![0xff, 0x34, 0x25, 0x00, 0x50, 0x00, 0x00],
            ),
            format_read(source_cell, Vec::new(), vec![0xff, 0x75, 0xf8]),
            format_read(
                source_cell,
                vec![(RegisterX86::RBP, source_cell + 16)],
                vec![0xff, 0x75, 0xf8],
            ),
        ];
        assert!(invalid
            .iter()
            .all(|entry| !is_full_qword_frame_push(entry, &tail)));
    }

    #[test]
    fn zero_target_provenance_requires_a_paired_nonzero_to_zero_writer() {
        let source_cell = STACK_BASE + 0x5008;
        let rbp = source_cell + 8;
        let writer_rip = 0x1000;
        let consumer_rip = 0x1010;
        let registers = vec![
            (RegisterX86::RBP, rbp),
            (RegisterX86::RAX, 0x55),
            (RegisterX86::RSP, STACK_BASE + 0x6000),
        ];
        let raw_hits = vec![
            PersistentWatchHit {
                global_instruction_index: 10,
                is_write: false,
                address: source_cell,
                size: 8,
                rip: writer_rip,
                value: Some(0x55),
                registers: registers.clone(),
                code_window: vec![0x48, 0x31, 0x45, 0xf8], // xor [rbp-8],rax
            },
            PersistentWatchHit {
                global_instruction_index: 10,
                is_write: true,
                address: source_cell,
                size: 8,
                rip: writer_rip,
                value: Some(0),
                registers: registers.clone(),
                code_window: vec![0x48, 0x31, 0x45, 0xf8],
            },
            PersistentWatchHit {
                global_instruction_index: 20,
                is_write: false,
                address: source_cell,
                size: 8,
                rip: consumer_rip,
                value: Some(0),
                registers,
                code_window: vec![0xff, 0x75, 0xf8], // push qword [rbp-8]
            },
        ];
        let hits = format_watch_hits(raw_hits).unwrap();
        let tail = vec![FormattedInstruction {
            global_instruction_index: 20,
            address: consumer_rip,
            instruction: "push qword [rbp-8]".to_owned(),
            writes_r13: Some(false),
        }];
        let terminal = RegisterCallTerminal {
            global_instruction_index: 30,
            instruction_address: 0x1020,
            target_register: Register::RAX,
            target_value: 0,
            pushed_return_cell: STACK_BASE + 0x7000,
            pushed_return_address: 0x1022,
        };
        let provenance = derive_zero_target_provenance(&hits, &tail, terminal)
            .unwrap()
            .unwrap();
        assert_eq!(provenance.source_cell, source_cell);
        assert_eq!(provenance.zero_writer_input, 0x55);
        assert_eq!(provenance.zero_writer_output, 0);

        let mut before_frozen_tail = hits.clone();
        before_frozen_tail[2].hit.global_instruction_index = 19;
        assert_eq!(
            derive_zero_target_provenance(&before_frozen_tail, &tail, terminal).unwrap(),
            None
        );

        let mut after_frozen_tail = hits.clone();
        after_frozen_tail[2].hit.global_instruction_index = 21;
        assert_eq!(
            derive_zero_target_provenance(&after_frozen_tail, &tail, terminal).unwrap(),
            None
        );

        let mut zero_input = hits.clone();
        zero_input[0].hit.value = Some(0);
        assert_eq!(
            derive_zero_target_provenance(&zero_input, &tail, terminal).unwrap(),
            None
        );

        let mut conflicting = hits.clone();
        conflicting.insert(
            2,
            FormattedWatchHit {
                hit: PersistentWatchHit {
                    global_instruction_index: 15,
                    is_write: true,
                    address: source_cell + 1,
                    size: 1,
                    rip: 0x1008,
                    value: Some(0),
                    registers: Vec::new(),
                    code_window: vec![0x90],
                },
                instruction: "nop".to_owned(),
                fallthrough: vec![(0x1008, "nop".to_owned())],
            },
        );
        assert_eq!(
            derive_zero_target_provenance(&conflicting, &tail, terminal).unwrap(),
            None
        );

        let mut duplicate = hits;
        let mut second_consumer = duplicate[2].clone();
        second_consumer.hit.global_instruction_index = 21;
        duplicate.push(second_consumer);
        let mut duplicate_tail = tail;
        duplicate_tail.push(FormattedInstruction {
            global_instruction_index: 21,
            address: consumer_rip,
            instruction: "push qword [rbp-8]".to_owned(),
            writes_r13: Some(false),
        });
        assert!(derive_zero_target_provenance(&duplicate, &duplicate_tail, terminal).is_err());
    }

    #[test]
    fn indirect_call_frontier_validator_rejects_mutated_observations() {
        const INSTRUCTION: u64 = 0x1000;
        const POINTER_CELL: u64 = 0x2000;
        const FINAL_RSP: u64 = 0x3000;
        const RDI: u64 = 0x4000;
        const RETURN_ADDRESS: u64 = INSTRUCTION + 6;

        let writer = FormattedWatchHit {
            hit: PersistentWatchHit {
                global_instruction_index: 10,
                is_write: true,
                address: POINTER_CELL,
                size: 8,
                rip: 0x5000,
                value: Some(0),
                registers: Vec::new(),
                code_window: Vec::new(),
            },
            instruction: "mov [r9],rbx".to_owned(),
            fallthrough: Vec::new(),
        };
        let call_read = FormattedWatchHit {
            hit: PersistentWatchHit {
                global_instruction_index: 20,
                is_write: false,
                address: POINTER_CELL,
                size: 8,
                rip: INSTRUCTION,
                value: Some(0),
                registers: vec![(RegisterX86::RSP, FINAL_RSP + 8), (RegisterX86::RDI, RDI)],
                code_window: vec![0xff, 0x97, 0x00, 0xe0, 0xff, 0xff],
            },
            instruction: "call qword [rdi+20108h]".to_owned(),
            fallthrough: Vec::new(),
        };
        let terminal = ChildTerminal::NullControlTransfer;
        let transfer = TerminalTransfer::IndirectCall {
            instruction_address: INSTRUCTION,
            pointer_cell: POINTER_CELL,
            pushed_return_address: RETURN_ADDRESS,
        };
        let terminal_registers = vec![(RegisterX86::RSP, FINAL_RSP), (RegisterX86::RDI, RDI)];
        let validate = |phase, hits: &[FormattedWatchHit], registers| {
            validate_indirect_call_observation(IndirectCallObservation {
                transfer,
                terminal: &terminal,
                terminal_cell: POINTER_CELL,
                terminal_value: 0,
                terminal_source: None,
                watch_phase: phase,
                watch_hits: hits,
                terminal_registers: registers,
            })
        };

        let hits = vec![writer.clone(), call_read.clone()];
        assert_eq!(
            validate(Some(WatchPhase::BeforeMain), &hits, &terminal_registers).unwrap(),
            Some(0)
        );
        assert!(validate(Some(WatchPhase::BeforeTime), &hits, &terminal_registers).is_err());

        let mut extra_final_access = hits.clone();
        extra_final_access.push(writer.clone());
        assert!(validate(
            Some(WatchPhase::BeforeMain),
            &extra_final_access,
            &terminal_registers
        )
        .is_err());

        let duplicate_read = vec![writer.clone(), call_read.clone(), call_read.clone()];
        assert!(validate(
            Some(WatchPhase::BeforeMain),
            &duplicate_read,
            &terminal_registers
        )
        .is_err());

        let mut wrong_snapshot = hits.clone();
        wrong_snapshot[1]
            .hit
            .registers
            .iter_mut()
            .find(|(register, _value)| *register == RegisterX86::RSP)
            .unwrap()
            .1 ^= 8;
        assert!(validate(
            Some(WatchPhase::BeforeMain),
            &wrong_snapshot,
            &terminal_registers
        )
        .is_err());

        let nonzero_value = 0x6000;
        let nonzero_terminal = ChildTerminal::UnhandledApi {
            name: "DiagnosticApi".to_owned(),
        };
        let mut nonzero_hits = hits.clone();
        for entry in &mut nonzero_hits {
            entry.hit.value = Some(nonzero_value);
        }
        assert_eq!(
            validate_indirect_call_observation(IndirectCallObservation {
                transfer,
                terminal: &nonzero_terminal,
                terminal_cell: POINTER_CELL,
                terminal_value: nonzero_value,
                terminal_source: None,
                watch_phase: Some(WatchPhase::BeforeMain),
                watch_hits: &nonzero_hits,
                terminal_registers: &terminal_registers,
            })
            .unwrap(),
            Some(0)
        );

        let later_writer = FormattedWatchHit {
            hit: PersistentWatchHit {
                global_instruction_index: 15,
                ..writer.hit.clone()
            },
            ..writer.clone()
        };
        let two_writers = vec![writer, later_writer, call_read];
        assert_eq!(
            validate(
                Some(WatchPhase::BeforeMain),
                &two_writers,
                &terminal_registers
            )
            .unwrap(),
            Some(1)
        );
        assert_eq!(
            validate(
                Some(WatchPhase::BeforeMain),
                &two_writers[2..],
                &terminal_registers
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn source_register_path_rejects_unobserved_changes_and_dynamic_gaps() {
        let make_hit = |global_instruction_index, rip, instruction: &str| FormattedWatchHit {
            hit: PersistentWatchHit {
                global_instruction_index,
                is_write: false,
                address: 0,
                size: 0,
                rip,
                value: None,
                registers: Vec::new(),
                code_window: Vec::new(),
            },
            instruction: instruction.to_owned(),
            fallthrough: Vec::new(),
        };
        let mut selector = make_hit(100, 0x1000, "movzx rbx,word [rbx]");
        selector.fallthrough = vec![
            (0x1000, "movzx rbx,word [rbx]".to_owned()),
            (0x1004, "add rbx,rbp".to_owned()),
            (0x1007, "mov rbx,[rbx]".to_owned()),
            (0x100a, "mov [r9],rbx".to_owned()),
        ];
        let source = make_hit(102, 0x1007, "mov rbx,[rbx]");
        let slot = make_hit(103, 0x100a, "mov [r9],rbx");
        validate_source_register_path(&selector, &source, &slot).unwrap();

        let mut changed_rbx = selector.clone();
        changed_rbx.fallthrough[1].1 = "xor ebx,ebx".to_owned();
        assert!(validate_source_register_path(&changed_rbx, &source, &slot).is_err());

        let mut delayed_source = source.clone();
        delayed_source.hit.global_instruction_index += 1;
        assert!(validate_source_register_path(&selector, &delayed_source, &slot).is_err());

        let mut writes_decoder = Decoder::new(64, &[0x45, 0x31, 0xed], DecoderOptions::NONE);
        assert!(instruction_writes_r13(&writes_decoder.decode()));
        let mut preserves_decoder = Decoder::new(64, &[0x90], DecoderOptions::NONE);
        assert!(!instruction_writes_r13(&preserves_decoder.decode()));
    }

    #[test]
    fn rax_stack_path_validates_data_flow_and_rejects_mutations() {
        const SOURCE: u64 = 0x1000;
        const DESTINATION: u64 = SOURCE + 0x88;
        const VALUE: u64 = 0x1234_5678_9abc_def0;
        const SAVED_R8: u64 = 0x55aa;
        const FINAL_GLOBAL: u64 = 105;
        const FINAL_RIP: u64 = 0x2011;

        let make_hit = |global_instruction_index: u64,
                        is_write: bool,
                        address: u64,
                        rip: u64,
                        value: u64,
                        rsp: u64,
                        rax: u64,
                        r8: u64,
                        instruction: &str,
                        fallthrough: Vec<(u64, &str)>| {
            FormattedWatchHit {
                hit: PersistentWatchHit {
                    global_instruction_index,
                    is_write,
                    address,
                    size: 8,
                    rip,
                    value: Some(value),
                    registers: vec![
                        (RegisterX86::RSP, rsp),
                        (RegisterX86::RAX, rax),
                        (RegisterX86::R8, r8),
                    ],
                    code_window: Vec::new(),
                },
                instruction: instruction.to_owned(),
                fallthrough: fallthrough
                    .into_iter()
                    .map(|(address, instruction)| (address, instruction.to_owned()))
                    .collect(),
            }
        };

        let hits = vec![
            make_hit(
                100,
                true,
                SOURCE,
                0x2000,
                SAVED_R8,
                SOURCE + 8,
                VALUE,
                SAVED_R8,
                "push r8",
                vec![
                    (0x2000, "push r8"),
                    (0x2002, "pop qword [rsp]"),
                    (0x2005, "mov r8,rax"),
                    (0x2008, "push 12345678h"),
                ],
            ),
            make_hit(
                101,
                false,
                SOURCE,
                0x2002,
                SAVED_R8,
                SOURCE,
                VALUE,
                SAVED_R8,
                "pop qword [rsp]",
                Vec::new(),
            ),
            make_hit(
                103,
                true,
                SOURCE,
                0x2008,
                0x1234_5678,
                SOURCE + 8,
                VALUE,
                VALUE,
                "push 12345678h",
                vec![
                    (0x2008, "push 12345678h"),
                    (0x200d, "mov [rsp],r8"),
                    (FINAL_RIP, "pop qword [rsp+80h]"),
                ],
            ),
            make_hit(
                104,
                true,
                SOURCE,
                0x200d,
                VALUE,
                SOURCE,
                VALUE,
                VALUE,
                "mov [rsp],r8",
                vec![(0x200d, "mov [rsp],r8"), (FINAL_RIP, "pop qword [rsp+80h]")],
            ),
            make_hit(
                FINAL_GLOBAL,
                false,
                SOURCE,
                FINAL_RIP,
                VALUE,
                SOURCE,
                VALUE,
                VALUE,
                "pop qword [rsp+80h]",
                vec![(FINAL_RIP, "pop qword [rsp+80h]")],
            ),
            make_hit(
                FINAL_GLOBAL,
                true,
                DESTINATION,
                FINAL_RIP,
                VALUE,
                SOURCE,
                VALUE,
                VALUE,
                "pop qword [rsp+80h]",
                vec![(FINAL_RIP, "pop qword [rsp+80h]")],
            ),
        ];
        let producer = StackCellProducer {
            writer_rip: FINAL_RIP,
            writer_global_instruction_index: FINAL_GLOBAL,
            destination_cell: DESTINATION,
            value: VALUE,
            source_cell: SOURCE,
        };

        assert_eq!(
            validate_stack_value_from_rax(&hits, producer).unwrap(),
            RaxStackProducer {
                path_start_rip: 0x2000,
                path_start_global_instruction_index: 100,
                value: VALUE,
            }
        );

        let mut randomized_immediate = hits.clone();
        randomized_immediate[0].fallthrough[3].1 = "push 7F743E4h".to_owned();
        randomized_immediate[2].instruction = "push 7F743E4h".to_owned();
        randomized_immediate[2].fallthrough[0].1 = "push 7F743E4h".to_owned();
        validate_stack_value_from_rax(&randomized_immediate, producer).unwrap();

        let mut wrong_rax = hits.clone();
        wrong_rax[2]
            .hit
            .registers
            .iter_mut()
            .find(|(register, _)| *register == RegisterX86::RAX)
            .unwrap()
            .1 ^= 1;
        assert!(validate_stack_value_from_rax(&wrong_rax, producer).is_err());

        let mut wrong_pre_move_rax = hits.clone();
        for index in [0, 1] {
            wrong_pre_move_rax[index]
                .hit
                .registers
                .iter_mut()
                .find(|(register, _)| *register == RegisterX86::RAX)
                .unwrap()
                .1 ^= 1;
        }
        assert!(validate_stack_value_from_rax(&wrong_pre_move_rax, producer).is_err());

        let mut dynamic_gap = hits.clone();
        dynamic_gap[3].hit.global_instruction_index -= 1;
        assert!(validate_stack_value_from_rax(&dynamic_gap, producer).is_err());

        let mut divergent_halves = hits.clone();
        divergent_halves[5]
            .hit
            .registers
            .iter_mut()
            .find(|(register, _)| *register == RegisterX86::R8)
            .unwrap()
            .1 ^= 1;
        assert!(validate_stack_value_from_rax(&divergent_halves, producer).is_err());

        let mut conflicting_write = hits.clone();
        conflicting_write.insert(
            4,
            make_hit(
                104,
                true,
                DESTINATION,
                0x2010,
                0,
                SOURCE,
                VALUE,
                VALUE,
                "mov [rsp+88h],rax",
                Vec::new(),
            ),
        );
        assert!(validate_stack_value_from_rax(&conflicting_write, producer).is_err());
    }
}
