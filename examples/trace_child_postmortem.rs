//! Bounded diagnostic for the first runnable-unscheduled thread recorded by
//! the Win64 environment.
//!
//! This is not a scheduler or a Windows thread-start model. It runs a recorded
//! start address under explicit diagnostic-only stack/TEB conditions, restores
//! the stopped main CPU context, and gives terminal control transfers no
//! lifecycle meaning.

use std::{env, fs, process};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, InstructionInfoFactory, NasmFormatter, OpAccess,
    Register,
};
use midas::{
    emu::{
        Emu, PersistentWatchHit, RegisterX86, PEB_BASE, STACK_BASE, STACK_SIZE, TEB_BASE,
        TEB_PEB_OFFSET, TEB_SELF_OFFSET, TEB_SIZE, TEB_STACKBASE_OFFSET, TEB_STACKLIMIT_OFFSET,
    },
    pe::PeImage,
    win64::{run_with_import_trap, RunnableUnscheduledThread, TrapRun, TrapStop, Win64Env},
};

const DEFAULT_MAIN_PER_LEG_CAP: u64 = 60_000_000;
const DEFAULT_CHILD_PER_LEG_CAP: u64 = 100_000;
const MAX_CHILD_PER_LEG_CAP: u64 = 250_000;
const DEFAULT_WATCH_HIT_CAP: usize = 4_096;
const MAX_WATCH_HIT_CAP: usize = 16_384;
const FROZEN_PATH_INSTRUCTION_CAP: usize = 4;
const MAIN_API_BOUND: usize = 128;
const CHILD_PREFIX_API_BOUND: usize = 16;

const CHILD_STACK_BASE: u64 = 0x0000_000f_5000_0000;
const CHILD_STACK_SIZE: u64 = 0x0010_0000;
const CHILD_TEB_BASE: u64 = 0x0000_000f_5100_0000;
const CHILD_TEB_SIZE: u64 = 0x1000;
const CHILD_ENTRY_HEADROOM: u64 = 0x1000;
const CHILD_RETURN_SENTINEL: u64 = 0x0000_000e_dead_0000;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChildTerminal {
    NullControlTransfer,
    ReturnSentinel,
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

#[derive(Debug, Clone)]
struct FormattedWatchHit {
    hit: PersistentWatchHit,
    instruction: String,
    fallthrough: Vec<(u64, String)>,
}

#[derive(Debug, Clone)]
struct FormattedInstruction {
    address: u64,
    instruction: String,
    writes_r13: Option<bool>,
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
    terminal: ChildTerminal,
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

    let first = run_pass(&config, &image, &bytes, None)?;
    let watch_end = first.terminal_cell.checked_add(8).ok_or_else(|| {
        format!(
            "terminal watch range overflows at {:#x}",
            first.terminal_cell
        )
    })?;
    let second = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![(first.terminal_cell, watch_end)],
            phase: WatchPhase::BeforeTime,
        }),
    )?;

    compare_passes(&first, &second)?;
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
    let third = run_pass(
        &config,
        &image,
        &bytes,
        Some(WatchSpec {
            ranges: vec![(terminal_source.handler_slot, handler_watch_end)],
            phase: WatchPhase::BeforeMain,
        }),
    )?;
    compare_passes(&first, &third)?;
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
    let fourth = run_pass(
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
        }),
    )?;
    compare_passes(&first, &fourth)?;
    validate_watched_replay(&fourth, config.watch_hit_cap)?;
    validated_source_edge_indices(&fourth, terminal_source, handler_writer_source)?;
    print_summary(
        &config,
        &image,
        &first,
        &second,
        handler_writer_source,
        &third,
        &fourth,
    );
    Ok(())
}

fn parse_args() -> Result<Config, String> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "trace_child_postmortem".to_owned());
    let path = args.next().ok_or_else(|| usage(&program))?;
    let main_per_leg_cap = parse_optional(args.next(), DEFAULT_MAIN_PER_LEG_CAP, "main-cap")?;
    let child_per_leg_cap = parse_optional(args.next(), DEFAULT_CHILD_PER_LEG_CAP, "child-cap")?;
    let watch_hit_cap = validate_hit_cap(parse_optional(
        args.next(),
        DEFAULT_WATCH_HIT_CAP,
        "watch-hit-cap",
    )?)?;
    if args.next().is_some() {
        return Err(usage(&program));
    }
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
    })
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} <pe> [main-per-leg-cap] [child-per-leg-cap] [watch-hit-cap]\n\
         the diagnostic derives the pending Sleep, created thread, and timeGetTime stub at runtime"
    )
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

    if let Some(spec) = watch_spec
        .as_ref()
        .filter(|spec| spec.phase == WatchPhase::BeforeMain)
    {
        emu.configure_persistent_watch(&spec.ranges, config.watch_hit_cap)
            .map_err(|error| format!("failed to arm whole-run handler-slot watch: {error}"))?;
    }

    let mut frozen_main_watch_hits = None;
    let main = if let Some((capture, ranges)) =
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
        emu.configure_persistent_watch(&spec.ranges, config.watch_hit_cap)
            .map_err(|error| format!("failed to arm terminal-cell watch: {error}"))?;
    }

    let child_tail = run_with_import_trap(
        &mut env,
        &mut emu,
        image,
        child_prefix.pending_address,
        config.child_per_leg_cap,
        1,
    )
    .map_err(|error| format!("failed to run child timeGetTime suffix: {error}"))?;
    if child_tail.handled != ["timeGetTime"] {
        return Err(format!(
            "expected one timeGetTime dispatch, got {:?}",
            child_tail.handled
        ));
    }

    let child_rips = emu.executed_addresses();
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
    require_terminal_ret(&emu, &post_time_rips)?;
    let terminal_cell = terminal_cell(final_rsp)?;
    let terminal_value = read_u64(&emu, terminal_cell)?;
    let terminal = classify_terminal(&child_tail, final_rip, terminal_value)?;
    let tail_instructions = format_tail(&emu, &post_time_rips, 64);

    let watch_hits = frozen_main_watch_hits
        .unwrap_or_else(|| format_watch_hits(&emu, emu.persistent_watch_hits()));
    let terminal_source = derive_terminal_source(&emu, terminal_cell, terminal_value, &watch_hits)?;

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
        terminal,
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

        emu.configure_persistent_watch(watch_ranges, watch_hit_cap)
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
            let formatted = format_watch_hits(emu, hits);
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
        other => Err(format!(
            "child terminal transfer is outside the bounded classifier: stop={other:?}, RIP=0x{final_rip:016x}, consumed=0x{terminal_value:016x}"
        )),
    }
}

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
    let is_qword_near_return = matches!(instruction.code(), Code::Retnq | Code::Retnq_imm16);
    let encoded = bytes
        .get(..instruction.len())
        .ok_or_else(|| "decoded terminal instruction exceeds its read window".to_owned())?;
    if !is_qword_near_return
        || instruction.stack_pointer_increment() != 8
        || has_operand_size_override_prefix(encoded)
    {
        return Err(format!(
            "terminal-cell derivation requires a qword near RET with zero extra stack adjustment and no operand-size override, found {} at 0x{last:016x}",
            format_instruction(&instruction)
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

fn format_tail(emu: &Emu, rips: &[u64], count: usize) -> Vec<FormattedInstruction> {
    let start = rips.len().saturating_sub(count);
    rips[start..]
        .iter()
        .map(|&rip| format_instruction_observation_at(emu, rip))
        .collect()
}

fn format_instruction_observation_at(emu: &Emu, address: u64) -> FormattedInstruction {
    match emu.read_mem(address, 16) {
        Ok(bytes) => {
            let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            FormattedInstruction {
                address,
                instruction: format_instruction(&instruction),
                writes_r13: (!instruction.is_invalid())
                    .then(|| instruction_writes_r13(&instruction)),
            }
        }
        Err(error) => FormattedInstruction {
            address,
            instruction: format!("<unreadable: {error}>"),
            writes_r13: None,
        },
    }
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

fn format_instruction_at(emu: &Emu, address: u64) -> String {
    match emu.read_mem(address, 16) {
        Ok(bytes) => {
            let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            format_instruction(&instruction)
        }
        Err(error) => format!("<unreadable: {error}>"),
    }
}

fn format_instruction(instruction: &iced_x86::Instruction) -> String {
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
}

fn format_watch_hits(emu: &Emu, hits: Vec<PersistentWatchHit>) -> Vec<FormattedWatchHit> {
    hits.into_iter()
        .map(|hit| {
            let fallthrough =
                format_instruction_window_at(emu, hit.rip, FROZEN_PATH_INSTRUCTION_CAP);
            let instruction = fallthrough
                .first()
                .map(|(_address, instruction)| instruction.clone())
                .unwrap_or_else(|| format_instruction_at(emu, hit.rip));
            FormattedWatchHit {
                hit,
                instruction,
                fallthrough,
            }
        })
        .collect()
}

fn format_instruction_window_at(
    emu: &Emu,
    address: u64,
    instruction_cap: usize,
) -> Vec<(u64, String)> {
    let bytes = [64usize, 16]
        .into_iter()
        .find_map(|size| emu.read_mem(address, size).ok());
    let Some(bytes) = bytes else {
        return Vec::new();
    };
    let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
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
        && first.terminal == second.terminal
        && first.terminal_cell == second.terminal_cell
        && first.terminal_value == second.terminal_value
        && first.child_rips == second.child_rips
        && first.post_time_rips == second.post_time_rips
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
    Ok(())
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

fn print_summary(
    config: &Config,
    image: &PeImage,
    first: &PassEvidence,
    terminal_watch: &PassEvidence,
    handler_writer: HandlerWriterSource,
    handler_watch: &PassEvidence,
    source_watch: &PassEvidence,
) {
    let source = terminal_watch
        .terminal_source
        .expect("terminal source was validated before summary output");
    println!("image:                 {:?}", config.path);
    println!("image_base:            0x{:016x}", image.image_base);
    println!("entry_va:              0x{:016x}", image.entry_point_va());
    println!("main_per_leg_cap:      {}", config.main_per_leg_cap);
    println!("child_per_leg_cap:     {}", config.child_per_leg_cap);
    println!("watch_hit_cap:         {}", config.watch_hit_cap);
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
        handler_writer.writer_rip
    );
    println!(
        "handler_writer_global: {}",
        handler_writer.writer_global_instruction_index
    );
    println!(
        "source_selector:       0x{:04x}",
        handler_writer.source_selector
    );
    println!(
        "source_context:        0x{:016x}",
        handler_writer.source_context_address
    );
    println!(
        "source_value:          0x{:016x}",
        handler_writer.source_value
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

    print_watch_hits("terminal-cell watch hits", &terminal_watch.watch_hits);
    let terminal_writes = terminal_watch
        .watch_hits
        .iter()
        .filter(|entry| entry.hit.is_write)
        .count();
    let terminal_reads = terminal_watch
        .watch_hits
        .iter()
        .filter(|entry| !entry.hit.is_write)
        .count();
    println!("terminal_cell_writes:  {terminal_writes}");
    println!("terminal_cell_reads:   {terminal_reads}");

    print_watch_hits(
        "handler-slot whole-run watch hits",
        &handler_watch.watch_hits,
    );
    let handler_writes = handler_watch
        .watch_hits
        .iter()
        .filter(|entry| entry.hit.is_write)
        .count();
    let handler_reads = handler_watch
        .watch_hits
        .iter()
        .filter(|entry| !entry.hit.is_write)
        .count();
    println!("handler_slot_writes:   {handler_writes}");
    println!("handler_slot_reads:    {handler_reads}");
    if let Some(writer) = last_write_before_terminal_read(handler_watch, source) {
        println!("handler_watch_writer:  0x{:016x}", writer.hit.rip);
        println!(
            "handler_watch_value:   {}",
            format_optional_value(writer.hit.value)
        );
    } else {
        println!("handler_watch_writer:  <none observed>");
    }
    let source_edge_indices = validated_source_edge_indices(source_watch, source, handler_writer)
        .expect("source edge was validated before summary output");
    let source_edge_hits = source_edge_indices
        .into_iter()
        .map(|index| source_watch.watch_hits[index].clone())
        .collect::<Vec<_>>();
    print_watch_hits(
        "source-edge dynamically rearmed watch hits",
        &source_edge_hits,
    );
    println!("source_watch_retained:  {}", source_watch.watch_hits.len());
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
    fn plain_ret_reaches_sentinel_and_nonzero_cleanup_is_rejected() {
        const RET_BASE: u64 = 0x0000_0000_0100_0000;
        const RET_GUARD_BASE: u64 = RET_BASE + 0x1000;
        let rsp = STACK_BASE + 0x2000;
        let image = PeImage {
            image_base: RET_BASE,
            entry_point_rva: 0,
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
        assert_eq!(consumed_cell, rsp);
        let consumed_value = read_u64(&emu, consumed_cell).unwrap();
        assert_eq!(consumed_value, CHILD_RETURN_SENTINEL);
        assert_eq!(
            classify_terminal(&result, final_rip, consumed_value).unwrap(),
            ChildTerminal::ReturnSentinel
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
}
