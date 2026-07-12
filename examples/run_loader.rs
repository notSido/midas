use std::{env, fs, path::Component, path::Path, process};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use midas::{
    emu::{Emu, IndirectTransferCaptureFailure, IndirectTransferKind, IndirectTransferObservation},
    oep::{OepCandidate, OepCriterion},
    pe::PeImage,
    win64::{
        run_with_cooperative_scheduler, run_with_cooperative_scheduler_observing,
        IndirectTransferDisposition, IndirectTransferExecutionContext, TrapStop, Win64Env,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_PER_RUN_CAP: u64 = 250_000_000;
const DEFAULT_MAX_CALLS: usize = 512;
const ADJUDICATION_MANIFEST_VERSION: u32 = 2;
const MAX_REFUTED_CANDIDATES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjudicationImageIdentity {
    byte_len: u64,
    byte_sha256: String,
    image_base: u64,
    entry_point_rva: u32,
    size_of_image: u32,
    protector_boundary_rva: u32,
    loader_sections: Vec<AdjudicationSectionIdentity>,
    original_sections: Vec<AdjudicationSectionIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjudicationSectionIdentity {
    section_index: usize,
    start_rva: u32,
    end_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "snake_case")]
enum AdjudicationExecutionContext {
    Main,
    Child { thread_id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjudicationRegister {
    name: String,
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjudicationCandidateIdentity {
    global_instruction_index: u64,
    source_rip: u64,
    target_rip: u64,
    kind: String,
    source_bytes: String,
    target_bytes: String,
    registers: Vec<AdjudicationRegister>,
    source_section_index: usize,
    target_section_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjudicatedCandidate {
    context: AdjudicationExecutionContext,
    candidate: AdjudicationCandidateIdentity,
    adjudication: String,
    evidence_path: String,
    evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjudicationManifest {
    version: u32,
    image: AdjudicationImageIdentity,
    candidates: Vec<AdjudicatedCandidate>,
}

#[derive(Debug, Clone)]
enum CandidateDisposition {
    Refuted {
        evidence_path: String,
        evidence_sha256: String,
    },
    Pending,
}

#[derive(Debug, Clone)]
struct CandidateEvent {
    context: AdjudicationExecutionContext,
    candidate: OepCandidate,
    observation: IndirectTransferObservation,
    identity: AdjudicationCandidateIdentity,
    disposition: CandidateDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OepStopFailurePayload {
    CompleteObservation,
    IncompleteCapture(IndirectTransferCaptureFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OepTerminalState {
    NotArmed,
    DidNotFire,
    PendingCandidate,
    NoLaterCandidate {
        refuted_before: usize,
    },
    CaptureFailed {
        refuted_before: usize,
        failure: IndirectTransferCaptureFailure,
    },
    StopFailed {
        refuted_before: usize,
        payload: OepStopFailurePayload,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "run_loader".to_owned());
    let path = args.next().ok_or_else(|| usage(&program))?;
    let per_run_cap = parse_arg(args.next(), DEFAULT_PER_RUN_CAP, "per_run_cap")?;
    let max_calls = parse_arg(args.next(), DEFAULT_MAX_CALLS, "max_calls")?;
    let adjudication_manifest_path = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let bytes = fs::read(&path).map_err(|error| format!("failed to read {path:?}: {error}"))?;
    let image =
        PeImage::parse(&bytes).map_err(|error| format!("failed to parse {path:?}: {error}"))?;

    let mut emu = Emu::new().map_err(|error| format!("failed to create emulator: {error}"))?;
    emu.map_image(&image, &bytes, image.image_base)
        .map_err(|error| format!("failed to map image: {error}"))?;

    let oep_criterion = match OepCriterion::new(&image, image.image_base) {
        Ok(criterion) => {
            let layout = criterion.layout();
            let source_ranges =
                section_va_ranges(layout.mapped_base, &layout.loader_executable_sections)?;
            let target_ranges =
                section_va_ranges(layout.mapped_base, &layout.original_executable_sections)?;
            emu.configure_indirect_transfer_watch(&source_ranges, &target_ranges, false)
                .map_err(|error| format!("failed to arm OEP transfer observation: {error}"))?;
            println!(
                "OEP criterion armed: protector_boundary_rva=0x{:08x} loader_sections={:?} original_executable_sections={:?}",
                layout.protector_boundary_rva,
                layout
                    .loader_executable_sections
                    .iter()
                    .map(|region| region.section_index)
                    .collect::<Vec<_>>(),
                layout
                    .original_executable_sections
                    .iter()
                    .map(|region| region.section_index)
                    .collect::<Vec<_>>(),
            );
            Some(criterion)
        }
        Err(error) => {
            println!("OEP criterion unavailable: {error}");
            None
        }
    };

    let image_identity = oep_criterion
        .as_ref()
        .map(|criterion| adjudication_image_identity(&bytes, &image, criterion));
    let adjudication_manifest = match adjudication_manifest_path.as_deref() {
        Some(manifest_path) => {
            oep_criterion.as_ref().ok_or_else(|| {
                "an OEP adjudication manifest requires an armed OEP criterion".to_owned()
            })?;
            let expected_image = image_identity
                .as_ref()
                .expect("armed criterion produced an image identity");
            Some(load_adjudication_manifest(manifest_path, expected_image)?)
        }
        None => None,
    };

    let mut env = Win64Env::new(image.image_base);
    let mut candidate_events = Vec::new();
    let mut consumed_adjudications = 0usize;
    let mut callback_error = None;
    let result = if let Some(criterion) = oep_criterion.as_ref() {
        run_with_cooperative_scheduler_observing(
            &mut env,
            &mut emu,
            &image,
            image.entry_point_va(),
            per_run_cap,
            max_calls,
            |context, observation| {
                let Some(candidate) = criterion.evaluate_indirect_transfer_observation(observation)
                else {
                    callback_error = Some(
                        "latched transfer did not satisfy the criterion that armed its ranges"
                            .to_owned(),
                    );
                    return IndirectTransferDisposition::Stop;
                };
                let context = adjudication_execution_context(context);
                let identity = adjudication_candidate_identity(&candidate, observation);
                let expected = adjudication_manifest
                    .as_ref()
                    .and_then(|manifest| manifest.candidates.get(consumed_adjudications));
                let disposition = match expected {
                    Some(expected) if adjudication_entry_matches(expected, &context, &identity) => {
                        consumed_adjudications += 1;
                        let evidence_path = expected.evidence_path.clone();
                        let evidence_sha256 = expected.evidence_sha256.clone();
                        candidate_events.push(CandidateEvent {
                            context,
                            candidate,
                            observation: observation.clone(),
                            identity,
                            disposition: CandidateDisposition::Refuted {
                                evidence_path,
                                evidence_sha256,
                            },
                        });
                        IndirectTransferDisposition::ResumeAdjudicatedRefutation
                    }
                    Some(expected) => {
                        callback_error = Some(format!(
                            "adjudication entry {} does not match the observed candidate: expected context={:?} candidate={:?}, observed context={context:?} candidate={identity:?}",
                            consumed_adjudications + 1,
                            expected.context,
                            expected.candidate,
                        ));
                        candidate_events.push(CandidateEvent {
                            context,
                            candidate,
                            observation: observation.clone(),
                            identity,
                            disposition: CandidateDisposition::Pending,
                        });
                        IndirectTransferDisposition::Stop
                    }
                    None => {
                        candidate_events.push(CandidateEvent {
                            context,
                            candidate,
                            observation: observation.clone(),
                            identity,
                            disposition: CandidateDisposition::Pending,
                        });
                        IndirectTransferDisposition::Stop
                    }
                };
                disposition
            },
        )
    } else {
        run_with_cooperative_scheduler(
            &mut env,
            &mut emu,
            &image,
            image.entry_point_va(),
            per_run_cap,
            max_calls,
        )
    }
    .map_err(|error| format!("failed to run loader: {error}"))?;

    println!("handled APIs:");
    for (index, name) in result.handled.iter().enumerate() {
        println!("  {:03}: {name}", index + 1);
    }

    println!("cooperative yields:");
    for (index, yielded) in result.cooperative_yields.iter().enumerate() {
        println!(
            "  {:03}: thread={} stack=0x{:016x}+0x{:x} teb=0x{:016x} instructions={} stop={:?}",
            index + 1,
            yielded.thread_id,
            yielded.stack_base,
            yielded.stack_size,
            yielded.teb_base,
            yielded.instructions_executed,
            yielded.stop,
        );
        println!("       handled={:?}", yielded.handled);
    }
    println!(
        "main instructions after first yield: {}",
        result.main_instructions_after_first_yield
    );
    println!(
        "total instruction-hook boundaries: {}",
        emu.total_instructions_executed()
    );
    if let Some(observation) = env.changed_exception_continuation() {
        print_exception_continuation(observation);
    }

    let retained_observation = emu.indirect_transfer_observation();
    let capture_failure = emu.indirect_transfer_capture_failure();
    let terminal_state = validate_oep_terminal_state(
        oep_criterion.is_some(),
        &candidate_events,
        retained_observation.as_ref(),
        capture_failure.as_ref(),
        &result.stop,
    )?;

    for (index, event) in candidate_events.iter().enumerate() {
        print_oep_candidate(index + 1, event);
    }
    if let Some(pending) = candidate_events
        .iter()
        .find(|event| matches!(event.disposition, CandidateDisposition::Pending))
    {
        let manifest = pending_adjudication_template(
            image_identity
                .as_ref()
                .expect("candidate requires an armed image identity"),
            adjudication_manifest.as_ref(),
            consumed_adjudications,
            pending,
        );
        println!(
            "OEP adjudication template (pending is not permission to resume):\n{}",
            serde_json::to_string_pretty(&manifest)
                .map_err(|error| format!("failed to serialize adjudication template: {error}"))?
        );
    }

    print_oep_terminal_state(&terminal_state);

    println!("stop: {}", format_stop(&image, &result.stop));

    if let Some(error) = callback_error {
        return Err(error);
    }
    if let Some(manifest) = adjudication_manifest.as_ref() {
        if consumed_adjudications != manifest.candidates.len() {
            return Err(format!(
                "adjudication manifest supplied {} candidates but this run reproduced only {consumed_adjudications}",
                manifest.candidates.len()
            ));
        }
    }
    Ok(())
}

fn validate_oep_terminal_state(
    criterion_armed: bool,
    candidate_events: &[CandidateEvent],
    retained_observation: Option<&IndirectTransferObservation>,
    capture_failure: Option<&IndirectTransferCaptureFailure>,
    stop: &TrapStop,
) -> Result<OepTerminalState, String> {
    if retained_observation.is_some() && capture_failure.is_some() {
        return Err(
            "OEP watch retained both an observation and a capture failure at the terminal boundary"
                .to_owned(),
        );
    }

    if !criterion_armed {
        if !candidate_events.is_empty()
            || retained_observation.is_some()
            || capture_failure.is_some()
            || is_indirect_transfer_stop(stop)
        {
            return Err(
                "unarmed OEP criterion reached a terminal state containing indirect-watch evidence"
                    .to_owned(),
            );
        }
        return Ok(OepTerminalState::NotArmed);
    }

    let mut pending = None;
    let mut refuted_before = 0usize;
    for (index, event) in candidate_events.iter().enumerate() {
        match &event.disposition {
            CandidateDisposition::Refuted { .. } if pending.is_none() => {
                refuted_before += 1;
            }
            CandidateDisposition::Refuted { .. } => {
                return Err(format!(
                    "OEP candidate {} is marked refuted after a pending candidate",
                    index + 1
                ));
            }
            CandidateDisposition::Pending if pending.is_none() => pending = Some(event),
            CandidateDisposition::Pending => {
                return Err(
                    "OEP terminal state contains more than one pending candidate".to_owned(),
                );
            }
        }
    }

    if let Some(pending) = pending {
        if !matches!(candidate_events.last(), Some(last) if std::ptr::eq(last, pending)) {
            return Err("the pending OEP candidate is not the final candidate event".to_owned());
        }
        if capture_failure.is_some() {
            return Err(
                "a pending OEP candidate and a capture failure coexist at the terminal boundary"
                    .to_owned(),
            );
        }
        let retained = retained_observation.ok_or_else(|| {
            "the pending OEP candidate has no retained indirect-transfer observation".to_owned()
        })?;
        if retained != &pending.observation {
            return Err(
                "the pending OEP candidate does not match the retained indirect-transfer observation"
                    .to_owned(),
            );
        }
        if stop != &TrapStop::IndirectTransferObserved {
            return Err(format!(
                "the pending OEP candidate ended with {stop:?}, not IndirectTransferObserved"
            ));
        }
        return Ok(OepTerminalState::PendingCandidate);
    }

    if let Some(failure) = capture_failure {
        return match stop {
            TrapStop::IndirectTransferCaptureFailed => Ok(OepTerminalState::CaptureFailed {
                refuted_before,
                failure: failure.clone(),
            }),
            TrapStop::IndirectTransferStopFailed => Ok(OepTerminalState::StopFailed {
                refuted_before,
                payload: OepStopFailurePayload::IncompleteCapture(failure.clone()),
            }),
            _ => Err(format!(
                "retained OEP capture failure ended with incompatible stop {stop:?}"
            )),
        };
    }

    if retained_observation.is_some() {
        return if stop == &TrapStop::IndirectTransferStopFailed {
            Ok(OepTerminalState::StopFailed {
                refuted_before,
                payload: OepStopFailurePayload::CompleteObservation,
            })
        } else {
            Err(format!(
                "an unadjudicated retained OEP observation ended with incompatible stop {stop:?}"
            ))
        };
    }

    if is_indirect_transfer_stop(stop) {
        return Err(format!(
            "OEP run ended with {stop:?} but retained no matching observation or capture failure"
        ));
    }

    if candidate_events.is_empty() {
        Ok(OepTerminalState::DidNotFire)
    } else {
        Ok(OepTerminalState::NoLaterCandidate { refuted_before })
    }
}

fn is_indirect_transfer_stop(stop: &TrapStop) -> bool {
    matches!(
        stop,
        TrapStop::IndirectTransferObserved
            | TrapStop::IndirectTransferCaptureFailed
            | TrapStop::IndirectTransferStopFailed
    )
}

fn print_oep_terminal_state(state: &OepTerminalState) {
    match state {
        OepTerminalState::NotArmed => println!("OEP criterion: not armed"),
        OepTerminalState::DidNotFire => println!("OEP criterion: did not fire"),
        OepTerminalState::PendingCandidate => {}
        OepTerminalState::NoLaterCandidate { refuted_before } => println!(
            "OEP criterion: no later candidate after {refuted_before} adjudicated refutation(s) before the reported stop"
        ),
        OepTerminalState::CaptureFailed {
            refuted_before: 0,
            failure,
        } => println!(
            "OEP criterion: potential edge capture failed; no candidate emitted for the failed edge: {failure}"
        ),
        OepTerminalState::CaptureFailed {
            refuted_before,
            failure,
        } => println!(
            "OEP criterion: later potential edge capture failed after {refuted_before} adjudicated refutation(s); no candidate emitted for the failed edge: {failure}"
        ),
        OepTerminalState::StopFailed {
            refuted_before: 0,
            payload: OepStopFailurePayload::CompleteObservation,
        } => println!(
            "OEP criterion: potential edge proof was captured, but the hook failed to stop emulation; no candidate emitted"
        ),
        OepTerminalState::StopFailed {
            refuted_before,
            payload: OepStopFailurePayload::CompleteObservation,
        } => println!(
            "OEP criterion: later potential edge proof was captured after {refuted_before} adjudicated refutation(s), but the hook failed to stop emulation; no candidate emitted"
        ),
        OepTerminalState::StopFailed {
            refuted_before: 0,
            payload: OepStopFailurePayload::IncompleteCapture(failure),
        } => println!(
            "OEP criterion: potential edge capture failed and the hook also failed to stop emulation; no candidate emitted for the failed edge: {failure}"
        ),
        OepTerminalState::StopFailed {
            refuted_before,
            payload: OepStopFailurePayload::IncompleteCapture(failure),
        } => println!(
            "OEP criterion: later potential edge capture failed after {refuted_before} adjudicated refutation(s), and the hook also failed to stop emulation; no candidate emitted for the failed edge: {failure}"
        ),
    }
}

fn adjudication_image_identity(
    bytes: &[u8],
    image: &PeImage,
    criterion: &OepCriterion,
) -> AdjudicationImageIdentity {
    let layout = criterion.layout();
    let section_identity = |section: &midas::oep::SectionRegion| AdjudicationSectionIdentity {
        section_index: section.section_index,
        start_rva: section.start_rva,
        end_rva: section.end_rva,
    };
    AdjudicationImageIdentity {
        byte_len: bytes.len() as u64,
        byte_sha256: sha256_hex(bytes),
        image_base: image.image_base,
        entry_point_rva: image.entry_point_rva,
        size_of_image: image.size_of_image,
        protector_boundary_rva: layout.protector_boundary_rva,
        loader_sections: layout
            .loader_executable_sections
            .iter()
            .map(section_identity)
            .collect(),
        original_sections: layout
            .original_executable_sections
            .iter()
            .map(section_identity)
            .collect(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn adjudication_execution_context(
    context: IndirectTransferExecutionContext,
) -> AdjudicationExecutionContext {
    match context {
        IndirectTransferExecutionContext::Main => AdjudicationExecutionContext::Main,
        IndirectTransferExecutionContext::Child { thread_id } => {
            AdjudicationExecutionContext::Child { thread_id }
        }
    }
}

fn adjudication_candidate_identity(
    candidate: &OepCandidate,
    observation: &IndirectTransferObservation,
) -> AdjudicationCandidateIdentity {
    AdjudicationCandidateIdentity {
        global_instruction_index: observation.global_instruction_index,
        source_rip: observation.source_rip,
        target_rip: observation.target_rip,
        kind: indirect_transfer_kind_name(observation.kind).to_owned(),
        source_bytes: hex_bytes(&observation.source_bytes),
        target_bytes: hex_bytes(&observation.target_bytes),
        registers: observation
            .registers
            .iter()
            .map(|(register, value)| AdjudicationRegister {
                name: format!("{register:?}"),
                value: *value,
            })
            .collect(),
        source_section_index: candidate.source_section_index,
        target_section_index: candidate.target_section_index,
    }
}

fn indirect_transfer_kind_name(kind: IndirectTransferKind) -> &'static str {
    match kind {
        IndirectTransferKind::Branch => "branch",
        IndirectTransferKind::Call => "call",
        IndirectTransferKind::Return => "return",
    }
}

fn load_adjudication_manifest(
    path: &str,
    expected_image: &AdjudicationImageIdentity,
) -> Result<AdjudicationManifest, String> {
    let manifest_path = Path::new(path);
    let contents = fs::read_to_string(manifest_path)
        .map_err(|error| format!("failed to read OEP adjudication manifest {path:?}: {error}"))?;
    let manifest: AdjudicationManifest = serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse OEP adjudication manifest {path:?}: {error}"))?;
    let manifest_directory = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_adjudication_manifest(&manifest, expected_image, manifest_directory)?;
    Ok(manifest)
}

fn adjudication_entry_matches(
    expected: &AdjudicatedCandidate,
    context: &AdjudicationExecutionContext,
    candidate: &AdjudicationCandidateIdentity,
) -> bool {
    &expected.context == context && &expected.candidate == candidate
}

fn is_manifest_relative_evidence_path(path: &str) -> bool {
    !path.trim().is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_adjudication_manifest(
    manifest: &AdjudicationManifest,
    expected_image: &AdjudicationImageIdentity,
    manifest_directory: &Path,
) -> Result<(), String> {
    if manifest.version != ADJUDICATION_MANIFEST_VERSION {
        return Err(format!(
            "unsupported OEP adjudication manifest version {}, expected {ADJUDICATION_MANIFEST_VERSION}",
            manifest.version
        ));
    }
    if &manifest.image != expected_image {
        return Err(format!(
            "OEP adjudication manifest image identity does not match this input: expected {expected_image:?}, got {:?}",
            manifest.image
        ));
    }
    if manifest.candidates.is_empty() || manifest.candidates.len() > MAX_REFUTED_CANDIDATES {
        return Err(format!(
            "OEP adjudication manifest must contain 1..={MAX_REFUTED_CANDIDATES} candidates"
        ));
    }
    for (index, candidate) in manifest.candidates.iter().enumerate() {
        if candidate.adjudication != "refuted" {
            return Err(format!(
                "OEP adjudication entry {} must say adjudication=\"refuted\"",
                index + 1
            ));
        }
        if !is_manifest_relative_evidence_path(&candidate.evidence_path) {
            return Err(format!(
                "OEP adjudication entry {} requires a manifest-relative disassembly evidence path without root, prefix, current-directory, or parent components",
                index + 1
            ));
        }
        if !is_lowercase_sha256(&candidate.evidence_sha256) {
            return Err(format!(
                "OEP adjudication entry {} requires a lowercase 64-digit evidence SHA-256",
                index + 1
            ));
        }
        if candidate.candidate.registers.len() != 18
            || candidate.candidate.source_bytes.is_empty()
            || candidate.candidate.target_bytes.is_empty()
            || !matches!(
                candidate.candidate.kind.as_str(),
                "branch" | "call" | "return"
            )
        {
            return Err(format!(
                "OEP adjudication entry {} has an incomplete candidate identity",
                index + 1
            ));
        }
        if manifest.candidates[..index].iter().any(|earlier| {
            earlier.context == candidate.context && earlier.candidate == candidate.candidate
        }) {
            return Err(format!(
                "OEP adjudication entry {} duplicates an earlier candidate identity",
                index + 1
            ));
        }
    }

    for (index, candidate) in manifest.candidates.iter().enumerate() {
        let evidence_path = manifest_directory.join(&candidate.evidence_path);
        let evidence_bytes = fs::read(&evidence_path).map_err(|error| {
            format!(
                "failed to read OEP adjudication entry {} evidence {:?}: {error}",
                index + 1,
                evidence_path
            )
        })?;
        let actual_sha256 = sha256_hex(&evidence_bytes);
        if actual_sha256 != candidate.evidence_sha256 {
            return Err(format!(
                "OEP adjudication entry {} evidence SHA-256 mismatch for {:?}: expected {}, got {actual_sha256}",
                index + 1,
                evidence_path,
                candidate.evidence_sha256,
            ));
        }
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn pending_adjudication_template(
    image: &AdjudicationImageIdentity,
    supplied: Option<&AdjudicationManifest>,
    consumed: usize,
    pending: &CandidateEvent,
) -> AdjudicationManifest {
    let mut candidates = supplied
        .map(|manifest| manifest.candidates[..consumed].to_vec())
        .unwrap_or_default();
    candidates.push(AdjudicatedCandidate {
        context: pending.context.clone(),
        candidate: pending.identity.clone(),
        adjudication: "pending".to_owned(),
        evidence_path: String::new(),
        evidence_sha256: String::new(),
    });
    AdjudicationManifest {
        version: ADJUDICATION_MANIFEST_VERSION,
        image: image.clone(),
        candidates,
    }
}

fn section_va_ranges(
    mapped_base: u64,
    sections: &[midas::oep::SectionRegion],
) -> Result<Vec<(u64, u64)>, String> {
    sections
        .iter()
        .map(|section| {
            let start = mapped_base
                .checked_add(u64::from(section.start_rva))
                .ok_or_else(|| "OEP source/target section start overflows".to_owned())?;
            let end = mapped_base
                .checked_add(u64::from(section.end_rva))
                .ok_or_else(|| "OEP source/target section end overflows".to_owned())?;
            Ok((start, end))
        })
        .collect()
}

fn print_oep_candidate(index: usize, event: &CandidateEvent) {
    let candidate = &event.candidate;
    let observation = &event.observation;
    println!("OEP criterion: fired candidate {index}");
    println!("  execution context: {:?}", event.context);
    match &event.disposition {
        CandidateDisposition::Refuted {
            evidence_path,
            evidence_sha256,
        } => {
            println!(
                "  adjudication: refuted; evidence_path={evidence_path:?} evidence_sha256={evidence_sha256}"
            );
            println!("  action: exact observation matched; watch rearmed with coverage preserved");
        }
        CandidateDisposition::Pending => println!(
            "  adjudication: pending reproducibility and runtime-disassembly review; execution stopped"
        ),
    }
    println!("OEP candidate RIP: 0x{:016x}", candidate.rip);
    println!(
        "  global instruction: {}",
        observation.global_instruction_index
    );
    println!(
        "  source: 0x{:016x} section={} kind={:?} bytes={}",
        candidate.source_rip,
        candidate.source_section_index,
        candidate.kind,
        hex_bytes(&observation.source_bytes),
    );
    println!(
        "  target section: {} runtime_bytes={}",
        candidate.target_section_index,
        hex_bytes(&observation.target_bytes),
    );
    println!("  target disassembly:");
    let mut decoder = Decoder::with_ip(
        64,
        &observation.target_bytes,
        candidate.rip,
        DecoderOptions::NONE,
    );
    let mut formatter = NasmFormatter::new();
    for _ in 0..8 {
        if !decoder.can_decode() {
            break;
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            println!("    0x{:016x}: <invalid>", instruction.ip());
            break;
        }
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        println!("    0x{:016x}: {text}", instruction.ip());
    }
    println!("  captured registers:");
    for (register, value) in &observation.registers {
        println!("    {register:?}=0x{value:016x}");
    }
}

fn print_exception_continuation(observation: &midas::win64::ExceptionContinuationObservation) {
    println!("exception continuation: changed RIP; execution stopped before target");
    println!("  classification: separate OEP hypothesis, not a guest indirect-transfer firing");
    println!("  thread: {}", observation.thread_id);
    println!("  exception code: 0x{:08x}", observation.exception_code);
    println!(
        "  handler returning CONTINUE_EXECUTION: 0x{:016x}",
        observation.continuing_handler
    );
    println!("  original RIP: 0x{:016x}", observation.original_rip);
    println!(
        "  continuation RIP: 0x{:016x}",
        observation.continuation_rip
    );
    println!("  context record: 0x{:016x}", observation.context_record);
    println!(
        "  target runtime bytes: {}",
        hex_bytes(&observation.target_bytes)
    );
    println!("  target disassembly:");
    let mut decoder = Decoder::with_ip(
        64,
        &observation.target_bytes,
        observation.continuation_rip,
        DecoderOptions::NONE,
    );
    let mut formatter = NasmFormatter::new();
    for _ in 0..8 {
        if !decoder.can_decode() {
            break;
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            println!("    0x{:016x}: <invalid>", instruction.ip());
            break;
        }
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        println!("    0x{:016x}: {text}", instruction.ip());
    }
    println!("  frozen context registers:");
    for (register, value) in &observation.registers {
        println!("    {register:?}=0x{value:016x}");
    }
    println!(
        "  frozen context bytes: {}",
        hex_bytes(&observation.context_bytes)
    );
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn usage(program: &str) -> String {
    format!("usage: {program} <pe> [per_run_cap] [max_calls] [refuted-oep-candidates.json]")
}

fn parse_arg<T>(value: Option<String>, default: T, name: &str) -> Result<T, String>
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

fn format_stop(_image: &PeImage, stop: &TrapStop) -> String {
    match stop {
        TrapStop::UnhandledApi { name, rva } => {
            format!("unhandled API {name} at export-stub or import rva=0x{rva:08x}")
        }
        TrapStop::UnhandledSoftwareException { code } => {
            format!("unhandled software exception 0x{code:08x}")
        }
        TrapStop::NoncontinuableContinuationAttempt { code } => {
            format!("VEH attempted to continue noncontinuable exception 0x{code:08x}")
        }
        TrapStop::InvalidVectoredExceptionDisposition { code, disposition } => format!(
            "VEH returned invalid disposition 0x{disposition:08x} for exception 0x{code:08x}"
        ),
        TrapStop::InvalidVectoredExceptionContext { code } => {
            format!("VEH produced an invalid context for exception 0x{code:08x}")
        }
        TrapStop::ExceptionContinuationObserved => {
            "VEH changed CONTEXT.Rip; frozen before host-mediated continuation".to_owned()
        }
        TrapStop::IncompleteVectoredExceptionDispatch { thread_id } => format!(
            "cooperative child {thread_id} stopped before completing vectored exception dispatch"
        ),
        TrapStop::UnexpectedFault { address } => {
            format!("unexpected fetch fault at 0x{address:016x}")
        }
        TrapStop::InstructionCap => "instruction cap reached".to_owned(),
        TrapStop::IndirectTransferObserved => "OEP indirect transfer observed".to_owned(),
        TrapStop::IndirectTransferCaptureFailed => {
            "OEP indirect-transfer proof capture failed".to_owned()
        }
        TrapStop::IndirectTransferStopFailed => {
            "OEP indirect-transfer hook failed to stop emulation".to_owned()
        }
        TrapStop::NullControlTransfer => "null control transfer".to_owned(),
        TrapStop::Other(value) => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midas::emu::IndirectTransferCaptureFailureReason;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "midas-run-loader-test-{}-{sequence}",
                process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(relative);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn image_identity() -> AdjudicationImageIdentity {
        AdjudicationImageIdentity {
            byte_len: 0x1234,
            byte_sha256: sha256_hex(b"test image"),
            image_base: 0x0000_0001_4000_0000,
            entry_point_rva: 0x9000,
            size_of_image: 0xc000,
            protector_boundary_rva: 0x4000,
            loader_sections: vec![AdjudicationSectionIdentity {
                section_index: 2,
                start_rva: 0x4000,
                end_rva: 0x9000,
            }],
            original_sections: vec![AdjudicationSectionIdentity {
                section_index: 0,
                start_rva: 0x1000,
                end_rva: 0x2000,
            }],
        }
    }

    fn candidate_identity(seed: u64) -> AdjudicationCandidateIdentity {
        AdjudicationCandidateIdentity {
            global_instruction_index: 100 + seed,
            source_rip: 0x0000_0001_4000_4100 + seed,
            target_rip: 0x0000_0001_4000_1100 + seed,
            kind: "branch".to_owned(),
            source_bytes: "ffe0".to_owned(),
            target_bytes: "554889e5".to_owned(),
            registers: (0..18)
                .map(|index| AdjudicationRegister {
                    name: format!("R{index}"),
                    value: seed + index,
                })
                .collect(),
            source_section_index: 2,
            target_section_index: 0,
        }
    }

    fn refuted(seed: u64) -> AdjudicatedCandidate {
        AdjudicatedCandidate {
            context: AdjudicationExecutionContext::Main,
            candidate: candidate_identity(seed),
            adjudication: "refuted".to_owned(),
            evidence_path: format!("evidence-{seed}.txt"),
            evidence_sha256: ABC_SHA256.to_owned(),
        }
    }

    fn candidate_event(seed: u64, disposition: CandidateDisposition) -> CandidateEvent {
        let identity = candidate_identity(seed);
        CandidateEvent {
            context: AdjudicationExecutionContext::Main,
            candidate: OepCandidate {
                rip: identity.target_rip,
                source_rip: identity.source_rip,
                kind: midas::oep::TransferKind::IndirectBranch,
                source_section_index: identity.source_section_index,
                target_section_index: identity.target_section_index,
            },
            observation: IndirectTransferObservation {
                global_instruction_index: identity.global_instruction_index,
                source_rip: identity.source_rip,
                target_rip: identity.target_rip,
                kind: IndirectTransferKind::Branch,
                source_bytes: vec![0xff, 0xe0],
                target_bytes: vec![0x55, 0x48, 0x89, 0xe5],
                registers: Vec::new(),
            },
            identity,
            disposition,
        }
    }

    fn capture_failure(seed: u64) -> IndirectTransferCaptureFailure {
        IndirectTransferCaptureFailure {
            global_instruction_index: 200 + seed,
            source_rip: 0x0000_0001_4000_4200 + seed,
            target_rip: 0x0000_0001_4000_1200 + seed,
            reason: IndirectTransferCaptureFailureReason::TargetBytesUnavailable,
        }
    }

    #[test]
    fn adjudication_manifest_round_trips_and_accepts_only_complete_refutations() {
        let directory = TestDirectory::new();
        directory.write("evidence-1.txt", b"abc");
        let expected_image = image_identity();
        let manifest = AdjudicationManifest {
            version: ADJUDICATION_MANIFEST_VERSION,
            image: expected_image.clone(),
            candidates: vec![refuted(1)],
        };
        validate_adjudication_manifest(&manifest, &expected_image, directory.path()).unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        assert_eq!(
            serde_json::from_str::<AdjudicationManifest>(&json).unwrap(),
            manifest
        );

        let mut invalid = manifest.clone();
        invalid.candidates[0].adjudication = "pending".to_owned();
        assert!(
            validate_adjudication_manifest(&invalid, &expected_image, directory.path()).is_err()
        );
        let mut invalid = manifest.clone();
        invalid.candidates[0].evidence_path.clear();
        assert!(
            validate_adjudication_manifest(&invalid, &expected_image, directory.path()).is_err()
        );
        let mut invalid = manifest.clone();
        invalid.candidates[0].evidence_sha256.make_ascii_uppercase();
        assert!(
            validate_adjudication_manifest(&invalid, &expected_image, directory.path()).is_err()
        );
        let mut invalid = manifest.clone();
        invalid.candidates[0].candidate.registers.pop();
        assert!(
            validate_adjudication_manifest(&invalid, &expected_image, directory.path()).is_err()
        );
        let mut invalid = manifest.clone();
        invalid.candidates.push(invalid.candidates[0].clone());
        assert!(
            validate_adjudication_manifest(&invalid, &expected_image, directory.path()).is_err()
        );
        let mut wrong_image = expected_image.clone();
        wrong_image.byte_sha256.replace_range(0..1, "0");
        assert!(validate_adjudication_manifest(&manifest, &wrong_image, directory.path()).is_err());
    }

    #[test]
    fn manifest_evidence_is_resolved_relative_to_manifest_and_content_addressed() {
        let directory = TestDirectory::new();
        let evidence_path = directory.write("evidence-1.txt", b"abc");
        let expected_image = image_identity();
        let manifest = AdjudicationManifest {
            version: ADJUDICATION_MANIFEST_VERSION,
            image: expected_image.clone(),
            candidates: vec![refuted(1)],
        };
        let manifest_path = directory.write(
            "refutations.json",
            serde_json::to_string_pretty(&manifest).unwrap().as_bytes(),
        );

        assert_eq!(
            load_adjudication_manifest(manifest_path.to_str().unwrap(), &expected_image).unwrap(),
            manifest
        );

        fs::write(&evidence_path, b"mutated").unwrap();
        let error = load_adjudication_manifest(manifest_path.to_str().unwrap(), &expected_image)
            .unwrap_err();
        assert!(error.contains("evidence SHA-256 mismatch"), "{error}");

        fs::remove_file(&evidence_path).unwrap();
        let error = load_adjudication_manifest(manifest_path.to_str().unwrap(), &expected_image)
            .unwrap_err();
        assert!(error.contains("failed to read"), "{error}");
    }

    #[test]
    fn manifest_evidence_rejects_absolute_and_traversing_paths() {
        let directory = TestDirectory::new();
        let expected_image = image_identity();
        for evidence_path in [
            directory
                .path()
                .join("evidence-1.txt")
                .display()
                .to_string(),
            "../evidence-1.txt".to_owned(),
            "nested/../../evidence-1.txt".to_owned(),
            "./evidence-1.txt".to_owned(),
        ] {
            let mut manifest = AdjudicationManifest {
                version: ADJUDICATION_MANIFEST_VERSION,
                image: expected_image.clone(),
                candidates: vec![refuted(1)],
            };
            manifest.candidates[0].evidence_path = evidence_path;
            let error =
                validate_adjudication_manifest(&manifest, &expected_image, directory.path())
                    .unwrap_err();
            assert!(error.contains("manifest-relative"), "{error}");
        }
    }

    #[test]
    fn candidate_identity_matching_is_exact_across_context_bytes_and_registers() {
        let expected_context = AdjudicationExecutionContext::Child { thread_id: 2 };
        let expected = candidate_identity(7);

        assert_ne!(
            expected_context,
            AdjudicationExecutionContext::Child { thread_id: 3 }
        );
        for mutate in [
            |value: &mut AdjudicationCandidateIdentity| value.global_instruction_index ^= 1,
            |value: &mut AdjudicationCandidateIdentity| value.source_rip ^= 1,
            |value: &mut AdjudicationCandidateIdentity| value.target_rip ^= 1,
            |value: &mut AdjudicationCandidateIdentity| value.kind = "return".to_owned(),
            |value: &mut AdjudicationCandidateIdentity| value.source_bytes.push_str("90"),
            |value: &mut AdjudicationCandidateIdentity| value.target_bytes.push_str("90"),
            |value: &mut AdjudicationCandidateIdentity| value.registers[0].value ^= 1,
            |value: &mut AdjudicationCandidateIdentity| value.registers[0].name.push_str("X"),
            |value: &mut AdjudicationCandidateIdentity| value.registers.swap(0, 1),
            |value: &mut AdjudicationCandidateIdentity| value.source_section_index ^= 1,
            |value: &mut AdjudicationCandidateIdentity| value.target_section_index ^= 1,
        ] {
            let mut changed = expected.clone();
            mutate(&mut changed);
            assert_ne!(changed, expected);
        }
    }

    #[test]
    fn ordered_multi_candidate_manifest_authorizes_only_the_next_exact_identity() {
        let first = refuted(1);
        let second = refuted(2);
        let manifest = AdjudicationManifest {
            version: ADJUDICATION_MANIFEST_VERSION,
            image: image_identity(),
            candidates: vec![first.clone(), second.clone()],
        };
        let context = AdjudicationExecutionContext::Main;

        assert!(adjudication_entry_matches(
            &manifest.candidates[0],
            &context,
            &first.candidate,
        ));
        assert!(!adjudication_entry_matches(
            &manifest.candidates[0],
            &context,
            &second.candidate,
        ));
        assert!(adjudication_entry_matches(
            &manifest.candidates[1],
            &context,
            &second.candidate,
        ));
        assert!(!adjudication_entry_matches(
            &manifest.candidates[1],
            &AdjudicationExecutionContext::Child { thread_id: 2 },
            &second.candidate,
        ));
        assert!(manifest.candidates.get(2).is_none());
    }

    #[test]
    fn pending_template_preserves_consumed_refutations_but_cannot_authorize_resume() {
        let image = image_identity();
        let supplied = AdjudicationManifest {
            version: ADJUDICATION_MANIFEST_VERSION,
            image: image.clone(),
            candidates: vec![refuted(1)],
        };
        let event = candidate_event(2, CandidateDisposition::Pending);
        let identity = event.identity.clone();

        let template = pending_adjudication_template(&image, Some(&supplied), 1, &event);
        assert_eq!(template.candidates[0], supplied.candidates[0]);
        assert_eq!(template.candidates[1].candidate, identity);
        assert_eq!(template.candidates[1].adjudication, "pending");
        assert!(template.candidates[1].evidence_path.is_empty());
        assert!(template.candidates[1].evidence_sha256.is_empty());
        assert!(validate_adjudication_manifest(&template, &image, Path::new(".")).is_err());
    }

    #[test]
    fn sha256_digest_matches_known_vector_and_is_lowercase() {
        assert_eq!(sha256_hex(b"abc"), ABC_SHA256);
        assert!(is_lowercase_sha256(ABC_SHA256));
        assert!(!is_lowercase_sha256(&ABC_SHA256.to_uppercase()));
        assert_ne!(sha256_hex(b"midas"), sha256_hex(b"midAs"));
    }

    #[test]
    fn terminal_state_accepts_unarmed_idle_and_armed_no_fire() {
        assert_eq!(
            validate_oep_terminal_state(false, &[], None, None, &TrapStop::NullControlTransfer)
                .unwrap(),
            OepTerminalState::NotArmed
        );
        assert_eq!(
            validate_oep_terminal_state(true, &[], None, None, &TrapStop::InstructionCap).unwrap(),
            OepTerminalState::DidNotFire
        );
        assert!(validate_oep_terminal_state(
            false,
            &[],
            None,
            None,
            &TrapStop::IndirectTransferObserved
        )
        .is_err());
    }

    #[test]
    fn terminal_state_requires_pending_to_match_retained_observation_and_stop() {
        let pending = candidate_event(1, CandidateDisposition::Pending);
        let retained = pending.observation.clone();
        assert_eq!(
            validate_oep_terminal_state(
                true,
                std::slice::from_ref(&pending),
                Some(&retained),
                None,
                &TrapStop::IndirectTransferObserved,
            )
            .unwrap(),
            OepTerminalState::PendingCandidate
        );

        assert!(validate_oep_terminal_state(
            true,
            std::slice::from_ref(&pending),
            None,
            None,
            &TrapStop::IndirectTransferObserved,
        )
        .is_err());
        let different = candidate_event(2, CandidateDisposition::Pending).observation;
        assert!(validate_oep_terminal_state(
            true,
            std::slice::from_ref(&pending),
            Some(&different),
            None,
            &TrapStop::IndirectTransferObserved,
        )
        .is_err());
        assert!(validate_oep_terminal_state(
            true,
            &[pending],
            Some(&retained),
            None,
            &TrapStop::InstructionCap,
        )
        .is_err());
    }

    #[test]
    fn terminal_state_requires_all_refuted_natural_stop_to_retain_nothing() {
        let refuted_event = candidate_event(
            1,
            CandidateDisposition::Refuted {
                evidence_path: "evidence-1.txt".to_owned(),
                evidence_sha256: ABC_SHA256.to_owned(),
            },
        );
        assert_eq!(
            validate_oep_terminal_state(
                true,
                std::slice::from_ref(&refuted_event),
                None,
                None,
                &TrapStop::InstructionCap,
            )
            .unwrap(),
            OepTerminalState::NoLaterCandidate { refuted_before: 1 }
        );

        let retained = refuted_event.observation.clone();
        assert!(validate_oep_terminal_state(
            true,
            &[refuted_event],
            Some(&retained),
            None,
            &TrapStop::InstructionCap,
        )
        .is_err());
    }

    #[test]
    fn terminal_state_distinguishes_initial_and_later_capture_failures() {
        let failure = capture_failure(1);
        assert_eq!(
            validate_oep_terminal_state(
                true,
                &[],
                None,
                Some(&failure),
                &TrapStop::IndirectTransferCaptureFailed,
            )
            .unwrap(),
            OepTerminalState::CaptureFailed {
                refuted_before: 0,
                failure: failure.clone(),
            }
        );

        let refuted_event = candidate_event(
            1,
            CandidateDisposition::Refuted {
                evidence_path: "evidence-1.txt".to_owned(),
                evidence_sha256: ABC_SHA256.to_owned(),
            },
        );
        assert_eq!(
            validate_oep_terminal_state(
                true,
                &[refuted_event],
                None,
                Some(&failure),
                &TrapStop::IndirectTransferCaptureFailed,
            )
            .unwrap(),
            OepTerminalState::CaptureFailed {
                refuted_before: 1,
                failure,
            }
        );
    }

    #[test]
    fn terminal_state_distinguishes_complete_and_incomplete_stop_failures() {
        let refuted_event = candidate_event(
            1,
            CandidateDisposition::Refuted {
                evidence_path: "evidence-1.txt".to_owned(),
                evidence_sha256: ABC_SHA256.to_owned(),
            },
        );
        let retained = candidate_event(2, CandidateDisposition::Pending).observation;
        assert_eq!(
            validate_oep_terminal_state(
                true,
                std::slice::from_ref(&refuted_event),
                Some(&retained),
                None,
                &TrapStop::IndirectTransferStopFailed,
            )
            .unwrap(),
            OepTerminalState::StopFailed {
                refuted_before: 1,
                payload: OepStopFailurePayload::CompleteObservation,
            }
        );

        let failure = capture_failure(2);
        assert_eq!(
            validate_oep_terminal_state(
                true,
                &[refuted_event],
                None,
                Some(&failure),
                &TrapStop::IndirectTransferStopFailed,
            )
            .unwrap(),
            OepTerminalState::StopFailed {
                refuted_before: 1,
                payload: OepStopFailurePayload::IncompleteCapture(failure),
            }
        );
    }

    #[test]
    fn terminal_state_rejects_watch_stop_without_matching_latch() {
        for stop in [
            TrapStop::IndirectTransferObserved,
            TrapStop::IndirectTransferCaptureFailed,
            TrapStop::IndirectTransferStopFailed,
        ] {
            assert!(validate_oep_terminal_state(true, &[], None, None, &stop).is_err());
        }
    }
}
