//! Runtime-derived original-entry-point candidate detection.
//!
//! This layer deliberately reports a candidate, not proof of the OEP. A
//! candidate still requires reproducible execution and disassembly of bytes
//! captured from the unpacked runtime image. Section names and preferred image
//! addresses never participate in the criterion.

use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use thiserror::Error;

use crate::{
    emu::{IndirectTransferKind, IndirectTransferObservation},
    pe::{PeImage, Section},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionRegion {
    pub section_index: usize,
    pub start_rva: u32,
    pub end_rva: u32,
}

impl SectionRegion {
    fn contains_rva(self, rva: u32) -> bool {
        self.start_rva <= rva && rva < self.end_rva
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OepLayout {
    pub mapped_base: u64,
    pub image_size: u32,
    pub protector_boundary_rva: u32,
    pub bridge_section_index: usize,
    pub entry_section_index: usize,
    pub original_executable_sections: Vec<SectionRegion>,
    pub loader_executable_sections: Vec<SectionRegion>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OepLayoutError {
    #[error("{field} must be nonzero")]
    ZeroAlignment { field: &'static str },
    #[error("{field} must be a power of two, got {value:#x}")]
    NonPowerOfTwoAlignment { field: &'static str, value: u32 },
    #[error("mapped image range overflows the address space")]
    ImageRangeOverflow,
    #[error("section {section_index} has an invalid or overflowing mapped range")]
    InvalidSectionRange { section_index: usize },
    #[error("section {section_index} extends beyond SizeOfImage")]
    SectionOutsideImage { section_index: usize },
    #[error("mapped ranges of sections {first_index} and {second_index} overlap")]
    OverlappingSections {
        first_index: usize,
        second_index: usize,
    },
    #[error("the entry-point RVA does not belong to exactly one mapped section")]
    EntrySectionMissingOrAmbiguous,
    #[error("the entry-point section is not executable code")]
    EntrySectionNotExecutableCode,
    #[error("the entry-point section has no raw backing")]
    EntrySectionNotRawBacked,
    #[error("the entry-point section has no immediate predecessor")]
    MissingBridgeSection,
    #[error("the entry-point predecessor is not a rawless writable executable code section")]
    InvalidBridgeSection,
    #[error("the rawless bridge is not mapped-adjacent to the entry-point section")]
    BridgeNotAdjacent,
    #[error("the bridge and entry-point sections do not begin at the earlier raw-data frontier")]
    RawFrontierMismatch,
    #[error("no pre-boundary executable code section was found")]
    NoOriginalExecutableSection,
    #[error("a pre-boundary executable code section has no raw backing")]
    OriginalExecutableNotRawBacked,
    #[error("a pre-boundary executable section is not marked as code")]
    OriginalExecutableNotCode,
    #[error("a pre-boundary code section is not executable")]
    OriginalCodeNotExecutable,
    #[error("BaseOfCode does not identify exactly one pre-boundary executable code section")]
    BaseOfCodeMismatch,
    #[error("pre-boundary executable code does not account exactly for SizeOfCode")]
    SizeOfCodeMismatch,
}

#[derive(Debug, Clone, Copy)]
struct IndexedSection<'a> {
    index: usize,
    section: &'a Section,
    declared_end: u32,
    content_end: u32,
    mapped_end: u32,
}

impl OepLayout {
    /// Derive the supported protected-image layout from PE metadata.
    ///
    /// The recognizer intentionally fails closed. It requires an executable
    /// raw-backed entry section appended at the earlier sections' raw frontier,
    /// preceded by a mapped-adjacent rawless RWX code section. The executable
    /// sections before that bridge must also agree with the optional header's
    /// preserved `BaseOfCode` and `SizeOfCode` accounting.
    pub fn derive(image: &PeImage, mapped_base: u64) -> Result<Self, OepLayoutError> {
        if image.section_alignment == 0 {
            return Err(OepLayoutError::ZeroAlignment {
                field: "SectionAlignment",
            });
        }
        if image.file_alignment == 0 {
            return Err(OepLayoutError::ZeroAlignment {
                field: "FileAlignment",
            });
        }
        if !image.section_alignment.is_power_of_two() {
            return Err(OepLayoutError::NonPowerOfTwoAlignment {
                field: "SectionAlignment",
                value: image.section_alignment,
            });
        }
        if !image.file_alignment.is_power_of_two() {
            return Err(OepLayoutError::NonPowerOfTwoAlignment {
                field: "FileAlignment",
                value: image.file_alignment,
            });
        }
        mapped_base
            .checked_add(u64::from(image.size_of_image))
            .ok_or(OepLayoutError::ImageRangeOverflow)?;

        let mut sections = image
            .sections
            .iter()
            .enumerate()
            .map(|(index, section)| indexed_section(index, section, image))
            .collect::<Result<Vec<_>, _>>()?;
        sections.sort_by_key(|indexed| (indexed.section.virtual_address, indexed.index));

        for pair in sections.windows(2) {
            if pair[0].mapped_end > pair[1].section.virtual_address {
                return Err(OepLayoutError::OverlappingSections {
                    first_index: pair[0].index,
                    second_index: pair[1].index,
                });
            }
        }

        let entry_positions = sections
            .iter()
            .enumerate()
            .filter_map(|(position, indexed)| {
                (indexed.section.virtual_address <= image.entry_point_rva
                    && image.entry_point_rva < indexed.content_end)
                    .then_some(position)
            })
            .collect::<Vec<_>>();
        let [entry_position] = entry_positions.as_slice() else {
            return Err(OepLayoutError::EntrySectionMissingOrAmbiguous);
        };
        let entry_position = *entry_position;
        let entry = sections[entry_position];
        if !is_executable_code(entry.section) {
            return Err(OepLayoutError::EntrySectionNotExecutableCode);
        }
        if entry.section.size_of_raw_data == 0 {
            return Err(OepLayoutError::EntrySectionNotRawBacked);
        }

        let bridge_position = entry_position
            .checked_sub(1)
            .ok_or(OepLayoutError::MissingBridgeSection)?;
        let bridge = sections[bridge_position];
        if bridge.section.virtual_size == 0
            || bridge.section.size_of_raw_data != 0
            || !is_executable_code(bridge.section)
            || bridge.section.characteristics & IMAGE_SCN_MEM_WRITE == 0
        {
            return Err(OepLayoutError::InvalidBridgeSection);
        }
        if bridge.mapped_end != entry.section.virtual_address {
            return Err(OepLayoutError::BridgeNotAdjacent);
        }

        let earlier_raw_frontier = sections[..bridge_position]
            .iter()
            .filter(|indexed| indexed.section.size_of_raw_data != 0)
            .map(|indexed| {
                u64::from(indexed.section.pointer_to_raw_data)
                    .checked_add(u64::from(indexed.section.size_of_raw_data))
                    .ok_or(OepLayoutError::RawFrontierMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or(OepLayoutError::RawFrontierMismatch)?;
        let entry_raw = u64::from(entry.section.pointer_to_raw_data);
        if earlier_raw_frontier != entry_raw
            || bridge.section.pointer_to_raw_data != entry.section.pointer_to_raw_data
        {
            return Err(OepLayoutError::RawFrontierMismatch);
        }

        let pre_boundary = &sections[..bridge_position];
        let executable = pre_boundary
            .iter()
            .filter(|indexed| is_executable(indexed.section) && indexed.section.virtual_size != 0)
            .copied()
            .collect::<Vec<_>>();
        if executable.is_empty() {
            return Err(OepLayoutError::NoOriginalExecutableSection);
        }
        if executable
            .iter()
            .any(|indexed| indexed.section.size_of_raw_data == 0)
        {
            return Err(OepLayoutError::OriginalExecutableNotRawBacked);
        }
        if executable.iter().any(|indexed| !is_code(indexed.section)) {
            return Err(OepLayoutError::OriginalExecutableNotCode);
        }
        if pre_boundary
            .iter()
            .any(|indexed| is_code(indexed.section) && !is_executable(indexed.section))
        {
            return Err(OepLayoutError::OriginalCodeNotExecutable);
        }

        let base_matches = executable
            .iter()
            .filter(|indexed| indexed.section.virtual_address == image.base_of_code)
            .count();
        if base_matches != 1 {
            return Err(OepLayoutError::BaseOfCodeMismatch);
        }

        let accounted_code_size = executable.iter().try_fold(0u64, |total, indexed| {
            let aligned = align_up(
                u64::from(indexed.section.virtual_size),
                image.file_alignment,
            )
            .ok_or(OepLayoutError::SizeOfCodeMismatch)?;
            total
                .checked_add(aligned)
                .ok_or(OepLayoutError::SizeOfCodeMismatch)
        })?;
        if accounted_code_size != u64::from(image.size_of_code) {
            return Err(OepLayoutError::SizeOfCodeMismatch);
        }

        let original_executable_sections = executable
            .iter()
            .map(|indexed| SectionRegion {
                section_index: indexed.index,
                start_rva: indexed.section.virtual_address,
                end_rva: indexed.declared_end,
            })
            .collect::<Vec<_>>();
        let loader_executable_sections = sections[bridge_position..]
            .iter()
            .filter(|indexed| {
                is_executable(indexed.section)
                    && indexed.declared_end > indexed.section.virtual_address
            })
            .map(|indexed| SectionRegion {
                section_index: indexed.index,
                start_rva: indexed.section.virtual_address,
                end_rva: indexed.declared_end,
            })
            .collect::<Vec<_>>();

        Ok(Self {
            mapped_base,
            image_size: image.size_of_image,
            protector_boundary_rva: bridge.section.virtual_address,
            bridge_section_index: bridge.index,
            entry_section_index: entry.index,
            original_executable_sections,
            loader_executable_sections,
        })
    }

    fn address_to_rva(&self, address: u64) -> Option<u32> {
        let delta = address.checked_sub(self.mapped_base)?;
        let rva = u32::try_from(delta).ok()?;
        (rva < self.image_size).then_some(rva)
    }

    fn original_section_at(&self, address: u64) -> Option<SectionRegion> {
        let rva = self.address_to_rva(address)?;
        self.original_executable_sections
            .iter()
            .copied()
            .find(|region| region.contains_rva(rva))
    }

    fn loader_section_at(&self, address: u64) -> Option<SectionRegion> {
        let rva = self.address_to_rva(address)?;
        self.loader_executable_sections
            .iter()
            .copied()
            .find(|region| region.contains_rva(rva))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    DirectBranch,
    IndirectBranch,
    IndirectCall,
    Return,
}

impl TransferKind {
    fn is_indirect_tail(self) -> bool {
        matches!(self, Self::IndirectBranch | Self::Return)
    }
}

impl From<IndirectTransferKind> for TransferKind {
    fn from(kind: IndirectTransferKind) -> Self {
        match kind {
            IndirectTransferKind::Branch => Self::IndirectBranch,
            IndirectTransferKind::Call => Self::IndirectCall,
            IndirectTransferKind::Return => Self::Return,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferObservation {
    pub source_rip: u64,
    pub target_rip: u64,
    pub kind: TransferKind,
    /// Whether the exact target RIP appeared earlier in the execution history.
    pub target_previously_executed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OepCandidate {
    pub rip: u64,
    pub source_rip: u64,
    pub kind: TransferKind,
    pub source_section_index: usize,
    pub target_section_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OepCriterion {
    layout: OepLayout,
}

impl OepCriterion {
    pub fn new(image: &PeImage, mapped_base: u64) -> Result<Self, OepLayoutError> {
        Ok(Self {
            layout: OepLayout::derive(image, mapped_base)?,
        })
    }

    pub fn layout(&self) -> &OepLayout {
        &self.layout
    }

    /// Evaluate one already-decoded control transfer.
    ///
    /// Calls are excluded because loader-invoked callbacks or helpers would be
    /// ambiguous. The first accepted observation is only an OEP candidate; the
    /// caller owns execution-history tracking and must still capture registers
    /// and runtime bytes for the M4 proof artifact.
    pub fn evaluate(&self, observation: TransferObservation) -> Option<OepCandidate> {
        if !observation.kind.is_indirect_tail() || observation.target_previously_executed {
            return None;
        }
        let source = self.layout.loader_section_at(observation.source_rip)?;
        let target = self.layout.original_section_at(observation.target_rip)?;

        Some(OepCandidate {
            rip: observation.target_rip,
            source_rip: observation.source_rip,
            kind: observation.kind,
            source_section_index: source.section_index,
            target_section_index: target.section_index,
        })
    }

    /// Evaluate a proof payload captured by [`crate::emu::Emu`]'s bounded
    /// indirect-transfer watch.
    ///
    /// The emulator watch emits an observation only for the first entry to its
    /// exact target RIP. Keeping that invariant at this consuming boundary
    /// avoids implying that an arbitrary transfer has unseen-target history.
    /// Keeping the conversion in the library also makes the production FIRE
    /// path share the same tested mapping as the criterion.
    pub fn evaluate_indirect_transfer_observation(
        &self,
        observation: &IndirectTransferObservation,
    ) -> Option<OepCandidate> {
        self.evaluate(TransferObservation {
            source_rip: observation.source_rip,
            target_rip: observation.target_rip,
            kind: observation.kind.into(),
            target_previously_executed: false,
        })
    }
}

fn indexed_section<'a>(
    index: usize,
    section: &'a Section,
    image: &PeImage,
) -> Result<IndexedSection<'a>, OepLayoutError> {
    let declared_end = section
        .virtual_address
        .checked_add(section.virtual_size)
        .ok_or(OepLayoutError::InvalidSectionRange {
            section_index: index,
        })?;
    let mapped_size = section.virtual_size.max(section.size_of_raw_data);
    let content_end = section.virtual_address.checked_add(mapped_size).ok_or(
        OepLayoutError::InvalidSectionRange {
            section_index: index,
        },
    )?;
    let mapped_end = if mapped_size == 0 {
        content_end
    } else {
        let unaligned_end = u64::from(section.virtual_address)
            .checked_add(u64::from(mapped_size))
            .ok_or(OepLayoutError::InvalidSectionRange {
                section_index: index,
            })?;
        align_up(unaligned_end, image.section_alignment)
            .and_then(|end| u32::try_from(end).ok())
            .ok_or(OepLayoutError::InvalidSectionRange {
                section_index: index,
            })?
    };
    if mapped_end > image.size_of_image {
        return Err(OepLayoutError::SectionOutsideImage {
            section_index: index,
        });
    }

    Ok(IndexedSection {
        index,
        section,
        declared_end,
        content_end,
        mapped_end,
    })
}

fn align_up(value: u64, alignment: u32) -> Option<u64> {
    let alignment = u64::from(alignment);
    let remainder = value.checked_rem(alignment)?;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

fn is_executable(section: &Section) -> bool {
    section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
}

fn is_code(section: &Section) -> bool {
    section.characteristics & IMAGE_SCN_CNT_CODE != 0
}

fn is_executable_code(section: &Section) -> bool {
    is_executable(section) && is_code(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emu::{Emu, StopReason};
    use std::{fs, path::Path};

    const PREFERRED_BASE: u64 = 0x0000_0001_4000_0000;
    const REBASED: u64 = 0x0000_0001_8000_0000;
    const CODE_XR: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | 0x4000_0040;
    const CODE_RWX: u32 = CODE_XR | IMAGE_SCN_MEM_WRITE;
    const DATA_RW: u32 = 0xc000_0040;
    const DATA_R: u32 = 0x4000_0040;

    fn section(
        name: &str,
        virtual_address: u32,
        virtual_size: u32,
        pointer_to_raw_data: u32,
        size_of_raw_data: u32,
        characteristics: u32,
    ) -> Section {
        Section {
            name: name.to_owned(),
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
            characteristics,
        }
    }

    fn protected_image() -> PeImage {
        PeImage {
            image_base: PREFERRED_BASE,
            entry_point_rva: 0x9050,
            base_of_code: 0x1000,
            size_of_code: 0x1800,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_headers: 0x400,
            size_of_image: 0xc000,
            subsystem: 3,
            sections: vec![
                section("original", 0x1000, 0x1780, 0x400, 0x1000, CODE_XR),
                section("data", 0x3000, 0x600, 0x1400, 0x600, DATA_RW),
                section("bridge", 0x4000, 0x5000, 0x1a00, 0, CODE_RWX),
                section("entry", 0x9000, 0x1800, 0x1a00, 0x1800, CODE_XR),
                section("relocations", 0xb000, 0x100, 0x3200, 0x200, DATA_R),
            ],
        }
    }

    fn observation(mapped_base: u64, kind: TransferKind) -> TransferObservation {
        TransferObservation {
            source_rip: mapped_base + 0x4120,
            target_rip: mapped_base + 0x1040,
            kind,
            target_previously_executed: false,
        }
    }

    #[test]
    fn derives_name_free_layout_and_accepts_indirect_tail_transfer() {
        let image = protected_image();
        let criterion = OepCriterion::new(&image, PREFERRED_BASE).unwrap();
        let layout = criterion.layout();

        assert_eq!(layout.protector_boundary_rva, 0x4000);
        assert_eq!(layout.bridge_section_index, 2);
        assert_eq!(layout.entry_section_index, 3);
        assert_eq!(
            layout.original_executable_sections,
            vec![SectionRegion {
                section_index: 0,
                start_rva: 0x1000,
                end_rva: 0x2780,
            }]
        );
        assert_eq!(
            criterion.evaluate(observation(PREFERRED_BASE, TransferKind::IndirectBranch)),
            Some(OepCandidate {
                rip: PREFERRED_BASE + 0x1040,
                source_rip: PREFERRED_BASE + 0x4120,
                kind: TransferKind::IndirectBranch,
                source_section_index: 2,
                target_section_index: 0,
            })
        );
        assert!(criterion
            .evaluate(observation(PREFERRED_BASE, TransferKind::Return))
            .is_some());
    }

    #[test]
    fn emulator_transfer_kinds_map_without_losing_indirectness() {
        for (emulator, criterion) in [
            (IndirectTransferKind::Branch, TransferKind::IndirectBranch),
            (IndirectTransferKind::Call, TransferKind::IndirectCall),
            (IndirectTransferKind::Return, TransferKind::Return),
        ] {
            assert_eq!(TransferKind::from(emulator), criterion);
        }
    }

    #[test]
    fn real_emulator_observation_reaches_candidate_through_fire_bridge() {
        const SOURCE: u64 = PREFERRED_BASE + 0x4000;
        const TARGET: u64 = PREFERRED_BASE + 0x1000;

        let image = protected_image();
        let criterion = OepCriterion::new(&image, PREFERRED_BASE).unwrap();
        let mut source_bytes = vec![0x48, 0xb8]; // mov rax, TARGET
        source_bytes.extend_from_slice(&TARGET.to_le_bytes());
        source_bytes.extend_from_slice(&[0xff, 0xe0]); // jmp rax

        let mut emu = Emu::new().unwrap();
        emu.map_code(SOURCE, &source_bytes).unwrap();
        emu.map_code(TARGET, &[0x90, 0x0f, 0x0b]).unwrap();
        let layout = criterion.layout();
        let source_ranges = layout
            .loader_executable_sections
            .iter()
            .map(|section| {
                (
                    layout.mapped_base + u64::from(section.start_rva),
                    layout.mapped_base + u64::from(section.end_rva),
                )
            })
            .collect::<Vec<_>>();
        let target_ranges = layout
            .original_executable_sections
            .iter()
            .map(|section| {
                (
                    layout.mapped_base + u64::from(section.start_rva),
                    layout.mapped_base + u64::from(section.end_rva),
                )
            })
            .collect::<Vec<_>>();
        emu.configure_indirect_transfer_watch(&source_ranges, &target_ranges, false)
            .unwrap();

        let report = emu.resume(SOURCE, 16).unwrap();
        assert_eq!(report.stop_reason, StopReason::IndirectTransferObserved);
        let observation = emu.indirect_transfer_observation().unwrap();
        assert_eq!(observation.kind, IndirectTransferKind::Branch);
        assert_eq!(observation.source_rip, SOURCE + 10);
        assert_eq!(observation.target_rip, TARGET);
        assert_eq!(
            criterion.evaluate_indirect_transfer_observation(&observation),
            Some(OepCandidate {
                rip: TARGET,
                source_rip: SOURCE + 10,
                kind: TransferKind::IndirectBranch,
                source_section_index: 2,
                target_section_index: 0,
            })
        );
    }

    #[test]
    fn names_do_not_affect_layout_or_candidate() {
        let original = protected_image();
        let mut renamed = original.clone();
        for (index, section) in renamed.sections.iter_mut().enumerate() {
            section.name = format!("misleading-{index}");
        }

        let original = OepCriterion::new(&original, PREFERRED_BASE).unwrap();
        let renamed = OepCriterion::new(&renamed, PREFERRED_BASE).unwrap();
        assert_eq!(original.layout(), renamed.layout());
        assert_eq!(
            original.evaluate(observation(PREFERRED_BASE, TransferKind::Return)),
            renamed.evaluate(observation(PREFERRED_BASE, TransferKind::Return))
        );
    }

    #[test]
    fn actual_mapped_base_controls_address_classification() {
        let image = protected_image();
        let criterion = OepCriterion::new(&image, REBASED).unwrap();

        assert_eq!(criterion.layout().mapped_base, REBASED);
        assert!(criterion
            .evaluate(observation(REBASED, TransferKind::IndirectBranch))
            .is_some());
        assert!(criterion
            .evaluate(observation(PREFERRED_BASE, TransferKind::IndirectBranch))
            .is_none());
    }

    #[test]
    fn excludes_calls_direct_transfers_and_previously_executed_targets() {
        let image = protected_image();
        let criterion = OepCriterion::new(&image, PREFERRED_BASE).unwrap();

        assert!(criterion
            .evaluate(observation(PREFERRED_BASE, TransferKind::IndirectCall))
            .is_none());
        assert!(criterion
            .evaluate(observation(PREFERRED_BASE, TransferKind::DirectBranch))
            .is_none());
        let mut seen = observation(PREFERRED_BASE, TransferKind::Return);
        seen.target_previously_executed = true;
        assert!(criterion.evaluate(seen).is_none());
    }

    #[test]
    fn requires_loader_source_and_original_executable_target() {
        let image = protected_image();
        let criterion = OepCriterion::new(&image, PREFERRED_BASE).unwrap();

        let mut transfer = observation(PREFERRED_BASE, TransferKind::Return);
        transfer.source_rip = PREFERRED_BASE + 0x1040;
        assert!(criterion.evaluate(transfer).is_none());

        transfer = observation(PREFERRED_BASE, TransferKind::Return);
        transfer.target_rip = PREFERRED_BASE + 0x3010;
        assert!(criterion.evaluate(transfer).is_none());

        transfer.target_rip = 0x0000_7fff_0000_1000;
        assert!(criterion.evaluate(transfer).is_none());
    }

    #[test]
    fn declared_virtual_size_excludes_original_section_padding() {
        let image = protected_image();
        let criterion = OepCriterion::new(&image, PREFERRED_BASE).unwrap();
        let mut transfer = observation(PREFERRED_BASE, TransferKind::Return);

        transfer.target_rip = PREFERRED_BASE + 0x277f;
        assert!(criterion.evaluate(transfer).is_some());
        transfer.target_rip = PREFERRED_BASE + 0x2780;
        assert!(criterion.evaluate(transfer).is_none());
        transfer.target_rip = PREFERRED_BASE + 0x2fff;
        assert!(criterion.evaluate(transfer).is_none());
    }

    #[test]
    fn entry_point_in_alignment_padding_is_rejected() {
        let mut image = protected_image();
        image.entry_point_rva = 0xafff;

        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::EntrySectionMissingOrAmbiguous)
        );
    }

    #[test]
    fn section_table_order_does_not_change_relational_roles() {
        let original = protected_image();
        let mut shuffled = original.clone();
        shuffled.sections.swap(0, 4);
        shuffled.sections.swap(1, 3);

        let layout = OepLayout::derive(&shuffled, PREFERRED_BASE).unwrap();
        assert_eq!(layout.protector_boundary_rva, 0x4000);
        assert_eq!(layout.bridge_section_index, 2);
        assert_eq!(layout.entry_section_index, 1);
        assert_eq!(layout.original_executable_sections[0].section_index, 4);
    }

    #[test]
    fn rejects_mutated_bridge_and_raw_frontier_invariants() {
        let mut image = protected_image();
        image.sections[2].size_of_raw_data = 0x200;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::InvalidBridgeSection)
        );

        let mut image = protected_image();
        image.sections[2].virtual_size = 0x4000;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::BridgeNotAdjacent)
        );

        let mut image = protected_image();
        image.sections[3].pointer_to_raw_data += 0x200;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::RawFrontierMismatch)
        );
    }

    #[test]
    fn rejects_mutated_legacy_code_metadata() {
        let mut image = protected_image();
        image.base_of_code += 0x10;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::BaseOfCodeMismatch)
        );

        let mut image = protected_image();
        image.size_of_code += image.file_alignment;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::SizeOfCodeMismatch)
        );
    }

    #[test]
    fn rejects_ambiguous_rawless_pre_boundary_executable_code() {
        let mut image = protected_image();
        image.sections[2].virtual_address = 0x5000;
        image.sections[2].virtual_size = 0x4000;
        image
            .sections
            .insert(2, section("ambiguous", 0x4000, 0x1000, 0x1a00, 0, CODE_RWX));
        image.size_of_code += 0x1000;

        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::OriginalExecutableNotRawBacked)
        );
    }

    #[test]
    fn rejects_overlapping_sections_and_overflowing_image_base() {
        let mut image = protected_image();
        image.sections[1].virtual_address = 0x2000;
        assert!(matches!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::OverlappingSections { .. })
        ));

        let image = protected_image();
        assert_eq!(
            OepLayout::derive(&image, u64::MAX - 0x1000),
            Err(OepLayoutError::ImageRangeOverflow)
        );
    }

    #[test]
    fn rejects_zero_and_non_power_of_two_alignments() {
        let mut image = protected_image();
        image.section_alignment = 0;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::ZeroAlignment {
                field: "SectionAlignment"
            })
        );

        let mut image = protected_image();
        image.file_alignment = 0x180;
        assert_eq!(
            OepLayout::derive(&image, PREFERRED_BASE),
            Err(OepLayoutError::NonPowerOfTwoAlignment {
                field: "FileAlignment",
                value: 0x180,
            })
        );
    }

    #[test]
    fn derives_the_name_free_layout_for_real_samples_if_present() {
        let samples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples");
        let entries = match fs::read_dir(samples_dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("exe") {
                continue;
            }
            let bytes = fs::read(&path).expect("sample should be readable");
            let image = PeImage::parse(&bytes).expect("sample should parse as PE64");
            let layout = OepLayout::derive(&image, image.image_base)
                .expect("sample should match the name-free protected-image layout");

            assert!(!layout.original_executable_sections.is_empty());
            assert_ne!(layout.bridge_section_index, layout.entry_section_index);
        }
    }
}
