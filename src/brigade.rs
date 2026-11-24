//! Central typed registry of **Die Zwergenbrigade**.
//!
//! Keeps presentation metadata (German display names, character descriptions,
//! and motto) cleanly separated from analytical logic.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::EvidenceLevel;

/// Project motto for Die Zwergenbrigade.
pub const MOTTO: &str = "Kleine Zwerge. Große Sorgfalt.";

/// Stable ASCII machine-readable identifier for each dwarf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DwarfId {
    /// `NetzZwerg` — HTTP, DNS, connectivity, redirects, and endpoint reliability.
    Netz,
    /// `SicherheitsZwerg` — TLS, security headers, cookies, and security posture.
    Sicherheits,
    /// `LeistungsZwerg` — performance, latency, resource efficiency, and Core Web Vitals.
    Leistungs,
    /// `StrukturZwerg` — semantic HTML, document structure, and structural integrity.
    Struktur,
    /// `ZugänglichkeitsZwerg` — accessibility, WCAG, ARIA, and inclusive interaction.
    Zugaenglichkeits,
    /// `SuchZwerg` — SEO, metadata, indexability, and search visibility.
    Such,
    /// `InhaltsZwerg` — content quality, readability, and language.
    Inhalts,
    /// `GestaltungsZwerg` — visual integrity, responsive layouts, and presentation.
    Gestaltungs,
    /// `BrowserZwerg` — browser runtime, JavaScript, console, and network failures.
    Browser,
    /// `DokumentationsZwerg` — report generation and evidence presentation.
    Dokumentations,
    /// `KommandantZwerg` — optional AI-assisted correlation and diagnostic planning.
    Kommandant,
}

/// Functional layer to which a dwarf belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DwarfRole {
    /// Acquires external evidence.
    Collector,
    /// Evaluates deterministic/heuristic rules over an `EvidenceSnapshot`.
    DeterministicAnalyser,
    /// Formats and persists audit reports.
    Reporting,
    /// Optional post-analysis AI synthesis.
    OptionalIntelligence,
}

/// Current implementation maturity of a dwarf in the Rust rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    /// Implemented in the current Rust core.
    Implemented,
    /// Planned for a subsequent phase.
    Planned,
}

/// Static metadata entry describing a dwarf's identity and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DwarfProfile {
    /// Stable machine-readable identifier.
    pub id: DwarfId,
    /// German display name (may contain umlauts).
    pub display_name: &'static str,
    /// British English technical responsibility summary.
    pub responsibility: &'static str,
    /// Architectural role.
    pub role: DwarfRole,
    /// Presentation character tagline.
    pub character: &'static str,
    /// Minimum evidence capability level required for full operation.
    pub required_evidence: EvidenceLevel,
    /// Current implementation status.
    pub status: ImplementationStatus,
}

/// Central registry of all eleven members of Die Zwergenbrigade.
pub const ZWERGENBRIGADE: &[DwarfProfile] = &[
    DwarfProfile {
        id: DwarfId::Netz,
        display_name: "NetzZwerg",
        responsibility: "HTTP, DNS, connectivity, redirects, and endpoint reliability",
        role: DwarfRole::DeterministicAnalyser,
        character: "The relentless network inspector",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Sicherheits,
        display_name: "SicherheitsZwerg",
        responsibility: "TLS, security headers, cookies, and security posture",
        role: DwarfRole::DeterministicAnalyser,
        character: "The suspicious sentinel",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Leistungs,
        display_name: "LeistungsZwerg",
        responsibility: "Performance, latency, resource efficiency, and Core Web Vitals",
        role: DwarfRole::DeterministicAnalyser,
        character: "The obsessive clockmaker",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Struktur,
        display_name: "StrukturZwerg",
        responsibility: "Semantic HTML, document structure, and structural integrity",
        role: DwarfRole::DeterministicAnalyser,
        character: "The meticulous architect",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Zugaenglichkeits,
        display_name: "ZugänglichkeitsZwerg",
        responsibility: "Accessibility, WCAG, ARIA, and inclusive interaction",
        role: DwarfRole::DeterministicAnalyser,
        character: "The conscientious accessibility inspector",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Such,
        display_name: "SuchZwerg",
        responsibility: "SEO, metadata, indexability, and search visibility",
        role: DwarfRole::DeterministicAnalyser,
        character: "The fastidious librarian",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Inhalts,
        display_name: "InhaltsZwerg",
        responsibility: "Content quality, readability, and language",
        role: DwarfRole::DeterministicAnalyser,
        character: "The grumpy editor",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Gestaltungs,
        display_name: "GestaltungsZwerg",
        responsibility: "Visual integrity, responsive layouts, and presentation",
        role: DwarfRole::DeterministicAnalyser,
        character: "The perpetually dissatisfied designer",
        required_evidence: EvidenceLevel::Rendered,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Browser,
        display_name: "BrowserZwerg",
        responsibility: "Browser runtime, JavaScript, console, and network failures",
        role: DwarfRole::DeterministicAnalyser,
        character: "The experimental mechanic",
        required_evidence: EvidenceLevel::Rendered,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Dokumentations,
        display_name: "DokumentationsZwerg",
        responsibility: "Report generation and evidence presentation",
        role: DwarfRole::Reporting,
        character: "The devoted archivist",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
    DwarfProfile {
        id: DwarfId::Kommandant,
        display_name: "KommandantZwerg",
        responsibility: "Optional AI-assisted correlation, interpretation, and diagnostic planning",
        role: DwarfRole::OptionalIntelligence,
        character: "The brigade commander",
        required_evidence: EvidenceLevel::Source,
        status: ImplementationStatus::Implemented,
    },
];

/// Looks up a dwarf profile by its stable [`DwarfId`].
#[must_use]
pub fn profile(id: DwarfId) -> &'static DwarfProfile {
    match id {
        DwarfId::Netz => &ZWERGENBRIGADE[0],
        DwarfId::Sicherheits => &ZWERGENBRIGADE[1],
        DwarfId::Leistungs => &ZWERGENBRIGADE[2],
        DwarfId::Struktur => &ZWERGENBRIGADE[3],
        DwarfId::Zugaenglichkeits => &ZWERGENBRIGADE[4],
        DwarfId::Such => &ZWERGENBRIGADE[5],
        DwarfId::Inhalts => &ZWERGENBRIGADE[6],
        DwarfId::Gestaltungs => &ZWERGENBRIGADE[7],
        DwarfId::Browser => &ZWERGENBRIGADE[8],
        DwarfId::Dokumentations => &ZWERGENBRIGADE[9],
        DwarfId::Kommandant => &ZWERGENBRIGADE[10],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn registry_has_eleven_unique_dwarfs() {
        assert_eq!(ZWERGENBRIGADE.len(), 11);
        let ids: HashSet<DwarfId> = ZWERGENBRIGADE.iter().map(|d| d.id).collect();
        assert_eq!(ids.len(), 11);
        for d in ZWERGENBRIGADE {
            assert_eq!(profile(d.id).id, d.id);
        }
    }
}
