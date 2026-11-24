# Evidence Model

> **Status**: Level 1 (Source) implemented; Level 2–3 and JSONL persistence planned.

The **Evidence Model** guarantees that every claim in an audit report is traceable, reproducible, and honest about uncertainty.

## 1. Evidence Capability Levels

1. **Level 1 (`EvidenceLevel::Source`)**: HTTP responses, headers, redirect chains, and HTML5-parsed source document observations without JavaScript execution. *(Implemented)*
2. **Level 2 (`EvidenceLevel::Rendered`)**: Browser-rendered DOM, computed styles, accessibility tree, browser performance entries, layout, and screenshots. *(Phase 2)*
3. **Level 3 (`EvidenceLevel::Behavioural`)**: Controlled browser interaction, keyboard navigation, focus management, and dynamic state changes. *(Phase 2+)*

If a rule's required evidence level is absent, incomplete, or truncated, it emits `CheckStatus::Skipped` or `CheckStatus::Unavailable` rather than silently downgrading to an unreliable heuristic.

## 2. Epistemic Distinctions

NZW explicitly separates:
- **Observed Facts** (`HttpEvidence`, `DocumentObservations`)
- **Measured Metrics** (`Measurement<T>` with typed `MeasurementUnit`)
- **Deterministic Findings** (`FindingKind::Deterministic`)
- **Heuristic Findings** (`FindingKind::Heuristic`, e.g. container ratio, title length)
- **Inferred Relationships** (`FindingKind::Inferred`)
- **AI-Generated Interpretations** (`FindingKind::AiInterpretation`, Phase 4)
- **Unknown / Unverified Conditions** (`Unavailable`, `Failed`, `Skipped`)

## 3. `EvidenceSnapshot` & Integrity

Each `EvidenceSnapshot` records `target`, `captured_at_unix_secs`, and `http: CollectorOutcome<HttpEvidence>`. Every `Finding` includes non-empty `evidence_refs: Vec<EvidenceRef>` referencing a typed `EvidenceSource`.
