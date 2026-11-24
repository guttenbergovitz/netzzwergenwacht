# Evidence Model

> **Status**: Target Design (Phase 1 core snapshot; Phase 3 persistence).

The **Evidence Model** guarantees that every claim in an audit report is traceable, reproducible, and honest about uncertainty.

## 1. Epistemic Distinctions

NZW explicitly separates:

1. **Observed Facts**: Raw immutable captures (e.g. HTTP status `200`, header `strict-transport-security` absent, TLS cert `not_after`).
2. **Measured Metrics**: Typed numeric quantities with units and provenance (`Measurement<T>`, e.g. `1420 ms`, `48.2 KiB`).
3. **Deterministic Findings**: Exact rule evaluations over facts/metrics (`FindingKind::Deterministic`).
4. **Heuristic Findings**: Threshold or pattern indicators with documented assumptions (`FindingKind::Heuristic`).
5. **Inferred Relationships**: Cross-domain correlations (`FindingKind::Inferred`).
6. **AI-Generated Interpretations**: Optional LLM synthesis (`FindingKind::AiInterpretation`).
7. **Recommendations**: Actionable remediation steps attached to findings or synthesis.
8. **Unknown / Unverified Conditions**: Explicit `Unavailable`, `Failed`, or `Skipped` states.

## 2. `EvidenceSnapshot` & Provenance

Each `EvidenceSnapshot` records:
- `snapshot_id` & `captured_at` (UTC)
- `target`: canonical `AuditTarget`
- `http`: HTTP response, headers, redirect chain, bounded body digest/excerpt
- `tls`: `rustls` handshake & certificate metadata
- `browser`: rendered DOM summary, console/network events, screenshot paths (Phase 2)
- `external_tools`: adapter name, tool version, execution status, raw output reference (Phase 2)

Every `Finding` includes `evidence_refs: Vec<EvidenceRef>` pointing to the exact snapshot artifact or external tool record that produced it.

## 3. Finding Fingerprints (Phase 3)

Each finding computes a deterministic `FindingFingerprint` (hash of `target_host`, `rule_id`, and normalised `location`/subject) to enable stable cross-run regression diffing (`New`, `Persisting`, `Resolved`).
