# 0002. Zwergenbrigade Domains, Shared Document Observations, and Evidence Levels

## Status

Accepted

## Context

In the initial Phase 1 prototype, HTML metadata checks were placed under SEO while semantic HTML structure and source-level accessibility had no dedicated home, and network reliability was conflated with browser runtime (`WebBrowserZwerg`). Additionally, parsing HTML independently per analyser wastes work and encourages duplicate findings across domains.

## Decision

1. **Separate Semantic Document Analysis, Accessibility, and SEO**:
   - `StrukturZwerg` (`analysis::semantics`) owns HTML5 document structure, heading hierarchy, landmarks, duplicate IDs, and native interactive semantics.
   - `ZugänglichkeitsZwerg` (`analysis::accessibility`) owns source-level accessibility checks (`<html lang>`, `img[alt]`, form labels, ARIA references, accessible names) and explicitly marks Rendered/Behavioural checks as unavailable until Phase 2.
   - `SuchZwerg` (`analysis::seo`) focuses on search metadata (`<title>`, meta description, canonical, robots/noindex) without duplicating heading-hierarchy rules.
   - `NetzZwerg` (`analysis::network`) owns HTTP/DNS/redirect reliability, distinct from `BrowserZwerg` (Phase 2 browser runtime).
2. **Shared Document Observation Model**:
   - Parse complete HTML responses once into `DocumentObservations` (`analysis::document`) consumed by `StrukturZwerg`, `ZugänglichkeitsZwerg`, and `SuchZwerg`.
   - Truncated responses (`body_truncated == true`) skip full-document checks to prevent false absence findings.
3. **Three Evidence Capability Levels**:
   - Formalise `EvidenceLevel::Source` (Level 1), `EvidenceLevel::Rendered` (Level 2), and `EvidenceLevel::Behavioural` (Level 3) across findings and check statuses.
4. **Language & Registry Boundary**:
   - Technical identifiers, modules, and prose use British English (`en-GB`, ASCII identifiers); German (`de-DE`) dwarf display names and character metadata live in a central typed registry (`src/brigade.rs`), separated from analytical logic.

## Consequences

- **Easier**: Clear rule ownership without duplicate findings; single HTML parse pass; honest reporting when rendered or behavioural evidence is absent.
- **Harder**: Cross-domain insights (e.g. SEO interpretation of heading structure) must reference shared observations or findings rather than re-implementing checks.
- **Trade-offs**: Maintaining a central `ZWERGENBRIGADE` registry requires updating it whenever a new Zwerg domain is introduced.
