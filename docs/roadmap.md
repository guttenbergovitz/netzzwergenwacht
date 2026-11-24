# Operation Aufrüstung — Diagnostic Roadmap

> Strategic goal: Equip Die Zwergenbrigade with broad, deterministic, evidence-first web diagnostics (70% diagnostics & collectors, 20% tests & differential validation, 10% agentic integration).

## Phase A: Upstream Verification & Inventories (Complete)
- Pinned upstream reference: `squirrelscan` `v0.0.191-beta.1` (`640f9b36afc467f83ab9ebf5890bf4ac8ae6bdaf`, MIT).
- Machine-extracted inventories: `upstream-rule-inventory.json` (360 rules), `nzw-rule-inventory.json` (36 rules), `diagnostic-capability-mapping.json`.

## Phase B: Observation Model Foundation (Slice 1 — Complete)
- Enriched `DocumentObservations` (`LinkObs`, `HreflangObs`, `json_ld_blocks`, `SocialMetaObs`, `ScriptObs`, `StylesheetObs`, `FormObs`, `ImageObs` dimensions, `viewport_meta`, `charset_declared`, `has_skip_link`, `has_favicon`, `visible_text_sample`) and `HttpEvidence` header helpers.

## Phase C: High-Value Deterministic Rule Families (In Progress)
- **Slice 2 (`SuchZwerg` + `InhaltsZwerg`):** `H1` uniqueness, `hreflang`, JSON-LD validation, OpenGraph/Twitter Card, `X-Robots-Tag`, placeholders, text-to-HTML ratio, legal/trust links.
- **Slice 3 (`SicherheitsZwerg` + `NetzZwerg`):** `Set-Cookie` flags, mixed content, SRI, permissive CORS, `security.txt`, CSP directive hardening, `robots.txt`/`sitemap.xml` diagnostics.
- **Slice 4 (`LeistungsZwerg` + `GestaltungsZwerg` + `StrukturZwerg`):** Render-blocking assets, image `width`/`height`, `<meta name="viewport">`, charset/doctype, skip-link checks.

## Phase D: Application-Level Graph Diagnostics
- Cross-page duplicate titles/descriptions, canonical graph, `hreflang` reciprocity, orphan pages, broken internal link checks.

## Phase E: Optional External Adapters & Differential Validation
- Optional bounded `adapters::squirrelscan` (`squirrel audit -f json`) + Zwergenprüfstand differential test suite.

## Phase F: CLI & Rig Integration
- Rich terminal presentation (`nzw check` / `nzw investigate`) and typed specialist observation queries over the expanded deterministic engine.
