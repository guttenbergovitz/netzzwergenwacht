# Shared Document Analysis (`analysis::document`)

> **Status**: Implemented (Level 1 Source Analysis).

To avoid parsing HTML independently across `StrukturZwerg`, `ZugänglichkeitsZwerg`, and `SuchZwerg`, `analysis::run_all` parses complete HTML responses **once** into `DocumentObservations` (`src/analysis/document.rs`).

## 1. Extracted Observations

- **Document Metadata**: `<title>`, `<html lang>`, `<meta name="description">`, `<meta name="robots">`, `<link rel="canonical">`, `hreflang` links, JSON-LD blocks.
- **Structure & Landmarks**: Ordered `<h1>`–`<h6>` headings, `<main>`/`<nav>`/`<header>`/`<footer>` counts, element `id` set and sorted `duplicate_ids`, `<div>`/`<span>`/total element counts.
- **Accessibility & Interactive Signals**: `<img>` `src`/`alt`, `<label for>` IDs, form controls (`<input>`, `<select>`, `<textarea>` excluding hidden/button types), `<a>` without `href`, empty links/buttons lacking accessible names, clickable `<div>`/`<span>` without `role`, nested interactive elements, and `aria-labelledby`/`aria-describedby` references.

## 2. Rule Ownership & Caveats

- `StrukturZwerg` owns heading hierarchy, duplicate IDs, landmarks, and native interactive semantics.
- `ZugänglichkeitsZwerg` owns language declaration, `img[alt]`, form labelling, broken ARIA references, and accessible names.
- `SuchZwerg` owns search metadata (`<title>`, meta description, canonical, robots).
- **HTML5 Parser Caveat**: `scraper` uses an HTML5-compliant parser (`html5ever`) that repairs malformed markup; Level 1 checks observe the repaired DOM tree and do not claim to validate original raw HTML syntax.
- **Truncation Guardrail**: When `HttpEvidence::body_truncated` is `true`, `DocumentObservations` is not constructed and full-document rules emit `CheckStatus::Skipped`.
