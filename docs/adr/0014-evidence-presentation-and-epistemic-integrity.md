# 0014. Evidence Presentation and Epistemic Integrity

## Status

Accepted

## Context

An interactive diagnostic interface can easily mislead operators if it equates missing measurements with passing checks, displays fabricated completion percentages during adaptive discovery, presents probabilistic LLM hypotheses as verified facts, or renders untrusted web content directly to the terminal without sanitisation.

In accordance with `AGENTS.md` and `docs/conventions.md`, Zwergenleitstand must uphold evidence-first epistemic integrity and strict terminal security boundaries.

## Decision

1. **Strict visual separation between Observations, Findings, and Hypotheses**:
   - **Observations** (Evidence view) are raw or aggregated measurements captured by collectors (`EvidenceSnapshot`), always accompanied by their provenance (`EvidenceSource`, collector status, clock domain, and truncation markers).
   - **Findings** (Findings view) are rule evaluations backed by at least one concrete `EvidenceRef` and tagged with explicit `Severity` and `Confidence`.
   - **Hypotheses** (Investigation view) are candidate explanations proposed by `KommandantZwerg`, explicitly badged with their lifecycle state (`Proposed`, `Supported`/`Confirmed`, `Rejected`/`Refuted`, `Inconclusive`) and never merged into the deterministic Findings table unless verified by a concrete rule or tool measurement.
2. **Explicit representation of incomplete and unavailable evidence**:
   - Every evidence family and measurement renders an explicit status badge (`Captured`, `Partial`, `Failed`, `Skipped`, `Unavailable`, `Unsupported`, `NotApplicable`, `PolicyBlocked`).
   - Unavailable, skipped, or failed measurements are never coerced into `0`, `0 ms`, `100%`, or empty passing tables.
3. **Honest progress and waterfall presentation**:
   - Progress bars with percentages are displayed only when an exact, fixed denominator exists (for example, `18 / 18` rules in a completed analyser or `N / M` pages in a fixed batch).
   - Adaptive crawls and open-ended investigations display explicit counters (`Discovered`, `Inspected`, `Queued`, `Failed`, `Skipped`) and lifecycle badges rather than fabricated percentage gauges.
   - Terminal resource waterfalls render only measured `start_time_ms` and `duration_ms` spans from `BrowserEvidence::resources`; they never invent DNS/TLS/TTFB sub-segments when only total resource duration was captured, and they never merge incompatible clock domains (`BrowserEventTime::Monotonic` vs `BrowserEventTime::Unix`).
4. **Historical comparability enforcement**:
   - Historical diffs in the History view surface `unverified` and `incomparable` counts alongside `new`, `persisted`, `resolved`, and `reintroduced` findings, and preserve explicit `RenderedDiffLimit` reasons when rendered block fingerprints cannot be compared.
5. **Untrusted content sanitisation and redaction (`src/tui/sanitize.rs`)**:
   - All strings originating from target web applications, browser runtime logs, DOM attributes, URLs, headers, or LLM outputs must pass through `sanitize_for_terminal` before rendering.
   - `sanitize_for_terminal` strips ANSI CSI/OSC/DCS escape sequences, C0/C1 control characters (including `\r`, `\x08` backspace, `\x07` bell, `\x1b` escape), and Unicode bidirectional override/isolate controls (`U+202A`..`U+202E`, `U+2066`..`U+2069`, `U+200E`, `U+200F`, `U+061C`), normalises tabs/newlines for single-line table cells, and enforces bounded character length limits.
   - Existing URL query/credential redaction policies remain enforced; rendered content explorer views display SHA-256 `text_fingerprint` values and structural metadata rather than dumping unsanitised raw page prose.

## Consequences

- Operators can trust that every number, chart, and status badge in Zwergenleitstand reflects an actual measurement or an honest limitation.
- Hostile target websites cannot inject terminal escape sequences, spoof bidirectional text, manipulate the terminal title/clipboard, or freeze rendering with multi-megabyte strings.
