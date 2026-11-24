# ADR 0006: Browser Isolation, Origin Scope, and Regression Semantics

- **Status**: Accepted
- **Date**: 2026-11-24

## Context

Slice A ("Trustworthy execution") identified three foundational gaps:
1. `lighthouse` and `browser` adapters passed `--no-sandbox` unconditionally.
2. Discovery and tool authorisation checked `host()` rather than complete `(scheme, host, port)` origin.
3. Fingerprints included volatile evidence `detail` prose (such as latency in milliseconds), and `diff_reports` lacked `NotComparable` / `Changed` semantics.

## Decision

1. **Browser Sandboxing by Default**:
   - Chromium and Lighthouse adapters run with Chromium sandboxing enabled by default. `--no-sandbox` is only passed when `NZW_ALLOW_UNSAFE_BROWSER_SANDBOX=1` is explicitly set. If an environment lacks OS sandbox support, the adapter fails explicitly rather than silently weakening isolation.
2. **Typed `Origin` and `InvestigationScope`**:
   - `src/domain.rs` defines `Origin { scheme, host, port }` and `InvestigationScope`. Both `discover_same_origin_links` and `PortableTool` authorisation validate complete origins, blocking cross-scheme downgrades and alternate ports.
3. **Stable Page-Level Fingerprints & Comparable Regression Diffs**:
   - `populate_fingerprints` hashes `(page_scope, rule_id)` without volatile latency/count details.
   - `diff_reports` refuses cross-target resolution claims (`not_comparable_reason` + `unverified_findings`), tracks `changed_findings`, and keeps `unverified_findings` separate from `resolved_findings`.
