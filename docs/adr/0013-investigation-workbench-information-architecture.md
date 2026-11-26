# 0013. Investigation Workbench Information Architecture

## Status

Accepted

## Context

NetzZwergenWacht serves both interactive single-target troubleshooting and multi-page/historical quality analysis. Operators need to move fluidly from high-level execution status ("What is the brigade doing right now?") to remediation priorities ("Which high-severity findings exist?") to raw empirical verification ("What exact HTTP header, DOM block, or timeline event caused this?") without being overwhelmed by every observation at once.

## Decision

1. **Organise Zwergenleitstand around nine logical workbench views plus a Launcher and Help overlay**:
   - **Launcher** (initial setup modal/screen when started without an active run or loaded report): Target URL input, execution mode selection (`Deterministic Check`, `Agentic Investigation`, `Autonomous Patrol`, `Open Report`, `Open History`), profile selection, runtime instrument availability check (`Chromium`, `axe-core`, `Lighthouse`, `Agent Provider`), and effective budget preview.
   - **1. Overview (`1`)**: Real-time operational dashboard showing run lifecycle, elapsed time, target & profile, application surface counters (discovered, inspected, queued, failed, skipped), findings by severity, active brigade status, current investigation focus, and recent activity feed.
   - **2. Brigade (`2`)**: Registry-driven view of all 11 specialists from `src/brigade.rs` (`ZWERGENBRIGADE`), showing per-dwarf lifecycle status, deterministic vs agentic mode, checks evaluated/passed/failed/skipped/inconclusive, findings count, required vs available evidence levels, and recent specialist events.
   - **3. Targets (`3`)**: Master-detail inventory of discovered and inspected pages, showing discovery source, crawl depth, locale, template classification, HTTP status, inspection state, evidence levels, and per-page findings.
   - **4. Findings (`4`)**: Filterable, deterministically sortable master-detail table of diagnostic findings (severity, confidence, domain, rule ID, target, title, historical status) with a detail pane exposing explanation, impact, remediation, and clickable/navigable `EvidenceRef` links.
   - **5. Evidence (`5`)**: Zero-acquisition evidence explorer powered by `&EvidenceSnapshot` and `src/investigation/evidence_query.rs`, divided into sub-tabs:
     - *Summary & HTTP/TLS* (headers, redirects, TLS certificate & chain, source segmentation),
     - *Network & Timeline* (`BrowserTimeline` events, status/origin/failure filters, and terminal resource waterfall from measured start times and durations),
     - *Performance* (Core Web Vitals, navigation timing, top CPU consumers, JS/CSS coverage, resource transfer breakdown),
     - *Rendered Content & Runtime* (paginated `RenderedBlockSummary` with SHA-256 text fingerprints, runtime console/uncaught errors, accessibility tree summary).
   - **6. Investigation (`6`)**: Agentic reasoning workbench displaying `KommandantZwerg` objective, specialist contributions, hypothesis inventory (`Proposed`, `Confirmed`/`Supported`, `Refuted`/`Rejected`, `Inconclusive`), tool invocations, and cited evidence references.
   - **7. Topology (`7`)**: Navigable tree and neighbourhood explorer over `ApplicationGraph` (`src/analysis/graph.rs`) and page resource dependencies, using bounded depth and explicit cycle detection.
   - **8. History (`8`)**: Saved run inventory and regression comparison (`diff_reports`, `diff_history`, and offline `RenderedTextDiff` block fingerprint comparison) with comparability checks.
   - **9. System (`9`)**: Execution budget consumption, elapsed vs deadline, HTTP/browser counters, event queue health (including dropped/coalesced progress event counters), instrument availability, and LLM token/request counters.
2. **Cross-view deep linking**:
   - Selecting a finding and pressing `Enter` on an `EvidenceRef` jumps directly to the Evidence view focused on the referenced observation family (e.g. `timeline-event=N`, `rendered-block=N`, HTTP header, or resource).
   - Selecting a dwarf in the Brigade view allows filtering Findings by that dwarf's domain.
   - Selecting a target in the Targets view filters Findings and Evidence to that target page.
3. **Responsive layout tiers**:
   - **Wide (`>= 120` cols)**: Full navigation bar, multi-column dashboard cards, side-by-side master-detail panes.
   - **Standard (`90..119` cols)**: Compact navigation tabs, two-pane master-detail with condensed table columns.
   - **Narrow (`80..89` cols)**: Single-pane stacked master/detail toggle, abbreviated tab labels.
   - **Below minimum (`< 80` cols or `< 20` rows)**: Non-panicking fallback prompt instructing the operator to resize the terminal.

## Consequences

- Operators follow a consistent progressive-disclosure workflow: Overview -> Brigade/Targets -> Findings -> Evidence -> History/Topology.
- Narrow terminals remain functional and safe without layout panics.
- Views bind directly to existing domain and query structures without duplicating analytical logic.
