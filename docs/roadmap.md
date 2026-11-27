# NetzZwergenWacht Roadmap

Current state on `develop`: **235 registered diagnostic rules** across **Die Zwergenbrigade** and `ApplicationGraph`, the **Zwergenleitstand** Ratatui investigation workbench (`nzw tui`) with 19 Evidence categories, and **21 offline Evidence Query Engine** tools over a retained `EvidenceSnapshot`.

No capability in this repository has been empirically validated against real applications yet. Empirical evaluation, comparative benchmarking, and product effectiveness studies belong to a separate operation and are explicitly out of scope here.

## Completed under Operation Zwergenleitstand (Waves ZL-0 – ZL-8)

- **Architecture & ADRs (`0010`–`0015`)**: Ratatui + Crossterm local-first presentation architecture, bounded `DiagnosticEvent` transport (`capacity = 256`, non-blocking progress coalescing, observable event loss), unidirectional TEA/Elm state reducer (`src/tui/`), nine-view information architecture, epistemic integrity & ANSI/OSC/BiDi terminal sanitisation, and semantic themes (`StandardDark`, `HighContrast`, `Monochrome`, `--ascii`).
- **Live & Offline Investigation Workbench (`nzw tui`, `--tui`)**: Interactive launcher with runtime instrument detection (`Chromium`, `axe-core`, `Lighthouse`, LLM provider), live streaming of deterministic checks, agentic investigations, and autonomous patrols, offline `--report` and `--history` exploration, finding-to-evidence drill-down (`Enter`), network timeline & resource waterfall views, and JSON report export (`w`). Patrol runs share the CLI memory directory.

## Completed under Operation Aufrüstung I–III

- **Browser Sensory Foundation (Wave A)**: CDP network waterfall + initiator provenance, categorised runtime errors (`uncaught_exception`, `unhandled_rejection`, `csp_violation`, `console_error`), explicit truncation flags (`resources_truncated`, `rendered_images_truncated`), and `QueryBrowserEvidenceTool`.
- **Accessibility Tree & Performance Depth (Wave B)**: `Accessibility.getFullAXTree` summary (`a11y.ax.*`), `PerformanceObserver` navigation/LCP/CLS/Long-Task telemetry, and RFC-compliant `Cache-Control` directive parsing.
- **Surface Security & Privacy (Wave C / J)**: Native CSP directive parser, `__Host-`/`__Secure-` cookie prefix validation, `Max-Age` cap checks, URL query-parameter secret redaction (`redacted_url`), and fresh-session privacy storage/tracking observations (`sec.privacy.*`).
- **Statistical Intelligence & Resource Graph (Wave E/G)**: `analysis::stats` (`DistributionSummary`, Tukey IQR outliers), `CalculateDistributionTool`, `ResourceGraph` shared-dependency and concentration rules, and crawl-trap detection.
- **Layout Geometry, Media & Content Integrity (Wave D/F/H/I)**: Offscreen controls, oversized sticky headers, pixelated images, caption tracks, suspicious alt text, ambiguous links, i18n key leakage, placeholder contacts, HTTPS downgrade redirects, ETag validation, and `Zwergenprüfstand` clean-control verification.

## Operation Aufrüstung IV — implementation status

Rule-count expansion remains frozen at **235 rules** while sensory depth, element-level evidence, and the **Evidence Query Engine** were completed and then hardened under **Operation Aufrüstung IV — Evidence Integrity** (ADRs `0016`–`0021`).

### Status vocabulary

| Status | Meaning |
| --- | --- |
| Model implemented | Domain representation exists and is serialised |
| Producer implemented | The collector actually observes the data |
| Query implemented | An offline `EvidenceSnapshot` query exists |
| Agent integration implemented | `KommandantZwerg` can request the evidence and must cite it |
| TUI integration implemented | The operator can inspect the evidence in `Zwergenleitstand` |
| Regression tested | Automated contract coverage exists |
| Empirically validated | Practical validity established against real applications — **not attempted** |

### Observation families

| Capability | Model | Producer | Offline query | Agent tool | TUI | Regression coverage |
| --- | --- | --- | --- | --- | --- | --- |
| Browser runtime & network timeline | Yes | Yes | `query_browser_timeline_filtered`, `query_request_chains`, `query_failed_dependencies` | Yes | Yes | Live Chromium (`tests/browser_timeline.rs`) |
| Rendered DOM segmentation & fingerprints | Yes | Yes | `query_rendered_content`, `nzw diff` | Yes | Yes | Unit + offline suite |
| Source versus rendered comparison | Yes | Yes | `compare_source_and_rendered` | Yes | Yes | Offline suite |
| Interactive element inventory | Yes | Yes | `query_interactive_elements` | Yes | Yes | Live Chromium |
| Application state | Yes | Yes | `query_application_state` | Yes | Yes | Live Chromium |
| Interaction trace (restricted behavioural probe) | Yes | Yes | `query_interaction_trace` | Yes | Yes | Live Chromium |
| Visual geometry | Yes | Yes | `query_element_geometry` | Yes | Yes | Live Chromium |
| Accessibility node inventory | Yes | Yes | `query_accessibility_nodes` | Yes | Yes | Live Chromium |
| Cookie & browser storage | Yes | Yes | `query_storage_and_cookies` | Yes | Yes | Live Chromium |
| Third-party origins | Yes | Yes | `query_third_party_origins` | Yes | Yes | Live Chromium |
| Security posture & challenge evidence | Yes | Yes | `query_security_posture`, `query_security_challenge` | Yes | Yes | Live Chromium |
| Performance attribution (LCP/CLS/render-blocking) | Yes | Yes | `query_performance_attribution` | Yes | Yes | Live Chromium |
| Media & font inventory | Yes | Yes | `query_media_and_fonts` | Yes | Yes | Live Chromium |
| Indexability & structured data | Yes | Yes | `query_indexability_authority`, `query_structured_data` | Yes | Yes | Live Chromium |
| Responsive comparison | Yes | Yes | `query_responsive_comparison` | Yes | Yes | Live Chromium |
| Link graph & form endpoints | Yes | Yes | `query_link_graph` | Yes | Yes | Live Chromium |
| Visual artefacts (screenshot digest, retained-rect coverage) | Yes | Yes | `query_visual_artifacts` | Yes | Yes | Live Chromium |
| Service worker lifecycle | Yes | Yes | `query_service_worker_lifecycle` | Yes | Yes | Live Chromium |
| TLS & direct CAA records | Yes | Yes (CAA only when a resolver is configured) | `query_tls_and_caa` | Yes | Yes | Unit (outcome taxonomy) + CLI smoke |
| Patrol index catalogue | Yes | Yes | `query_catalog_targets`, `query_catalog_anomalies`, `query_catalog_stale_pages`, `query_catalog_runs` | No (offline/TUI only) | Yes | Offline suite |

### Measurement honesty rules applied to these observations

- Missing evidence is `None`, `CollectorOutcome::Skipped`/`Failed`, or `EvidenceQueryStatus::Unavailable`; it is never rendered as `0`, `false`, or an empty inventory.
- CLS is the largest observed session window; LCP timing comes only from a measured `largest-contentful-paint` entry, and a DOM-geometry candidate is labelled `dom_geometry_heuristic` without inheriting measured timing.
- Render-blocking attribution separates confirmed, potential, and unknown resources; it never sums every script and stylesheet.
- Interaction steps record bounded observation windows and state changes; they describe requests and errors observed during the window, never causal effects.
- Visual coverage is `above_fold_retained_element_coverage_milli`: a geometric estimate over retained element rectangles, not pixel coverage.

### Deferred capabilities

The following are **not implemented**. They remain candidates for a later operation and must not be described as available:

- Request initiator top stack frame, queueing/download phase split, WebSocket/SSE/frame lifecycle, SPA route transitions.
- CMP identity, multi-scenario consent matrix (`fresh`, `reject_all`, `accept_all`, `withdrawal`), vendor tracking classification.
- Event Timing/INP, Long Animation Frames, main-thread trace breakdown, JS heap/DOM growth, cold/warm cache comparison, repeated-run distributions.
- CSS rule/design-token inventory; bounded media binary inspection (EXIF, perceptual hashes, SVG complexity); PDF/document intelligence.
- Multi-engine browser compatibility; field performance telemetry (CrUX/RUM).
- Historical queries (`compare_observations`, `query_historical_evidence`, `find_similar_pages`, `find_similar_components`, `request_additional_measurement`).
- Full certificate chain, OCSP/CT verification, negotiated TLS version/cipher from the browser, `testssl.sh` adapter, per-agent `robots.txt` modelling.

## Next Horizons

1. **Empirical validation**: real application audits, comparative analysis against Lighthouse/axe-core, and effectiveness studies — a separate operation, deliberately not started here.
2. **External Instrument Integrations**: optional `testssl.sh` TLS protocol/cipher enumeration and Nu HTML Checker (`vnu`) conformance adapter behind `CollectorOutcome`.
3. **Interaction safety depth**: network-restricted behavioural probes with explicit authorisation policies, plus multi-state consent observation.
4. **Historical evidence**: longitudinal comparison across observation families with explicit compatibility rules for differing coverage and fingerprint contracts.

## Phase II: External Technical Quality Assurance

Phase II transitions NetzZwergenWacht from an evidence-rich diagnostic prototype into an independent, defensible black-box technical QA system. See [phase-2-external-technical-qa.md](file:///Users/krzys/github.com/guttenbergovitz/netzzwergenwacht/docs/product/phase-2-external-technical-qa.md) for the full specification.

- **P0 — Stabilisation and credibility**: Chromium CI launch stability, live browser test reliability, unified `EvidenceStore` persistence, rule verification, empirical validation baseline, unified multi-dimensional quality assessment (`compute_release_readiness` + `evaluate_policy`), and explicit coverage/`INSUFFICIENT EVIDENCE` semantics.
- **P1 — Genuine black-box QA**: Controlled interaction engine, functional assertions, user journey testing, Application Quality Profiles, persistent finding lifecycle, visual regression, cross-run evidence comparison, and extended runtime/accessibility analysis.
- **P2 — Diagnostic depth**: Repeated performance distributions, multi-state privacy/consent scenarios, advanced multilingual assessment, cross-browser assessment, systemic defect clustering, and dependency failure attribution.
- **P3 — Continuous technical assurance**: Release-aware baselines, scheduled execution, portfolio-level assessment, synthetic monitoring, regression alerts, longitudinal quality trends, and exportable evidence packages.
