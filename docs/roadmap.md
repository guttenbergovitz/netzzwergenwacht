# NetzZwergenWacht Roadmap

Current state on `develop`: **235 registered diagnostic rules** across **Die Zwergenbrigade** and `ApplicationGraph`, with **250+ passing tests**, the **Zwergenleitstand** Ratatui investigation workbench (`nzw tui`) with 19 Evidence categories, and full **Operation Aufrüstung IV** sensory inventories and **21 offline Evidence Query Engine** tools.

## Completed under Operation Zwergenleitstand (Waves ZL-0 – ZL-8)

- **Architecture & ADRs (`0010`–`0015`)**: Ratatui + Crossterm local-first presentation architecture, bounded `DiagnosticEvent` transport (`capacity = 256`, non-blocking progress coalescing), unidirectional TEA/Elm state reducer (`src/tui/`), nine-view information architecture, epistemic integrity & ANSI/OSC/BiDi terminal sanitisation, and semantic themes (`StandardDark`, `HighContrast`, `Monochrome`, `--ascii`).
- **Live & Offline Investigation Workbench (`nzw tui`, `--tui`)**: Interactive launcher with runtime instrument detection (`Chromium`, `axe-core`, `Lighthouse`, LLM provider), live streaming of deterministic checks, agentic investigations, and autonomous patrols, offline `--report` and `--history` exploration, finding-to-evidence drill-down (`Enter`), network timeline & resource waterfall views, and JSON report export (`w`).

## Completed under Operation Aufrüstung I–III

- **Browser Sensory Foundation (Wave A)**: CDP network waterfall + initiator provenance, categorised runtime errors (`uncaught_exception`, `unhandled_rejection`, `csp_violation`, `console_error`), explicit truncation flags (`resources_truncated`, `rendered_images_truncated`), and `QueryBrowserEvidenceTool`.
- **Accessibility Tree & Performance Depth (Wave B)**: `Accessibility.getFullAXTree` summary (`a11y.ax.*`), `PerformanceObserver` navigation/LCP/CLS/Long-Task telemetry, and RFC-compliant `Cache-Control` directive parsing.
- **Surface Security & Privacy (Wave C / J)**: Native CSP directive parser, `__Host-`/`__Secure-` cookie prefix validation, `Max-Age` cap checks, URL query-parameter secret redaction (`redacted_url`), and fresh-session privacy storage/tracking observations (`sec.privacy.*`).
- **Statistical Intelligence & Resource Graph (Wave E/G)**: `analysis::stats` (`DistributionSummary`, Tukey IQR outliers), `CalculateDistributionTool`, `ResourceGraph` shared-dependency and concentration rules, and crawl-trap detection.
- **Layout Geometry, Media & Content Integrity (Wave D/F/H/I)**: Offscreen controls, oversized sticky headers, pixelated images, caption tracks, suspicious alt text, ambiguous links, i18n key leakage, placeholder contacts, HTTPS downgrade redirects, ETag validation, and `Zwergenprüfstand` clean-control verification.

## Next Horizons

1. **External Instrument Integrations**: Optional `testssl.sh` TLS protocol/cipher enumeration and Nu HTML Checker (`vnu`) conformance adapter behind `CollectorOutcome`.
2. **Multi-State Consent & Interaction Matrix**: Automated 3-state browser sessions (fresh, explicit reject, explicit accept) and safe widget keyboard-navigation probes.
3. **Visual Regression & Differential Benchmarks**: Screenshot perceptual-hashing baselines and automated differential comparison runs against SquirrelScan, Lighthouse, and axe-core.
4. **Language-Aware Linguistic & Similarity Layer**: Locale-specific readability models and SimHash/MinHash near-duplicate content clustering.

## Completed under Operation Aufrüstung IV (Waves IV-A – IV-I)

Rule-count expansion remains frozen at **235 rules** while sensory depth, element-level evidence, and the **Evidence Query Engine** have been completed across Waves IV-A through IV-I:

- **Wave IV-A & IV-A2 (Content, Timeline Sensory & Evidence Query Core — Completed)**: Source and rendered DOM segmentation with conservative cross-capture block matching and SHA-256 text fingerprints (`nzw diff`); redacted `endpoint_path`, `TimelineCacheSource`, and `TimelinePhaseTimings` on `BrowserTimeline`; offline `query_browser_timeline_filtered`, `query_request_chains`, `query_failed_dependencies`, `query_rendered_content`, `query_network_resources`, `query_runtime_errors`, and snapshot reuse in `query_browser_evidence_from_snapshot`.
- **Wave IV-B (Functional Intelligence — Completed)**: `InteractiveElementInventory`, `ApplicationStateSnapshot`, and `UserJourneyTrace` with offline `query_interactive_elements`, `query_application_state`, and `query_interaction_trace`.
- **Wave IV-C (Presentation & Accessibility Intelligence — Completed)**: `VisualGeometryInventory`, `AccessibilityNodeInventory`, modal Escape/focus restoration probes, and `axe-core` `target_selectors` with offline `query_element_geometry` and `query_accessibility_nodes`.
- **Wave IV-D (Security, Privacy & Third-Party Surfaces — Completed)**: `CookieAndStorageInventory` (value-free cookie attributes and storage key metadata), `ThirdPartyInventory`, `SecurityPostureSummary`, and `SecurityChallengeEvidence` with offline `query_storage_and_cookies`, `query_third_party_origins`, `query_security_posture`, and `query_security_challenge`.
- **Wave IV-E (Performance Attribution, Media & Fonts — Completed)**: `PerformanceAttributionEvidence` and `MediaAndFontInventory` with offline `query_performance_attribution` and `query_media_and_fonts`.
- **Wave IV-F (Search, Indexability & Structured Data — Completed)**: `IndexabilityAuthorityEvidence` and `StructuredDataInventory` with offline `query_indexability_authority` and `query_structured_data`.
- **Wave IV-G (Cross-Context Parity, Responsive Layout & Link Graph — Completed)**: Source-vs-rendered landmark drift (`compare_source_and_rendered`), `ResponsiveComparisonEvidence` (`query_responsive_comparison`), and `LinkGraphInventory` (`query_link_graph`).
- **Wave IV-H & IV-I (Visual Artefacts, Service Workers, TLS/CAA, Patrol Catalog, TUI & Zwergenprüfstand v2 — Completed)**: `VisualArtifactEvidence` (`query_visual_artifacts`), `ServiceWorkerLifecycleEvidence` (`query_service_worker_lifecycle`), `TlsAndCaaDiagnostics` (`query_tls_and_caa`), indexed `PatrolIndexCatalog` queries (`src/patrol/memory.rs`), 19-category `Zwergenleitstand` Evidence Workbench, and `Zwergenprüfstand` v2 comparative evaluation scenarios (`F-05`–`F-07`).

### Wave IV-A — Content & Initial Timeline Foundations (Completed)

- Source paragraph and region observations, language inheritance, and fixture-verified text distribution for documents with a single `main` landmark.
- Rendered clipping checks remain disabled until element-level geometry evidence is available (Wave IV-C).
- Initial browser timeline recording request hops and runtime events in receive order with bounded 16-event snapshot queries.
- Rendered DOM segmentation at the desktop viewport with conservative cross-capture block matching (unique ID or unique tag ancestry), versioned SHA-256 text fingerprints, and offline comparison via `nzw diff`.

### Wave IV-A2 — Complete Sensory Foundations & Evidence Query Core (P0)

- **Runtime & Network Timeline Expansion**: normalised and redacted endpoint paths, request initiator and top stack frame, interaction correlation, full per-request timing phases (DNS, TCP, TLS, queueing, TTFB, download), encoded vs decoded transfer sizes, wire-level status (`304` revalidation), cache source (`memory`, `disk`, `service_worker`), priority transitions, block and CORS failure classifications, WebSocket/SSE lifecycles, frame lifecycle, and SPA route transitions.
- **Evidence Query Engine (Timeline & Dependencies)**: typed offline operations over `EvidenceSnapshot` (`investigation::evidence_query`: `query_rendered_content`, `query_network_resources`, `query_runtime_errors`, `query_browser_evidence_from_snapshot`, plus upcoming `query_network_events`, `query_failed_dependencies`, `query_request_chain`) with explicit `EvidenceQueryStatus` (`Captured`, `Partial`, `Failed`, `Skipped`, `Unavailable`), bounded 16-item pagination, snapshot reuse in `query_browser_evidence`, and citation-checked `query_rendered_content` evaluation without exposing raw rendered text excerpts.

### Wave IV-B — Functional Intelligence (P0)

- **Interactive Element Inventory Collector**: element-level catalogue with stable identity, tag/role/accessible name, state (`enabled`, `disabled`, `expanded`, `selected`), visibility, bounding geometry, interaction capability, navigation targets, form constraints, ARIA relationships, component/modal context, safety classification, and functional classification (navigation menu, search, product selector, filter, sort, pagination, language selector, form, CTA, dialog, tabs, accordion, carousel, combobox, media player, download control).
- **Application State Collector**: shared state observations across `BrowserZwerg`, User Journey, and `KommandantZwerg` (document readiness, navigation state, DOM mutation rate, structural and visible fingerprints, active dialog/element/tab, expanded and disabled controls, form validation, loading/error/empty indicators, scroll position, active filters/variants, network idle state, and application stability).
- **User Journey & Interaction Collector**: candidate scenario discovery, safe bounded execution (requiring explicit authorisation for state-changing operations), initial and final state capture, latency measurement, DOM and AX tree mutation tracking, URL/routing transitions, correlated network and runtime errors, repeatable runs, and post-remediation verification (`query_interactive_elements`, `query_interaction_trace`, `query_application_state`).

### Wave IV-C — Presentation & Accessibility Intelligence (P0)

- **Visual Geometry Collector**: element-level bounding boxes, box model, scroll geometry, clipping bounds, text-fragment rectangles, occlusion and overlap relationships, stacking context (`position`, `z-index`), hit testing, and comparable multi-viewport measurements (`query_element_geometry`), unlocking evidence-backed content clipping and CTA/dialog reachability diagnostics.
- **Accessibility Tree & Behaviour Collector**: per-node AX inventory (node and backend DOM IDs, parent/child hierarchy, role, name/description and computation sources, states, properties, ignored reasons, semantic relationships, focusability, visibility, geometry), behavioural keyboard probes (forward, reverse, activation, arrow-key widgets, focus appearance and restoration, modal containment, live regions, validation feedback, reduced motion, text spacing, zoom/reflow, non-text contrast), and element-level `axe-core` node selectors and check outcomes (`query_accessibility_nodes`).

### Wave IV-D — Privacy & Consent Intelligence (P0)

- **Cookie & Browser Storage Collector**: full cookie attribute inventory (without storing raw secret or session values; using protected comparison digests for persistence checks) and browser storage inventory (`localStorage`/`sessionStorage` keys, IndexedDB databases, Cache Storage, service workers, and interaction deltas) via `query_cookie_inventory`.
- **Consent & External Data Flow Collector**: CMP detection, available consent options, isolated multi-scenario runs (`fresh`, `reject_all`, `accept_all`, `custom`, `withdrawal`, `repeat_visit`), observable consent state, cookie/storage and network deltas, external vendor and tracker classification, choice persistence, and cross-page enforcement (`compare_consent_sessions`).

### Wave IV-E — Performance Attribution Intelligence (P0)

- **Performance Attribution Collector**: LCP phase breakdown and resource correlation, CLS session windows and shifting element attribution, Event Timing (input delay, processing, presentation), main-thread trace breakdown (scripting vs layout, paint, compilation), Long Animation Frames, critical dependency chains, font loading variants, cold/warm/repeat cache behaviour, JS heap and DOM growth, rendering milestones, scenario-scoped code coverage, and repeated-measurement distributions.

### Wave IV-F — Application-Wide & Business Intelligence (P1)

- **Rendered Content & DOM Expansion**: rendered headings, lists, tables, control/link/label copy, product copy, rendered local/inherited `lang`, pseudo-element text, open Shadow DOM, same-origin iframes, CSS vs geometric visibility, heuristic main-content extraction, structural and similarity fingerprints, component association, and cross-page boilerplate clustering (`find_similar_pages`, `find_similar_components`).
- **Application Topology & Dependency Collector**: explicit distinction between observed and inferred edges across templates, components, resources, interactions, journeys, API endpoints, external services, business entities, documents, fonts, and application states (`find_shared_dependencies`).
- **Structured Business Entity Collector**: extraction across JSON-LD, Microdata, RDFa, semantic HTML, and rendered DOM for products, offers, variants, organisations, locations, articles, contacts, documents, CTAs, and forms, supporting market-, currency-, and locale-aware consistency checks (`query_business_entities`).
- **Search & Discovery Expansion**: per-agent `robots.txt` policies, sitemap provenance and `lastmod` consistency, HTTP/source/rendered canonical and redirect graphs, link context, cross-page fragment validation, hreflang target status, JS-dependent discoverability, and an explicit crawl frontier and uninspected coverage ledger.

### Wave IV-G — Extended Sensory Coverage (P1–P2)

- **TLS & Transport Collector (P1)**: full certificate chain, SANs, hostname and trust verification, serial, `not_before`, key/signature algorithms and sizes, negotiated TLS version/cipher/ALPN, HTTP/2 and HTTP/3 capabilities, OCSP stapling and CT observations, plus optional `testssl.sh` integration.
- **CSS & Component Inventory Collector (P1)**: stylesheet and rule inventory, selector specificity, duplicates, custom properties, extracted design tokens (colour palette, typography, spacing, radii, breakpoints), inline styles, animations, and computed-style/structural component fingerprints.
- **Media & Image Binary Collector (P1)**: bounded binary inspection (format/MIME, dimensions, decoded pixel volume caps, aspect ratio, DPR suitability, alpha, animation frames, colour profile, EXIF, exact and perceptual hashes, SVG complexity, video/audio metadata, poster and caption tracks).
- **Document Intelligence Collector (P2)**: bounded PDF inspection (format, size, page count, title, language, metadata, text layer, embedded links, structure, accessibility tags, fingerprints, and page references).
- **Browser Compatibility Collector (P2)**: targeted multi-engine investigation profiles (Chromium, Firefox, WebKit) and device/viewport/input/preference emulation (`request_additional_measurement`).

### Wave IV-H — Continuous & Field Intelligence (P1–P2)

- **Historical Evidence & Regression Collector (P1)**: longitudinal comparison across resource inventories, dependency topology, runtime/network timelines, user journeys, application states, performance distributions, AX/cookie/consent/geometry observations, business entities, and measurement profiles (`compare_observations`, `query_historical_evidence`), preserving epistemic honesty when coverage differs.
- **Field Performance Collector (P2)**: optional CrUX, RUM, and owner-supplied production telemetry kept strictly distinct from laboratory observations.
