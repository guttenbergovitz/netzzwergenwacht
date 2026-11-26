# Collector Capability Matrix

Inventory of NetzZwergenWacht data collectors, evidence levels, resource budgets, and completeness guarantees.

## 1. Core Collectors

| Collector | Module | Evidence Level | Default Bounds / Sampling Caps | Truncation / Partial Semantics |
| --- | --- | --- | --- | --- |
| HTTP Collector | `collection::http` | `Source` | `ExecutionBudget` timeout, redirect limit, `max_response_bytes` | `body_truncated` -> `CollectorOutcome::Partial` |
| TLS Inspector | `collection::tls` | `Source` | `ExecutionBudget` timeout; CAA lookup only when a resolver endpoint is configured | Missing/unverified TLS -> `Skipped` or `Failed`; CAA outcome recorded as `CaaLookupOutcome` |
| HTML5 Observation Parser | `analysis::document` | `Source` | Single HTML5 parse pass (`visible_text_sample` 4096 B) | Skipped on missing/truncated HTML |
| Discovery & Sitemap Crawler | `discovery` | `Source` | `CrawlBudget` (`max_pages`, `max_depth`, same-origin) | Records `coverage_complete` in `ApplicationGraph` |
| Chromium CDP Harness | `adapters::browser` | `Rendered` | `resources` <= 200, `rendered_images` <= 100, `ax_tree` <= 5000 nodes, load timeout derived from the execution budget | `load_timed_out` / truncation flags -> `CollectorOutcome::Partial` |
| `axe-core` Adapter | `adapters::axe` | `Rendered` | External CLI invocation bounded by timeout | `Unavailable` when Chromium/axe absent |
| Lighthouse Adapter | `adapters::lighthouse` | `Rendered` | External CLI invocation bounded by timeout | `Unavailable` when Lighthouse absent |
| Source Content Segmentation | `analysis::segmentation` | `Source` | Complete HTTP HTML, 32,768 nodes, depth 128, 256 paragraphs, 4 KiB per paragraph, 128 bytes per language attribute | Tree and paragraph limits explicit. A missing or ambiguous main landmark leaves word distribution unavailable. |
| Browser Runtime and Network Timeline | `adapters::browser` | `Rendered` | Existing Chromium session, 512 events, 128-byte identifier fields, 16 events per query | Explicit event cap and load termination, optional timestamps and correlation. Older snapshots have no timeline. |
| Rendered DOM Segmentation | `adapters::browser` | `Rendered` | Main-frame light DOM at the desktop viewport, 16,384 node visits, depth 64, 256 blocks, 512 UTF-16 units per excerpt. Identity census adds up to 16,384 node visits and counts IDs of up to 128 UTF-16 units | Explicit traversal, retention and census limits. Complete CSS-visible text can carry a versioned fingerprint. Failed evaluation is unavailable. |

## 2. Operation Aufrüstung IV Sensory Collectors

All rows below run inside the existing Chromium session and produce typed evidence consumed by the offline Evidence Query Engine. Every inventory reports its own retention limits; a failed enumeration is `Unavailable`, never an empty inventory.

| Collector | Domain model | Bounds | Availability semantics |
| --- | --- | --- | --- |
| Interactive Element Inventory | `InteractiveElementInventory` | 256 retained controls; per-element identity census and accessible-name fingerprint only | Truncation via `InteractiveInventoryLimits`; absent accessible name is `name_present = false` rather than an empty string claim |
| Application State | `ApplicationStateSnapshot` | Single snapshot at capture time; structural fingerprint bounded to 512 nodes and depth 16 | Fingerprint carries `structural_nodes_visited`, budgets, and truncation flags; `network_idle_reached` derives from observed in-flight requests |
| Interaction Trace | `UserJourneyTrace` | Native `details > summary` disclosures outside forms and links, 16 steps, 250 ms observation window per step | Each step records window length, termination reason, restoration result, and `InteractionProbePolicy`; `network_requests_suppressed = false` because probes are not isolated |
| Visual Geometry | `VisualGeometryInventory` | 16,384 node visits, depth 64, 128 retained elements | `VisualGeometryLimits` records DOM, depth and element truncation |
| Accessibility Node Inventory | `AccessibilityNodeInventory` | 256 retained CDP AX nodes with name length and SHA-256 name fingerprint | `AccessibilityInventoryLimits.total_cdp_nodes` and `nodes_truncated` |
| Cookie & Browser Storage | `CookieAndStorageInventory` | 128 cookies, 128 storage keys, IndexedDB enumeration, Cache Storage names | `cookies_enumerated` / `storage_enumerated` / `indexed_db_enumerated` flag acquisition; value byte lengths are UTF-8 byte counts |
| Third-Party Origins | `ThirdPartyInventory` | Resource-derived origins, bounded resource inventory | Origin classification reports capability (`script_element_present_in_main_frame`, cookie scoping), never execution or cookie setting |
| Security Posture | `SecurityPostureSummary` | Header and document signals from the captured response | Presence booleans are observed header/meta state, not policy effectiveness claims |
| Security Challenge Evidence | `SecurityChallengeEvidence` | Bounded indicator matching (challenge wrappers, captcha frames) | `challenge_detected` reports matched indicators, not provider attribution certainty |
| Performance Attribution | `PerformanceAttributionEvidence` | `PerformanceObserver` for LCP, layout shifts, long tasks; 16 retained shift regions | Observer installation flags gate every value; CLS is the largest session window; LCP candidate from DOM geometry is `dom_geometry_heuristic` with no inherited timing |
| Render-Blocking Chain | `RenderBlockingChainSummary` | 64 classified scripts and stylesheets | Confirmed/potential/unknown classification; byte totals are `None` when any member lacks an observed transfer size |
| Media & Font Inventory | `MediaAndFontInventory` | 128 media assets, 64 fonts | Separate truncation flags per inventory |
| Indexability & Authority | `IndexabilityAuthorityEvidence` | Rendered meta/canonical/hreflang signals (64 alternates) | Reports inspected signals only; no search-engine indexing claims |
| Structured Data | `StructuredDataInventory` | 32 entities, 32 JSON-LD blocks | `malformed_json_ld_count` and `issues` distinguish parse failure from valid structure |
| Responsive Comparison | `ResponsiveComparisonEvidence` | Desktop and mobile viewports measured in their own contexts | Built only when both viewports are observed; control counts and touch-target counts are optional |
| Link Graph & Forms | `LinkGraphInventory` | 256 links, 32 forms | Separate truncation flags; anchor text exposed as word count and fingerprint |
| Visual Artefacts | `VisualArtifactEvidence` | Viewport screenshot SHA-256 digest, 64 retained above-the-fold rectangles, 40x25 sampling grid | Coverage is `above_fold_retained_element_coverage_milli` — a geometric estimate, not pixel coverage; screenshot digest proves binary equality only |
| Service Worker Lifecycle | `ServiceWorkerLifecycleEvidence` | Registration and Cache Storage enumeration at capture time | Reports registration state as observed; no inference about offline capability |
| TLS & CAA Diagnostics | `TlsAndCaaDiagnostics` | Leaf-certificate projection from `TlsEvidence`; up to 16 direct CAA records | CAA records are direct observations for the queried hostname only; effective policy inheritance is not computed |

## 3. Evidence Query Engine

`src/investigation/evidence_query.rs` and `src/investigation/browser_timeline.rs` expose 21+ offline queries over `&EvidenceSnapshot`. Each query:

- reports `EvidenceQueryStatus` (`Captured`, `Partial`, `Failed`, `Skipped`, `Unavailable`) before any data;
- pages at 16 items and never exposes raw rendered text, cookie values, or storage values;
- excludes unobserved numeric values from numeric filters instead of treating them as zero;
- validates citations against the page that was actually supplied to the agent.

## 4. Identity and Comparison Contracts

- Rendered block identity census is bounded; `id_census_complete = false` means a duplicate ID verdict covers only the inspected scope.
- Structural fingerprints carry their version, node budget, depth budget, and truncation flags; a comparison of a bounded projection is reported as such.
- Text fingerprints are versioned SHA-256 digests of normalised visible text; they establish equality or difference, not similarity.
