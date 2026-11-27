# NetzZwergenWacht — Phase II: External Technical Quality Assurance

**Target positioning:** *NetzZwergenWacht — Independent, Evidence-Driven Black-Box Application Quality Assurance.*

The objective is not to find more defects. The objective is to establish, with defensible evidence, how well a digital product actually works.

## 1. Strategic Objective

NetzZwergenWacht is an independent, evidence-driven system for assessing the technical fitness of web applications from the perspective of an external observer (black-box assessment).

The system enables teams and decision-makers to:

- Perform independent technical acceptance of a product delivered by an internal team or external agency.
- Identify technical defects, quality regressions, and operational risks.
- Assess real application fitness from the user's perspective.
- Verify that declared fixes have actually been implemented.
- Monitor product quality continuously across release stages.
- Supply defensible, traceable evidence for QA, PM, PO, and CTO stakeholders.

NetzZwergenWacht does not replace engineering or QA roles; it automates diagnostic, auditing, and verification labour.

## 2. Scope and Non-Goals

### In Scope

- External web application auditing and black-box technical QA.
- Non-functional quality assessment and bounded user-perspective functional testing.
- Application reconnaissance and evidence-driven diagnosis.
- Release acceptance support, regression detection, and continuous quality monitoring.

### Out of Scope

- Project/schedule management, developer productivity analytics, or standalone backlog management.
- Internal source-code architecture or internal cloud infrastructure auditing.
- Autonomous modification of target applications.
- Full-scale penetration testing or formal legal compliance certification.

The system must remain useful without access to the target's repository, infrastructure, internal technical documentation, or delivery team. Optional configuration of expected product behaviour and authorised test sessions do not violate the black-box principle.

## 3. Current State Assessment

Phase I established the core architectural foundations: deterministic diagnostic engine (235 registered rules), HTTP/TLS/browser collectors, typed evidence model, offline Evidence Query Engine, specialist domains (`Die Zwergenbrigade`), agentic investigation (`KommandantZwerg`), bounded discovery and sampling, persistent evidence storage, historical diffing, autonomous patrol, and the `Zwergenleitstand` TUI.

The primary gap is no longer rule count, but **diagnostic depth, observation completeness, conclusion reliability, and empirical validation**. The existence of a collector, data model, rule, or unit test must never be equated with confirmed diagnostic effectiveness.

## 4. Technical Quality Competency Matrix

| Domain | Phase I Coverage | Phase II Direction |
|---|---|---|
| HTTP / Network | Substantial | Deepen |
| TLS / DNS | Partial | Deepen |
| Surface Security | Partial | Deepen |
| Browser Runtime | Substantial (CI launch instability) | Stabilise |
| Web Performance | Laboratory | Expand methodology |
| Accessibility | Partial | Deepen |
| Responsive Design | Partial | Expand |
| Visual Quality | Limited | Major expansion |
| Content Integrity | Partial | Deepen |
| SEO / Discoverability | Substantial rule coverage | Validate |
| Internationalisation | Limited | Expand |
| Functional Behaviour | Limited | **Critical gap** |
| User Journeys | Minimal | **Critical gap** |
| Privacy / Consent | Partial | Major expansion |
| Regression Detection | Partial | Consolidate |
| Application-wide Diagnosis | In progress | Consolidate |
| Operational Monitoring | Limited patrol | Expand |
| Empirical Validation | No published validation | **Critical gap** |

## 5. Required Diagnostic Capabilities

### 5.1 Application Discovery and Topology

Build a representative application map rather than a flat URL list: sitemap discovery, recursive crawling, browser-observable SPA route discovery, canonical URL resolution, template/page-family identification, locale variants, orphan page detection, form/interaction-point discovery, broken internal links and soft 404s, shared component/resource mapping, external dependency identification, and critical user-path detection.

Every URL/entity must be accounted for explicitly across: `Discovered`, `Inspected`, `PartiallyInspected`, `ReusedEvidence`, `Unreachable`, `Excluded`, and `Unknown`. A bounded scan must never be presented as a full audit.

### 5.2 Functional Behaviour Intelligence

Move beyond passive DOM observation to bounded, controlled behavioural probing with explicit scope, safety constraints, observed outcomes, and evidence: non-responsive buttons/navigation, forms and validation, search, filters/sorting, pagination, modals, mobile menus, language switchers, dynamically loaded components, API error handling, `loading`/`empty`/`error`/`success` states, and interrupted flows. Executing a click is never proof of functional correctness.

### 5.3 User Journey Assessment

Repeatable user scenarios (product discovery, information search, language switching, store locator, form submission, add-to-cart, bounded checkout stages) specifying preconditions, actions, expected outcomes, assertions, time limits, failure evidence, and safety restrictions. Mutating operations (sending messages, placing orders, payments) require explicit authorisation or test environments. An LLM rating behaviour as "sensible" never substitutes for explicit assertions.

### 5.4 Browser Runtime Intelligence

Capture JS exceptions, unhandled promise rejections, failed network/resource requests, redirect chains, API failure patterns, hydration failure signals, SPA navigation failures, service worker lifecycle, WebSocket/SSE lifecycle, main-thread activity, browser memory consumption, DOM growth, and request initiator attribution. Separate observed failures from causal hypotheses.

### 5.5 Performance Engineering

Replace single-shot lab runs with repeatable measurement series: median, p75, distributions; cold-cache vs warm-cache; mobile vs desktop; configurable network/CPU profiles; TTFB, FCP, LCP, CLS, Event Timing, Long Tasks, Long Animation Frames, main-thread blocking, JS execution cost, render-blocking resources, resource size distribution, third-party impact, and performance budgets. Strictly separate lab measurements from field telemetry (CrUX/INP).

### 5.6 Accessibility Assessment

Extend beyond static HTML and `axe-core`: keyboard navigation, focus order and visibility, keyboard traps, accessible names, ARIA state consistency, dynamic content announcements, modal focus management, contrast, zoom and reflow, accessibility tree consistency, form error accessibility, and regression detection. Explicitly state which requirements are automated vs human-verified; zero defects never implies WCAG compliance.

### 5.7 Visual and Responsive Quality

Extend element-geometry checks across representative viewports and, over time, multiple browser engines: horizontal overflow, clipped content, overlapping elements, invisible interactive controls, layout breakage, text overflow, broken images, aspect-ratio distortion, unreadable content, occluded navigation, excessive overlays, viewport-specific defects, visual regression, screenshot retention, and component-level comparison accounting for dynamic content/animations. LLM vision may assist interpretation but never replaces deterministic geometry and pixel/hash measurements.

### 5.8 Surface Security

Remain external and non-invasive: TLS protocol/certificate/chain/expiry assessment, security headers, CSP analysis, cookie security, mixed content, HTTPS downgrade detection, publicly exposed sensitive data, CORS observations, third-party dependency exposure, public API surface discovery, and browser-observable security failures. Active security probes require separate explicit authorisation.

### 5.9 Privacy and Consent Behaviour

Compare application behaviour across consent states: fresh session, no consent, reject all, accept all, selective consent, and consent withdrawal — covering cookies, `localStorage`, `sessionStorage`, third-party requests, tracking endpoints, state transitions, pre/post-consent network activity, and persistent identifiers. Report observed behaviour and risks, never automated legal opinions.

### 5.10 Content and Internationalisation

Detect missing translations, unresolved translation keys, placeholder content, inconsistent locale declarations, incorrect language fallback, missing language equivalents, cross-language navigation errors, incorrect `hreflang` relationships, content truncation, broken media, date/price/currency format inconsistencies, and structural differences across locale variants. Separate LLM semantic assessments from deterministic defects.

### 5.11 Application Availability and Reliability

Assess stability over time: repeatable HTTP availability checks, synthetic browser monitoring, DNS failure detection, TLS expiry monitoring, intermittent failure detection, response-time distributions, critical journey availability, external dependency failure detection, and multi-region observations where available. Distinguish application failures from measurement-infrastructure failures.

## 6. Evidence Integrity

Every finding must carry: stable finding identity, rule ID and version, application and page scope, environment, observation timestamp, collector identity and version, measurement conditions, evidence references, observed value, expected value (if defined), severity, confidence, known limitations, reproduction procedure, and verification procedure.

Strictly distinguish: `Measurement`, `DeterministicFinding`, `HeuristicObservation`, `AgenticHypothesis`, `ConfirmedDiagnosis`, and `Unknown`. An evidence reference does not prove interpretation correctness, and an LLM must never overwrite measured facts.

## 7. Application Quality Profile

Introduce an optional, versioned Application Quality Profile specifying: application type, criticality, expected locales, critical pages, critical user journeys, required viewports, required collectors, performance budgets, minimum coverage, applicable rules, accepted exceptions/waivers, maximum observation age, and technical acceptance criteria. Absence of a profile must not block exploratory audits, but must restrict definitive product-acceptance verdicts.

## 8. Quality Assessment Model

Do not collapse application quality into an arbitrary `0–100` score. Use a multi-dimensional assessment across:

- Functional integrity
- Runtime stability
- Performance
- Accessibility
- Visual quality
- Surface security
- Privacy
- Content integrity
- Discoverability
- Reliability
- Evidence coverage

Each domain receives an explicit verdict: `PASS`, `FAIL`, `INSUFFICIENT EVIDENCE`, `NOT APPLICABLE`, or `WAIVED`. An aggregate verdict must never hide critical defects or missing evidence. Consolidate `compute_release_readiness()` and `evaluate_policy()` around one shared quality assessment semantics.

## 9. Regression Intelligence

Classify changes across runs as: `New`, `Persisting`, `Worsened`, `Improved`, `ConfirmedResolved`, `Reintroduced`, `Unverified`, or `NonComparable` across functional behaviour, runtime behaviour, content structure, visual representation, performance distributions, security posture, accessibility, and dependency topology. Unchanged HTML or HTTP `304` does not imply unchanged application behaviour; comparisons must verify methodology, rule version, instrument, and scope compatibility.

## 10. Application-Wide and Systemic Diagnosis

Cluster shared-component, shared-template, shared-resource, systemic accessibility, recurring JS error, shared-dependency, locale-specific, viewport-specific, and correlated regression defects into single systemic findings with explicit affected scope (e.g., 1 defect across 900 pages rather than 900 independent tickets), with explicit justification for any common-cause hypothesis.

## 11. Operational Architecture

Consolidate `scan`, `check`, `investigate`, `patrol`, `verify`, and `diff` onto a unified nine-stage lifecycle sharing one Persistent Evidence Store (`Evidence`, `Findings`, `Coverage`, `ApplicationIdentity`, `HistoricalObservations`):

1. Discover → 2. Collect → 3. Persist → 4. Analyse → 5. Investigate → 6. Assess → 7. Report → 8. Verify → 9. Monitor.

## 12. Agentic Intelligence Responsibilities

Agents interpret audit goals, plan diagnostics, form falsifiable hypotheses, select existing instruments, correlate observations, identify missing evidence, propose additional tests, explain impact, prioritise issues, and generate reports. Agents must never simulate measurements, assert unobserved facts, alter acceptance criteria, treat unavailable data as passing, fabricate quality scores, or execute unauthorised interactions.

## 13. Stakeholder Reporting

Render the same underlying evidence through three stakeholder lenses with drill-down from executive conclusion to technical evidence:

- **QA**: defects, reproduction steps, expected vs observed behaviour, evidence, coverage, regression status, verification instructions.
- **PM**: technical acceptance state, blockers, items requiring remediation, verified fixes, unresolved questions, delta since previous audit.
- **CTO**: systemic defects, external technical quality debt, reliability and dependency risks, quality trends, material architectural symptoms, observation limitations.

## 14. Empirical Validation Programme

Build a labelled corpus covering static sites, SSR, SPA, e-commerce, CMS, multilingual, legacy, healthy controls, and intentionally defective applications. Measure precision, recall against ground truth, false-positive/negative rates, repeatability, evidence correctness, execution cost/time, human review effort, and incremental diagnostic value across: (1) specialist tools, (2) NZW deterministic mode, (3) NZW agentic mode, and (4) human expert assessment.

## 15. Implementation Priorities

- **P0 — Stabilisation and credibility**: Fix Chromium CI launch failure; stabilise live browser tests; consolidate evidence and persistence; verify existing rules; empirically validate current competencies; consolidate quality assessment mechanisms; enforce accurate coverage and `INSUFFICIENT EVIDENCE` semantics.
- **P1 — Genuine black-box QA**: Controlled interaction engine; functional assertions; user journey testing; Application Quality Profiles; persistent finding lifecycle; visual regression; cross-run evidence comparison; extended runtime and accessibility analysis.
- **P2 — Diagnostic depth**: Repeated performance measurements; privacy and consent scenarios; advanced multilingual assessment; cross-browser assessment; systemic defect clustering; dependency failure attribution.
- **P3 — Continuous technical assurance**: Release-aware baselines; scheduled execution; portfolio-level assessment; synthetic monitoring; regression alerts; longitudinal quality trends; exportable evidence packages.

## 16. Engineering Principles

- Do not expand rule count without demonstrated diagnostic value.
- Do not introduce new agents without a distinct measurable competency.
- Prefer deterministic observation over probabilistic interpretation.
- Prefer reproducible assertions over subjective evaluations.
- Prefer meaningful coverage over exhaustive but shallow crawling.
- Prefer systemic diagnosis over finding proliferation.
- Never confuse absence of evidence with evidence of absence.
- Never confuse diagnostic capability with empirical effectiveness.
- Never claim technical acceptance beyond the inspected and verified scope.

## 17. Definition of Success

NetzZwergenWacht enables a technical decision-maker to answer nine questions without juggling a dozen separate tools:

1. What actually works?
2. What does not work?
3. Under what conditions does the problem occur?
4. What is its scope and impact?
5. What evidence confirms the diagnosis?
6. What could not be verified?
7. What changed since the last audit?
8. Were declared fixes actually implemented?
9. Does the product meet defined technical quality criteria?
