# Collection Engine

> **Status**: Target Design (Phase 1 HTTP collector; Phase 2 browser & external adapters).

The **Collection Engine** is solely responsible for acquiring external evidence once per audit target and producing an immutable `EvidenceSnapshot`.

## 1. Responsibilities

- **HTTP & Redirect Collection** (`reqwest` + `rustls`):
  - Capture status code, redirect chain (up to `max_redirects`), response headers, response body (bounded by `max_response_bytes`), and timing metadata.
- **TLS & DNS Observations**:
  - Record negotiated TLS version, cipher suite, certificate subject/issuer/SANs/expiry from `rustls` handshake, and resolved IP addresses.
- **Browser Session Collection** (Phase 2):
  - Single controlled headless Chromium session per viewport profile (or isolated sessions only where measurement methodology requires it, e.g., clean cache for Lighthouse).
  - Attach console error and network failure listeners **before** navigation.
  - Capture rendered DOM, console events, failed network requests, and bounded screenshots.
- **External Tool Adapters** (Phase 2):
  - **Lighthouse** adapter for Core Web Vitals and performance traces.
  - **axe-core** adapter for rendered-DOM accessibility checks.
  - Optional active security adapters (only when explicitly authorised).

## 2. Failure & Isolation Semantics

- Each collector returns `CollectorOutcome<T>`: `Captured(T)` | `Partial { data: T, warnings: Vec<String> }` | `Failed(CollectionError)` | `Skipped(String)`.
- Collector failures do not crash the orchestrator; they are recorded in the `EvidenceSnapshot` so downstream analysers know which evidence is absent.

## Source content segmentation

The shared HTML5 parse yields content evidence for editorial integrity and
internationalisation checks. Paragraph references are zero-based positions in
body-subtree element order for the captured HTML. Consumers can resolve them
within that document. Changes to the document can shift those positions.

The collector records paragraph text with Unicode whitespace collapsed and
retains local and inherited language declarations within explicit limits.
Language checks exclude nested declarations from whole-paragraph inference.
The collector excludes explicitly hidden HTML and non-content elements.
Computed CSS visibility, rendered clipping and client-generated content require
browser evidence.

For a unique main landmark, the collector counts eligible source words inside
and outside it. The existing boilerplate rule uses a majority outside-main
threshold as a structural heuristic. Cross-page repetition and template
membership require separate observations. Empty regions are defined narrowly
as eligible regions without child elements or non-whitespace text.

The snapshot query exposes pages of 16 paragraph references and word counts,
along with retention status and the main-landmark distribution. Specialist and
Kommandant prompts receive the first page for complete HTML up to 512 KiB.
The prompt projection contains numeric metadata and no page text or collector
error messages. The query derives its evidence from the captured HTML locally.

## Browser runtime and network timeline

The existing Chromium session records network and classified runtime events
in collector receive order. Optional protocol timestamps preserve their
monotonic or Unix clock domain. A request ID and redirect hop identify observed
stages within the session. Frame and loader identifiers appear when CDP
provides them.

HTTP responses, transport failures, cancellations and browser or collector
blocks have separate event types. A known collector policy block suppresses
the corresponding terminal failure event. When CDP omits the network ID,
the block remains an uncorrelated observation. Response statuses come from
CDP response events. Wire-level cache revalidation status from additional
protocol events is unavailable in this slice.

The timeline retains up to 512 events and records truncation and the
observation end. URL evidence is limited to HTTP(S) origins. The timeline
omits request paths, credentials, queries, response bodies and raw runtime
messages. Existing browser summaries retain their own evidence contracts.

The Rust query pages through captured snapshot events in groups of 16.
Kommandant can request the first page without starting a browser. The
evaluation accepts timeline citations only when their sequence numbers appear
on that page. The sequence records observation order and can support further
investigation of a correlation.

## Rendered DOM segmentation

A read-only probe in an isolated Chromium execution world measures paragraphs
and semantic regions in the main document at the existing desktop viewport.
The snapshot records viewport dimensions and capture-local node positions.
These positions resolve only within a single capture. Comparing a source
document and a browser snapshot can show differing observations, while tracking
the cause or matching elements across captures requires further evidence.

Computed CSS checks cover display, visibility, opacity and content visibility.
The probe retains bounded excerpts from eligible text nodes, collapses
whitespace, and inserts separators at structural boundaries. Nested regions may
include the same text as their paragraphs. Editable content, form controls and
CSS-masked text are excluded. Frames, shadow trees, pseudo-elements, geometry,
clipping and occlusion are outside coverage.

The traversal stops at 16,384 node visits and skips subtrees below depth 64.
It retains 256 blocks, normalises at most 2,048 UTF-16 units per text run,
and retains at most 512 per block. Limit flags identify partial evidence.
A failed probe leaves segmentation unavailable. The serialised snapshot can
contain visible page text. Current investigation prompts receive no excerpts
from this collector.
