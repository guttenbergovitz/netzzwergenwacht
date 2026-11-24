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
