# Security Model

> **Status**: Target Design.

Auditing external websites involves handling untrusted network responses, untrusted DOM/JS content, and potentially sensitive active checks.

## 1. Passive vs. Active Auditing

- **Default (Passive)**: Standard HTTP GET/HEAD requests, TLS handshake inspection, and headless browser rendering of publicly accessible pages.
- **Active Security Testing** (e.g. port scanning, directory/endpoint probing):
  - **Disabled by default**.
  - Must be explicitly enabled (`--active-scan`) and restricted to explicitly authorised targets (allowlist / confirmation policy).

## 2. Untrusted Content Handling

- External HTML, headers, redirects, and console output are treated as hostile/untrusted.
- **SSRF / Internal Network Guardrails**: `AuditTarget` validation must be able to block loopback, link-local, and private RFC1918/ULA ranges unless explicitly permitted for local testing.
- **Response Size Caps**: Prevent memory exhaustion from oversized or compressed-bomb responses.
- **Browser Sandboxing**: Run headless Chromium with isolated temporary profiles and no persistent user cookies/credentials.
- **LLM Prompt Injection**: Untrusted page content is never trusted as instructions (see `docs/architecture/intelligence-layer.md`).

## 3. Supply-Chain & Secrets

- API keys (for optional Phase 4 LLM providers) are read from environment/secret config and never logged or written into `EvidenceSnapshot` or reports.
- Dependencies are tracked in `Cargo.lock` and audited via `cargo-audit` in CI.
