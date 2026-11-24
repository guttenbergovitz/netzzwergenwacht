---
name: nzw-security-audit
description: >-
  Security boundary audit checklist for NetzZwergenWacht as an external web
  auditing engine. Use whenever implementing or reviewing target validation,
  HTTP/TLS collection, browser automation, external tool adapters, active scans,
  or optional AI integration.
---

# NetzZwergenWacht Security Audit Checklist

NetzZwergenWacht processes untrusted external HTTP responses, HTML/DOM, headers, and console output. Audit every change touching security boundaries against the controls below.

## 1. Target validation and SSRF defences

- Reject non-`http`/`https` schemes, empty hosts, and embedded credentials in target URLs.
- Enforce SSRF guardrails: block loopback (`127.0.0.0/8`, `::1`), RFC 1918 private ranges, link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), unique local IPv6 (`fc00::/7`), and IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) unless explicitly permitted for local testing.
- Validate redirect hops against the same target/IP policy and cap `max_redirects`.

## 2. Resource exhaustion and browser sandboxing

- Enforce `max_response_bytes` while streaming HTTP responses (never buffer an unbounded body).
- Enforce `ExecutionBudget` timeouts, concurrency semaphores, and `CancellationToken` propagation across HTTP, browser, and external subprocesses.
- Run headless browser contexts in isolated temporary profiles without persistent cookies or host credentials.

## 3. Active security scanning gates

- Active security checks (port scanning, path probing) must remain **disabled by default** and require explicit opt-in (`--active-scan`) restricted to explicitly authorised targets.

## 4. Untrusted content & AI prompt-injection boundaries

- Treat externally collected HTML, titles, headers, and console logs as untrusted data.
- Never pass raw untrusted page content to an LLM as instructions, and never allow LLM tool calls to bypass `ExecutionBudget` or target-authorisation policies.
- Ensure API keys and secrets are never logged or persisted into `EvidenceSnapshot` or audit reports.

## Output format

Report findings by severity (**Critical**, **High**, **Medium**, **Note**) with concrete exploit scenarios and minimal remediation steps.
