# AGENTS.md

Guidance for AI coding agents working on the `rewrite/rust` branch of **NetzZwergenWacht**.

## 1. Mission & Product Direction

NetzZwergenWacht is an **evidence-driven external web quality and reliability auditing engine with optional AI-assisted analysis**.

- **Do not translate the Python code.** Translate the lessons learned (see `docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md`).
- The Python implementation on `main` is a historical reference only. Do not add new features to Python.
- Retain the Zwerg domain identity (`SicherheitsZwerg`, `LeistungsZwerg`, `ZugaenglichkeitsZwerg`, `SEOZwerg`, `InhaltZwerg`, `VisualZwerg`, `WebBrowserZwerg`) where it clarifies domain ownership without hurting code readability.

## 2. Non-Negotiable Engineering Rules

1. **Evidence First**:
   - Every finding must trace to captured evidence (`EvidenceRef`).
   - Never coerce a failed, skipped, or unavailable measurement into `0` or a passing check.
   - Absence of evidence is not evidence of absence.
2. **Deterministic Core**:
   - Collection and deterministic analysers must run with zero LLM dependencies or API keys.
   - Analysers must not perform uncontrolled network I/O; they consume `&EvidenceSnapshot`.
3. **Type-Driven Contracts**:
   - Prefer explicit algebraic types (`enum`, newtypes, `Result`) over generic JSON maps or stringly-typed contracts.
4. **Resource Governance**:
   - All network, browser, subprocess, and LLM operations must honour explicit `ExecutionBudget` bounds (concurrency, timeouts, payload caps, cancellation).
5. **Honest Claims**:
   - Automated accessibility checks must never be presented as proof of full WCAG or EU Accessibility Act legal compliance.
   - No placeholder implementations, fabricated metrics, or unbenchmarked performance claims.

## 3. Quality Gates

Before committing any Rust changes, run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 4. Key Documentation

- `docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md`
- `docs/architecture/overview.md`
- `docs/migration/python-capability-inventory.md`
- `docs/roadmap.md`
