# Agent Guidelines

Instructions for AI coding agents working on the `rewrite/rust` branch of **NetzZwergenWacht**.

## 1. Mission & Product Direction

NetzZwergenWacht is an **evidence-driven external web quality and reliability auditing engine with optional AI-assisted analysis**.

- **Do not translate the Python code.** Translate the lessons learned (see `docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md`).
- The legacy Python implementation in `legacy/` (and on `main`) is a frozen historical reference only. Do not add new features to Python.
- Retain the **Die Zwergenbrigade** identity (`NetzZwerg`, `SicherheitsZwerg`, `LeistungsZwerg`, `StrukturZwerg`, `ZugänglichkeitsZwerg`, `SuchZwerg`, `InhaltsZwerg`, `GestaltungsZwerg`, `BrowserZwerg`, `DokumentationsZwerg`, `KommandantZwerg`) via the central registry in `src/brigade.rs`, keeping presentation metadata separate from analytical logic.

## 2. Language and Tone

- Use **British English (`en-GB`)** and **ASCII identifiers** consistently across all technical module names (`analysis::accessibility`, `analysis::semantics`, etc.), source code identifiers, documentation, docstrings, error messages, and commit messages (for example: *optimise*, *behaviour*, *defence*, *colour*, *licence*, *normalise*, *artefact*, *initialise*).
- Use **German (`de-DE`)** for dwarf display names (umlauts permitted, e.g. `ZugänglichkeitsZwerg`), collective branding (`Die Zwergenbrigade`), and the motto (`Kleine Zwerge. Große Sorgfalt.`). Do not mix German and English within individual dwarf names.
- Write in plain, direct, no-nonsense prose. Explain the **purpose** and **why** behind a module, type, or invariant so both human developers and LLMs can reason about the code without guessing. Avoid filler and restating obvious syntax.

## 3. Spec-Driven Workflow and Repository Hygiene

- Temporary working specifications, design scratchpads, and agent plans must live exclusively under `.specs/` (which is gitignored). Never scatter temporary markdown plans, notes, or checklists across the repository.
- Canonical project skills live under `.agents/skills/` (`nzw-feature-slice`, `nzw-architecture-review`, `nzw-security-audit`). Use them when implementing features, reviewing changes, or auditing security boundaries.
- Durable architectural decisions belong in `docs/adr/` following `docs/adr/README.md`.
- Work in small, verifiable steps. Do not introduce speculative abstractions, unused traits, or unrequested dependencies.

## 4. Non-Negotiable Engineering & Rust Standards

Follow `docs/conventions.md` strictly:

1. **Evidence First**:
   - Every finding must trace to captured evidence (`EvidenceRef`).
   - Never coerce a failed, skipped, or unavailable measurement into `0` or a passing check (`Measurement<T>`).
   - Absence of evidence is not evidence of absence.
2. **Deterministic Core**:
   - Collection and deterministic analysers must run with zero LLM dependencies or API keys.
   - Analysers must consume `&EvidenceSnapshot` and never perform uncontrolled network I/O.
3. **Type-Driven Contracts**:
   - Prefer explicit algebraic types (`enum`, newtypes, `Result`) over generic JSON maps or stringly-typed contracts.
4. **No Arbitrary `.unwrap()` or `.expect()`**:
   - Denied in production code (`clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`). Propagate errors explicitly with `Result` and `?`.
5. **No Gratuitous `.clone()`**:
   - Design ownership, borrowing, and lifetimes cleanly.
6. **Resource Governance**:
   - All network, browser, subprocess, and LLM operations must honour explicit `ExecutionBudget` bounds (concurrency, timeouts, payload caps, cancellation).
7. **Honest Claims**:
   - Automated accessibility checks must never be presented as proof of full WCAG or EU Accessibility Act legal compliance.
   - No placeholder implementations, fabricated metrics, or unbenchmarked performance claims.

## 5. Quality Gates & Commits

Run before every commit (or via `task check`):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo test --all-targets --locked
```

Follow **Conventional Commits** in `en-GB`. Keep commits atomic and never commit secrets or files from `.specs/`.
