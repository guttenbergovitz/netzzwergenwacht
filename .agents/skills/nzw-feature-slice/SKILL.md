---
name: nzw-feature-slice
description: >-
  Spec-driven TDD workflow for implementing a small, verifiable feature slice in
  NetzZwergenWacht. Use when adding or modifying functionality across domain,
  collection, analysis, persistence, intelligence, or CLI modules.
---

# NetzZwergenWacht Feature Slice Workflow

Follow this sequence for every non-trivial code change so work stays small, idiomatic, evidence-driven, and verifiable.

## 1. Clarify scope before coding

- Check existing working notes in `.specs/` and relevant ADRs in `docs/adr/`.
- If the change introduces new behaviour or non-obvious invariants, write or update a concise working specification in `.specs/` first (never scatter temporary plans outside `.specs/`).
- Confirm the change respects module boundaries:
  - `domain` stays free of transport, browser, persistence, and LLM concerns.
  - `analysis` (Zwerge) consumes `&EvidenceSnapshot` and never performs network I/O.

## 2. Practise TDD

- Write focused unit or integration tests defining expected behaviour, boundary values, and failure modes before or alongside implementation.
- Cover invalid inputs, `ExecutionBudget` limits, and `Measurement::Failed` / `Unavailable` / `Skipped` states explicitly.
- Tests may use `.unwrap()` / `.expect()`, but production code must not.

## 3. Implement idiomatically

- Model invalid states out of existence with explicit domain types and enums instead of passing raw primitives or generic JSON maps.
- Propagate errors explicitly with `Result` and `?`. Do not bypass strict lints with silent `#[allow(...)]`.
- Prefer borrowing (`&T`, `&[u8]`, `Cow<'_, str>`) over gratuitous `.clone()`.
- Write plain, direct `en-GB` docstrings explaining *purpose* and *invariants*, not obvious syntax.
- Add external dependencies to `Cargo.toml` only when genuinely justified.

## 4. Verify with the full quality gate

Run all four checks (or `task check`) and ensure zero warnings and zero failures:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo test --all-targets --locked
```

## 5. Finalise cleanly

- If the change establishes a durable architectural decision, record a short KISS ADR in `docs/adr/` (using `docs/adr/README.md`).
- Commit atomically using Conventional Commits in `en-GB`.
