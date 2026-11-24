---
name: nzw-architecture-review
description: >-
  Architecture and idiomatic Rust review checklist for NetzZwergenWacht. Use when
  reviewing a diff, PR, or completed feature slice for module boundary
  violations, evidence-first invariants, ownership/cloning hygiene, lint
  bypasses, over-engineering, and en-GB documentation quality.
---

# NetzZwergenWacht Architecture & Idiomatic Rust Review

Audit the diff against NetzZwergenWacht's architectural boundaries and Rust standards in `docs/conventions.md` and `AGENTS.md`. Focus on what `cargo clippy` cannot catch automatically.

## 1. Module boundaries and evidence-first invariants

- Verify strict separation between `domain`, `collection`, `analysis`, `persistence`, `intelligence`, and `cli`.
- `domain` must never import from `collection`, `analysis`, `persistence`, `intelligence`, or `cli`.
- `analysis` (Zwerge) must consume `&EvidenceSnapshot` and must never perform HTTP, DNS, or browser I/O.
- Every finding must trace to captured evidence (`EvidenceRef`). Reject any code that coerces a failed, skipped, or unavailable measurement into `0` or a passing check.
- Reject any claim or score that presents automated accessibility checks as proof of full WCAG or EU Accessibility Act compliance.

## 2. Ownership, borrowing, and allocations

- Flag gratuitous `.clone()`, `.to_owned()`, or `.to_string()` added merely to appease the borrow checker.
- Flag unnecessary `Arc<Mutex<_>>` or `Box<dyn ...>` where borrowing (`&T`, `&[u8]`, `Cow<'_, str>`) or value ownership is cleaner.

## 3. Error handling and lint integrity

- Inspect every `#[allow(...)]` attribute in the diff. Reject any `#[allow(clippy::unwrap_used)]`, `#[allow(clippy::expect_used)]`, or `#[allow(clippy::panic)]` in production code unless an invariant is provably unbreakable and explicitly explained in a comment.
- Ensure failure modes are modelled as explicit, actionable domain error variants rather than stringly-typed errors.

## 4. Anti-over-engineering (KISS)

- Flag speculative traits with a single implementation, unused generics, dead helper layers, or configuration knobs with no current consumer.
- Flag primitive obsession (`String`, `u32`, `bool`) crossing module boundaries where a validated domain type belongs.

## 5. Documentation and language (`en-GB`)

- Confirm all public items, comments, error messages, and commit messages use **British English (`en-GB`)** with no Americanisms (for example: *optimise*, *behaviour*, *defence*, *normalise*, *artefact*, *initialise*, *colour*, *licence*).
- Confirm docstrings explain *why* and *invariants*, not trivial syntax.

## Output format

Report findings concisely grouped by severity (**Blocking**, **Suggestion**, **Clean**), citing exact file paths and line numbers.
