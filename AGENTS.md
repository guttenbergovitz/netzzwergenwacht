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

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:46cd31e7 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->
