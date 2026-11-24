# 0009. Patrol Persistence Evaluation and SQLite Migration Path

## Status

Accepted

## Context

`src/patrol/memory.rs` persists per-application institutional memory as `<memory_dir>/<app_id>.json`. As `nzw patrol --targets applications.toml` introduces multi-application portfolios, we must decide whether to introduce SQLite (`rusqlite` / `sqlx`) immediately or retain structured JSON files for the current phase.

## Decision

1. **Retain per-application JSON (`<memory_dir>/<app_id>.json`) for single-application and initial portfolio patrols**:
   - Zero native C/SQLite build dependencies, preserving fast static/cross-compilation and offline builds.
   - One file per canonical `ApplicationId` avoids write contention across independent applications in a bounded portfolio run.
   - Human-inspectable state simplifies debugging and fixture testing.
2. **Define explicit SQLite migration triggers**:
   - Migrate to a local SQLite database (`<memory_dir>/patrol.db` with WAL mode and schema migrations) when any of the following is required:
     - Indexed cross-application historical queries (e.g. searching all templates or findings across 50+ applications).
     - Retention pruning over hundreds of historical patrol snapshots per application.
     - Concurrent writer processes patrolling the same `ApplicationId` simultaneously.
3. **Keep JSON/JSONL export contracts permanent**:
   - Even after a SQLite backend is adopted, `AuditReport`, `PatrolReport`, and `RegressionReport` remain versioned JSON/JSONL interchange contracts.

## Consequences

- Portfolio patrols can run concurrently across distinct `ApplicationId`s today without introducing C toolchain dependencies.
- Cross-portfolio SQL queries remain unindexed until the SQLite backend is implemented.
