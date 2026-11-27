# ADR 0033: Turso Database as the Embedded Evidence Store

## Status

Accepted — 2026-11-27.

Amends ADR 0032, which selected SQLite through `rusqlite`. ADR 0032's status
changes to *Amended by ADR 0033*; its conceptual reasoning about durability,
bounded memory and selective queries still holds. ADR 0028 remains authoritative
for the data model, cache layers and retention rules.

## Context

ADR 0032 accepted a single-writer architecture: one writer at a time, WAL for
concurrent readers, and a crawl that writes once per phase rather than once per
page. That was a consequence of the engine, not a requirement of the product.

The reconnaissance engine changes the shape of the workload. Page workers,
resource workers and browser workers finish independently and at different times.
Serialising their evidence behind one writer turns independent acquisition into a
queue at the persistence boundary, and the queue grows exactly when the crawl is
doing well.

Turso Database (formerly Limbo) is the Rust reimplementation of SQLite. Its MVCC
mode permits several connections to write concurrently, with conflicts detected at
commit time rather than by holding an exclusive lock. That is the property the
architecture needs, so the amendment asks whether the engine is mature enough to
carry it.

The amendment also inherits a risk: Turso is pre-1.0 and its MVCC path is young.
The adoption gate is therefore evidence-based, not declarative.

## Pinned release

`turso = 0.9.0-pre.6` (crates.io, MIT, published 2026-11), used with
`default-features = false`. It builds offline from the local cargo cache, with
`turso_core` and `turso_sdk_kit` as transitive dependencies. `rusqlite` remains a
dev-dependency only, as the comparison baseline the amendment requires.

The API is asynchronous: `Builder::new_local(path).build().await`, `db.connect()`,
`conn.execute(sql, params).await`, `conn.query(sql, params).await`. MVCC is
enabled with `PRAGMA journal_mode = 'mvcc'` and used with `BEGIN CONCURRENT` /
`COMMIT` / `ROLLBACK`.

## Verification

`tests/evidence_store_spike.rs` now contains a Turso experiment alongside the
existing SQLite/JSONL comparison. It runs eight independent writers, a contended
counter, a reader during writes, an abandoned transaction, a reopen, an aggregate
comparison against a value computed in Rust, a `user_version` migration, and
foreign-key enforcement. Measured on one Apple silicon machine, release profile,
2026-11-27:

| Property | Observed |
| --- | --- |
| `PRAGMA journal_mode = 'mvcc'` | reports `mvcc` |
| 8 writers x 500 disjoint rows | 4 000 rows in 74 ms, 0 retries, 4 000 committed |
| 8 writers x 20 increments on one row | 160 commits, **999 retries**, final value 160 |
| Reader during writes | sees the committed count |
| Duplicate insert by stable identity | rejected, row count unchanged |
| Failing statement inside a transaction | rollback leaves no partial evidence |
| Connection dropped without commit | row absent after reopen; file reopens in `mvcc` |
| `PRAGMA user_version` | settable and readable (migration surface exists) |
| Orphan row with `PRAGMA foreign_keys = ON` | rejected |
| Analytical `GROUP BY` | equals the Rust-computed expectation |
| SQLite baseline, same 4 000 rows batched | 1–2 ms |

Interpretation, stated plainly:

- Concurrent writes over **disjoint identities** commit without conflicts and
  without loss. This is the common reconnaissance case, because observations are
  keyed by page or resource identity.
- Contention on a **single hot row** is expensive: 999 retries for 160 successful
  increments, roughly six attempts per commit. No update was lost, which is the
  correctness property that matters, but a design that keeps a shared mutable
  counter in the database would spend most of its time retrying. The schema must
  avoid hot rows rather than rely on MVCC to make them cheap.
- Turso is **not** faster than SQLite for batched single-writer inserts: 74 ms
  against 1–2 ms for the same population. The amendment is adopted for concurrent
  write capability, not for throughput.

## Decision

Adopt Turso Database through the native Rust SDK as the embedded application-wide
evidence store, in MVCC mode.

Required properties of the integration:

- **Isolation.** All engine-specific code stays inside `evidence_store`; the rest
  of the crate sees typed Rust interfaces, never SQL strings.
- **Independent connections.** Each persistence worker opens its own connection;
  no connection is shared across tasks.
- **Bounded write concurrency.** Database write concurrency is a configured bound
  independent of crawl concurrency, so persistence cannot outrun acquisition.
- **Short transactions.** A transaction covers one evidence batch. Long
  transactions lengthen the conflict window for every other writer.
- **Bounded retries.** Retryable conflicts (`Busy`, `BusySnapshot`, error text
  containing `conflict`) are retried with backoff under a budget; exhaustion is a
  recorded persistence failure, never a successful collection outcome.
- **Idempotent identity.** Writes use stable observation identities and
  `ON CONFLICT ... DO NOTHING`, so a retried batch cannot duplicate evidence.
- **No hot rows.** Coverage is derived from stored observations and computed on
  read; shared mutable counters are not persisted per write.
- **A finding never references uncommitted evidence.** Findings are written in the
  same transaction as the observations they cite, or after those observations are
  committed.

## Adoption gate outcome

Passed, with recorded limitations:

- The engine is a **pre-release** (`0.9.0-pre.6`). Upgrades must be pinned
  deliberately and re-run the spike.
- MVCC reduces lock contention; it does not remove it. The contended-row
  measurement is evidence of that.
- The database file format is the engine's, not SQLite's WAL. Existing SQLite
  files are not assumed to open. The comparison baseline is experimental only.

If a future engine release fails the spike — lost commits, unrecovered files,
silently ignored constraints — adoption stops and the fallback in ADR 0028
(typed append-only segments with an in-memory index) applies. The fallback stays
documented rather than implemented.

## Rejected alternatives

- **Single-writer SQLite (ADR 0032 as accepted).** Correct but serialises
  independent workers at the persistence boundary, which is the bottleneck the
  reconnaissance engine is designed to remove.
- **Turso with WAL instead of MVCC.** Would satisfy the API but not the
  requirement; claiming concurrent writes while using a single-writer journal is
  exactly the substitution the amendment forbids.
- **Turso Cloud, remote libSQL or sync services.** Violates local-first operation.
- **Two production backends.** Doubles the schema, migration and testing surface
  for no diagnostic benefit. SQLite is retained only in the ignored spike as a
  baseline.

## Consequences

- `Cargo.lock` gains the Turso engine and its SQLite-compatible parser. Both
  crates are development/build dependencies until `evidence_store` lands, so the
  library does not carry an engine nothing uses.
- Persistence errors are first-class: a crawl reports *what was committed*. A
  transaction that never committed contributes no findings and no coverage.
- The `schema_version` obligation from ADR 0032 is unchanged: forward-only
  migrations, and refusal to open a database written by a newer schema.
- The spike is an ignored test that must be re-run on every engine upgrade, and
  its assertions are correctness assertions, not performance ones.
