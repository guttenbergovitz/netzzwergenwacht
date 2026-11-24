# Verified Defect and Risk Register

Every entry below was verified directly against the current `rewrite/rust` codebase before being logged.

| # | Defect / Risk | Verified Location | Severity | Validation / Remediation Criteria |
|---|---|---|---|---|
| 1 | **Chromium runs with `--no-sandbox`** | `src/adapters/lighthouse.rs:29`, `src/adapters/browser.rs:42` | **Blocking** | Evaluate OS-appropriate Chromium sandboxing / isolated container profile; remove unconditional `--no-sandbox` or gate behind an explicit unsafe flag with clear warning. |
| 2 | **Browser/external tools bypass `TargetPolicy` network rules** | `src/adapters/{lighthouse,browser,axe}.rs` | **Blocking** | Enforce SSRF/private-IP/origin boundaries on browser navigation and subresource requests (e.g., proxy/CDP request interception), matching `collection.rs`. |
| 3 | **False historical resolutions when checks are skipped/failed** | `src/persistence.rs` (`diff_reports`) | **Resolved** | `diff_reports` now classifies missing baseline findings as `unverified_findings` whenever the corresponding rule is `Skipped`/`Unavailable` in `current` (tested). |
| 4 | **Volatile fingerprints & missing page-level scope** | `src/analysis/mod.rs:131`, `src/domain.rs` | **High Priority** | Fingerprints must hash stable rule + target/page identity without volatile latency/count prose, so latency drift does not create fake `New` + `Resolved` churn. |
| 5 | **Unbounded subprocess stdout/stderr & incomplete tree kill** | `src/adapters/mod.rs` (`run_bounded_command`) | **Partially Resolved** | stdout/stderr streams are now capped at 16 MiB via `AsyncReadExt::take`; full process-group termination (`killpg`) remains planned. |
| 6 | **Independent per-collector timeouts instead of shared budget** | `src/main.rs:297-311` | **High Priority** | Replace independent `budget.audit_timeout` calls per adapter with a shared `BudgetLedger` tracking remaining wall-clock time and request caps (`run_investigation` already uses `remaining_duration`). |
| 7 | **Quality gates ignore failed/skipped required collectors** | `src/config.rs` (`evaluate_policy`) | **Partially Resolved** | `evaluate_policy` now flags `Failed`, `Skipped`, and `Partial` HTTP outcomes; required Level 2 collector gating remains planned. |
| 8 | **Secret-bearing `Debug` on LLM provider** | `src/intelligence/mod.rs` (`OpenAiCompatibleProvider`) | **Resolved** | Custom `fmt::Debug` redacts `api_key` as `"[REDACTED]"`. |
| 9 | **Unbounded LLM response body & unvalidated AI rule refs** | `src/intelligence/mod.rs` | **Resolved** | LLM response body is stream-capped at 1 MiB and `related_rules` are validated against `AuditReport` rule IDs (`(unverified)` suffix). |
| 10 | **Prompt truncation can produce malformed JSON** | `src/intelligence/mod.rs` (`build_sanitised_prompt`) | **Resolved** | Finding count and field lengths are bounded before JSON serialisation; serialised JSON is never truncated mid-object. |
| 11 | **AI synthesis absent from structured JSON output** | `src/main.rs:330-350` | **Planned** | Include optional `AiSynthesis` / `InvestigationReport` in versioned JSON output when `--ai` or `investigate` is used. |
| 12 | **Browser partial load & fallback semantics** | `src/adapters/browser.rs` (CDP `setTimeout(resolve, 15000)` on load) | **Planned** | Mark timed-out `Page.loadEventFired` explicitly as `CollectorOutcome::Partial` with warning rather than `Captured`. |
| 13 | **Incomplete measurement provenance** | `src/domain.rs` (`LighthouseMetrics`, `BrowserEvidence`) | **Planned** | Record viewport, throttling profile, lab/field origin, and capture timestamp alongside metrics. |
| 14 | **Batch concurrency & backpressure** | `src/collection.rs:88` (`collect_batch`) | **Accepted Limitation** | `collect_batch` bounds HTTP concurrency via `Semaphore`, but has not yet been stress-tested with Level 2 browser sessions or large target lists. |
