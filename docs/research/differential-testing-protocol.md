# Differential Testing Protocol

Protocol for comparing NetzZwergenWacht deterministic rule outputs against SquirrelScan and independent ground truth.

## Objectives

- Verify behavioural compatibility where NZW adapts an upstream diagnostic capability.
- Prevent false positives and false negatives when porting thresholds and applicability rules.
- Never treat SquirrelScan as an infallible oracle; ground truth is maintained independently in fixtures.

## Execution Model

1. **Controlled Inputs:** Serve deterministic HTML/HTTP fixtures via local loopback servers or static `EvidenceSnapshot` builders in `tests/` (Zwergenprüfstand).
2. **Normalisation:** Map NZW `RuleId`s to upstream `category/rule` IDs via `docs/research/diagnostic-capability-mapping.json`. Compare `Passed` vs `clean`, `Failed` vs `problem`, `Skipped` vs `skipped`, and severity buckets.
3. **Discrepancy Classification:**
   - `nzw_defect` — NZW misses a valid defect or triggers a false positive.
   - `upstream_defect` — Upstream rule is overly rigid, buggy, or ignores edge cases; document and keep NZW's improvement.
   - `intentional_divergence` — Deliberate NZW policy difference (e.g., strict `EvidenceLevel` separation or non-zero-coercion).
   - `different_scope` — One tool requires rendered DOM or multi-page crawl while the other evaluates single-page source.
