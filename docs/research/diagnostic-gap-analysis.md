# Diagnostic Gap Analysis

Derived from `rule-equivalence-mapping.json` (SquirrelScan pinned at
`a536c5282220784343c9cb3213b8f29d16f8b47b`, 2026-11-27) and the verified assessment in
`.specs/operation-tiefenaufklaerung-assessment.md`.

The purpose of this document is to decide **what to build next and why**, not to maximise the
rule count. A gap is only actionable if the observation it needs can be acquired honestly.

## Gap classification

| Class | Meaning | Typical remedy |
| --- | --- | --- |
| `missing_observation_producer` | The signal is never acquired | New collector, usually in the browser harness or a resource fetcher |
| `missing_deterministic_rule` | The signal is acquired but unexamined | Rule on an existing snapshot |
| `missing_application_wide_aggregation` | Only single-page analysis exists | Cross-page analytics over the evidence store |
| `missing_resource_inspection` | Scripts, stylesheets, images and fonts are never fetched | Shared resource acquisition |
| `missing_execution_scope` | No origin, template, locale or portfolio scope | Rule engine scope model |
| `insufficient_acquisition_coverage` | The crawler fetches too few pages or sequentially | Concurrent crawl engine |
| `insufficient_diagnostic_depth` | Browser evidence is captured only on demand | Adaptive sampling |
| `weak_heuristic` | The check exists but its confidence is unstated | Confidence and methodology metadata |
| `unsupported_external_dependency` | Requires cloud data or an external service | Defer or reject |

## Verified position at the start of the operation

- `crawl_and_cluster` in `src/discovery/mod.rs` is a strictly sequential BFS: one
  `collect_http(…).await` per dequeued URL, no worker pool, no per-origin limit, no shared
  client, no in-flight deduplication.
- No resource is ever fetched. `perf`, `images` and part of `security` therefore cannot operate
  at all: there is no script, stylesheet, image or font body to inspect.
- `robots.txt` and sitemaps are read only to seed URLs; directives are not parsed into rules.
- Findings are per page. `SystemicIssue` clusters exist but are derived from repeated rule ids,
  not from a template or resource model, so remediation leverage cannot be reported.
- Persistence is append-only JSONL of `AuditReport`. Nothing is queryable across runs beyond
  `diff_reports`.
- 235 rules exist (verified by counting `RULE_*` constants). 25 have an automated candidate
  match against SquirrelScan; 339 are unmapped, which mostly reflects naming distance rather
  than genuine absence.

## Priority 1 — architectural gaps that block many rules at once

These are ordered by how many downstream capabilities they unlock per unit of work.

### 1. Sequential acquisition

One page at a time bounds an application audit to roughly one request per round trip. A 500-page
application takes minutes and is therefore rarely done. Everything application-wide — duplicate
metadata, template defects, locale coverage, orphan detection, systemic aggregation — is starved
by this, not by a missing rule.

Remedy: bounded worker pool, deduplicated frontier, per-origin limit, global deadline, explicit
partial completion. Wave TA-1.

### 2. No resource acquisition

Roughly 70 SquirrelScan rules across `perf`, `images`, `security` and `reliability` operate on
resource bodies or resource headers. NetzZwergenWacht measures only the HTML document and the
resources the browser happened to report. Shared scripts, stylesheets, images and fonts are
never inspected, deduplicated or attributed.

Remedy: resource acquisition keyed by representation identity, analysed once per compatible
variant, with page-to-resource relationships. Waves TA-1 and TA-2.

### 3. No application-wide evidence store

Every analysis is recomputed from a single snapshot. There is no place to put "the same stylesheet
is referenced by 312 pages", no history to query, and no way to re-run a rule without refetching.

Remedy: local evidence store with typed observation identity, provenance and retention. Wave TA-2.

### 4. No template, locale or route-family model

`PageType` exists. Templates, locale families and route families do not, so a defect repeated
across a template is reported as N unrelated page findings. This is the difference between a
finding list and a diagnosis.

Remedy: application topology graph with observed and inferred relationships, plus systemic
aggregation. Wave TA-4.

### 5. Coverage is not a first-class output

The crawler records `PageCrawlStatus`, but nothing aggregates discovered versus eligible versus
fetched versus analysed, and no report qualifies a percentage by its denominator.

Remedy: coverage accounting by origin, locale, template, route family and diagnostic domain.
Wave TA-1, surfaced later in reports and the workbench.

## Priority 2 — deterministic rules over evidence that is already acquired

These are cheap and honest once the snapshot contains the signal. They are grouped by domain
rather than listed individually; the per-rule detail lives in the mapping JSON.

| Domain | Representative gaps | Evidence already captured | Gap class |
| --- | --- | --- | --- |
| `core` | doctype, charset declaration consistency, favicon presence, canonical form drift | HTML source, headers | `missing_deterministic_rule` |
| `url` | length, case, underscore versus hyphen, session identifiers in path, parameter conventions | URL set from the crawl | `missing_deterministic_rule` |
| `mobile` | viewport meta correctness, font-size floor, horizontal scroll, tap-target size | HTML source, geometry inventory | `missing_deterministic_rule` |
| `reliability` | broken internal links, broken forms, JS error concentration | link graph, browser console events | `missing_application_wide_aggregation` |
| `social` | Open Graph completeness and image size, `og:url` agreement with canonical | HTML source, resource sizes | `missing_deterministic_rule` |
| `a11y` | ARIA allowed attributes, required parent/child, valid attribute values, label-in-name | HTML source | `missing_deterministic_rule` |
| `i18n` | hreflang reciprocity, target validity, locale mixing | link graph, hreflang declarations | `missing_application_wide_aggregation` |
| `blocking` | ad-blocked or privacy-blocked third-party endpoints | third-party inventory | `missing_deterministic_rule` |

## Priority 3 — requires application-wide computation

| Capability | Why it cannot be a page rule | Wave |
| --- | --- | --- |
| Duplicate and near-duplicate content clusters | Needs pairwise comparison with an index, not a document | TA-4 |
| Duplicate title and description distribution | Needs the whole page set and a frequency model | TA-4 |
| Canonical chains, loops and conflicts | Needs the redirect and canonical graph | TA-3 |
| Orphan candidates and click depth | Needs the discovered internal link graph | TA-3 |
| Template-wide metadata defects | Needs template families | TA-4 |
| Systemic finding aggregation with remediation leverage | Needs resource and template relationships | TA-4 |
| Locale coverage and missing equivalents | Needs locale families | TA-4 |
| Business entity consistency across representations | Needs typed entity extraction plus comparison | TA-4 |

## Priority 4 — requires deeper acquisition, therefore adaptive

| Capability | Cost | Why it is adaptive |
| --- | --- | --- |
| Rendered versus source content differences | One browser navigation | Sample representative templates |
| Runtime errors and failed requests per resource | Browser | Sample pages that reference the suspect resource |
| LCP/CLS/long tasks | Browser | Laboratory measurement on representative pages only |
| Accessibility tree and geometry | Browser | Sample per template, plus anomaly-driven pages |
| Service worker and storage observations | Browser | Once per origin plus sampled pages |

## Explicitly deferred

- INP and Event Timing, Long Animation Frames, main-thread attribution breakdown: require
  interaction instrumentation that is not yet safe to automate.
- CrUX and any field telemetry: requires an external service; contradicts local-first operation.
- WebSocket, Server-Sent Events and frame lifecycle timelines: no evidence producer yet.
- Multi-engine rendering comparison: operator burden disproportionate to current value.
- Full certificate chain validation and OCSP: requires trust-store and network policy decisions
  not yet taken.

## Explicitly rejected

Rejections are recorded so that future reviewers do not reopen them as oversights.

| Capability | Reason for rejection |
| --- | --- |
| `integrity/*` threat intelligence (known malicious URL, phishing kit signatures, brand impersonation) | Depends on cloud reputation feeds. A local engine without those feeds cannot produce the observation, and inventing one would be dishonest. |
| `gaps/*` keyword and content-gap analysis | Requires search-volume data from an external service. |
| `eeat/*` authority scoring | Trustworthiness cannot be reduced to a deterministic checklist. Signals may be reported as observations, never as a score. |
| `legal/*` sufficiency of privacy policy or cookie consent | Legal sufficiency is a judgement, not an observable. Presence and linkage may be observed; compliance may not be claimed. |
| Competitive rule-count parity | The target is diagnostic coverage, not a count. Rules that duplicate one condition under several names are not expansion. |

## Method for claiming a gap is closed

A gap moves to `closed` only when all of the following hold:

1. An observation producer exists and is regression-tested against a controlled fixture.
2. A deterministic rule consumes it and distinguishes defect, clean control, ambiguity,
   missing prerequisite and partial observation.
3. The rule declares its scope, severity, confidence and methodology.
4. The Evidence Query Engine can return the observation offline.
5. The workbench renders the unavailable, partial and failed states distinctly.

Anything less is recorded as `partial`, with the missing step named.
