# Competitive Capability Matrix

This document records what another auditing tool actually checks, so that NetzZwergenWacht
expansions are driven by verified capability gaps rather than by advertised rule counts.

It is a research artefact. The machine-readable inventories sit next to it:

| File | Content |
| --- | --- |
| `squirrelscan-rule-inventory.json` | Every rule id statically declared by SquirrelScan at the pinned commit, with description, scope, severity and WCAG mapping where declared. |
| `nzw-rule-inventory.json` | Every `RULE_*` constant in `src/analysis`, with its module and family prefix. |
| `rule-equivalence-mapping.json` | Per-rule mapping attempt with an explicit equivalence status. |
| `diagnostic-gap-analysis.md` | Gap classification and implementation priority. |

## Pinned comparison target

| Field | Value |
| --- | --- |
| Project | `squirrelscan/squirrelscan` |
| Licence | MIT |
| Pinned commit | `a536c5282220784343c9cb3213b8f29d16f8b47b` |
| Pinned commit date | 2026-11-27T02:24:41Z |
| Research date | 2026-11-27 |
| Language | TypeScript (Node.js CLI, package `apps/cli`, rules in `packages/rules`) |
| Statically declared native rules | 364 |
| Documented rule pages | 395 |
| Categories declared | 26 |

The difference between 364 and 395 is not an error. The pinned commit also documents rule
packs whose identifiers are produced dynamically or shipped as plugins (ad-blocking, AI
readiness, agent surfaces, cloud-only performance rules). Only the 364 statically declared
identifiers are used for equivalence work, because those are the ones whose implementation can
be read.

### Extraction method

`packages/rules/src/**/*.ts` was read at the pinned commit and every `meta: { … }` block was
parsed for `id`, `name`, `description`, `category`, `scope`, `findingScope`, `verdictScope`,
`severity`, `weight` and `wcag`. Descriptions are quoted from the source, not from marketing
pages. Nothing was inferred from a category name.

### Deliberate limits of this comparison

- No SquirrelScan code is copied. It is MIT-licensed, so behavioural comparison and independent
  reimplementation are permitted, but NetzZwergenWacht gains its own observation producers and
  its own rule logic.
- SquirrelScan rules are hand-written DOM checks. Several categories are heuristics that this
  project will not reproduce where the underlying signal cannot be observed honestly (see the
  rejected capabilities in the gap analysis).
- Cloud-only capabilities are out of scope for a local-first product and are recorded as such
  rather than treated as gaps.

## Category coverage at a glance

Counts are SquirrelScan rules per category at the pinned commit, and how many currently have an
automated candidate match in the NetzZwergenWacht inventory. `candidate` means an automated
token match that has **not** yet been reviewed by a human; it is not a claim of equivalence.

| Category | SquirrelScan | NZW candidates | Dominant gap class |
| --- | --- | --- | --- |
| `a11y` | 63 | 3 | Missing deterministic rules (ARIA reference and value validation) |
| `content` | 36 | 5 | Missing observation producer (article metadata, copy anomalies) |
| `security` | 35 | 7 | Missing deterministic rules and cross-page aggregation |
| `perf` | 32 | 3 | Missing resource inspection (no script/CSS/image fetch) |
| `crawl` | 27 | 1 | Missing crawl model (sitemaps, canonical chains, 404 handling) |
| `schema` | 26 | 1 | Missing entity validation profiles |
| `ax` | 21 | 0 | Missing observation producer (agent-facing surfaces) |
| `links` | 18 | 2 | Missing application-wide link graph |
| `images` | 16 | 3 | Missing resource inspection |
| `eeat` | 15 | 0 | Partly rejected: several checks are editorial judgement |
| `core` | 14 | 0 | Missing deterministic rules (doctype, charset, favicon) |
| `integrity` | 10 | 0 | Rejected: threat-intelligence data is not local-first |
| `url` | 10 | 0 | Missing deterministic rules (cheap to add) |
| `mobile` | 8 | 0 | Missing deterministic rules |
| `reliability` | 6 | 0 | Missing deterministic rules |
| `social` | 5 | 0 | Missing deterministic rules |
| `i18n` | 4 | 0 | Missing application-wide locale model |
| `legal` | 4 | 0 | Partly rejected: legal sufficiency is not observable |
| `blocking` | 3 | 0 | Missing deterministic rules |
| `analytics` | 3 | 0 | Missing deterministic rules |
| `local` | 3 | 0 | Missing deterministic rules |
| `video` | 3 | 0 | Missing deterministic rules |
| `gaps` | 2 | 0 | Cloud-only keyword data; rejected |

The single most important line in that table is `perf`, `images`, `crawl` and `links`: those
categories assume the auditing tool fetches resources and walks the application. NetzZwergenWacht
currently does neither, so the gap there is architectural rather than a list of missing checks.

## Per-capability mapping fields

Every entry in `rule-equivalence-mapping.json` records the fields required by the directive:

| Field | Source |
| --- | --- |
| `external_identifier` | Rule id at the pinned commit |
| `domain` | SquirrelScan category |
| `description` | SquirrelScan rule description, quoted |
| `severity_external` | Declared severity |
| `execution_scope_external` | Declared `scope` |
| `wcag` | Declared WCAG criteria |
| `nzw_equivalent` | Closest NetworkZwergenWacht rule id, or `null` |
| `equivalence` | `review_candidate` or `unmapped` |
| `match_score` | Automated token overlap used to propose a candidate |
| `local_availability` | All compared rules are local for both tools |
| `implementation_strategy` | `verify_and_extend` or `assess` |
| `validation_requirements` | Fixture obligations required before the rule is claimed |
| `licence_consideration` | MIT comparison note |

`equivalence` deliberately has no `exact` value yet. Marking a rule exact requires reading both
implementations and demonstrating the same observation, which is work for Wave TA-3, not for the
inventory pass.

## Supporting references

The following tools inform methodology only. None is a dependency.

| Tool | What is taken from it |
| --- | --- |
| Lighthouse | Performance metric definitions and the practice of separating laboratory from field data |
| axe-core | Accessible-name computation and ARIA parent/child requirements |
| Nu HTML Checker | Document conformance: relying on a maintained parser instead of a partial native validator |
| Sitebulb | Crawl frontier modelling, orphan and depth analysis |
| Screaming Frog | Sitemap, redirect and canonical chain handling |
| Pa11y | Accessibility rule reporting shape |
| WebPageTest | Waterfall and phase timing attribution |
| sitespeed.io | Resource-level budget thinking |
| testssl.sh | TLS and certificate diagnostic depth |

## Maintenance

The inventory is regenerated from a pinned commit, never from memory. When the comparison target
moves, record a new commit, a new date, and a new diff rather than overwriting the previous
figures, so that coverage claims stay auditable.
