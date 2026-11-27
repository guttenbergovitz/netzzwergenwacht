# 0031. Progressive Diagnostic Depth

## Status

Accepted — 2026-11-27

## Context

Browser instrumentation is expensive: process launch, navigation, network, scripting and
teardown. Applying it to every page of a 500-page application would dominate wall time and would
make the product unusable for routine checks. Applying it to the seed page only produces an
unrepresentative sample that is routinely reported as if it described the application.

Between those two extremes there is no selection logic today.

## Decision

Depth is a property of a selected page set, decided by deterministic evidence.

### Execution profiles

Profiles are acquisition policies, not editions. Every profile runs the same deterministic engine;
they differ in what they acquire and how far they go.

| Profile | Acquisition |
| --- | --- |
| Reconnaissance | Discovery and source-level observations; no browser, bounded page count |
| Standard | Reconnaissance plus full page and resource inspection, deterministic rules only |
| Deep | Standard plus browser and specialist instruments on a selected sample |
| Investigation | Deep evidence plus optional agentic follow-up with additional authorised acquisition |
| Patrol | Repeated observation against retained history for change detection |

Single-page `check` remains a lightweight operation. No profile silently turns a single-page check
into an application crawl.

### Sampling

Two independent samples, reported separately:

1. **Representative sample.** Stratified by template family, locale, route family and page type,
   so that any defect rate derived from it describes the application rather than the sample.
2. **Anomaly-driven sample.** Pages selected because evidence suggests something unusual: unusual
   resource profile, runtime-sensitive pattern, security anomaly, accessibility signal, content
   inconsistency, or a change since the previous run.

A rate computed only from suspicious pages is never presented as an application-wide rate. The
report states which sample produced which conclusion.

### Instrument reuse

- One browser session serves multiple evidence families for one navigation.
- Browser concurrency is separately bounded and lower than HTTP concurrency.
- A compatible retained browser capture is reused instead of repeating the navigation.
- Session state is never shared across incompatible application contexts: locale, consent context
  and authentication state are part of capture identity.

### Cost accounting

Escalation is cost-aware. Each instrument declares an approximate cost class, and the scheduler
spends the deep budget on the pages that maximise diagnostic value per unit cost. When the budget
is exhausted, remaining pages are recorded as not deeply inspected, not as passing.

## Alternatives considered

**Browser on every page.** Rejected on cost and on politeness; it also multiplies any
side-effecting probe across the application.

**Browser on the seed page only.** Rejected as unrepresentative. It is the current de facto
behaviour and the reason application-wide browser claims are not made.

**Agent-selected sampling.** Rejected as the primary mechanism: it is unauditable, irreproducible
and depends on a model. Agents may request additional targeted acquisition inside an authorised
follow-up budget, but they do not define the baseline sample.

**Fixed sample size.** Rejected: it ignores stratification. Ten pages from one template are not a
sample of the application.

## Consequences

- Coverage report separates representative from anomaly-driven inspection.
- Browser findings carry the sample identity that produced them.
- Probe safety policy from ADR 0018 applies to every selected page without exception.
- `Coordination` with ADR 0027: the deep phase runs after the crawl frontier has produced enough
  evidence to stratify, not concurrently with discovery.
