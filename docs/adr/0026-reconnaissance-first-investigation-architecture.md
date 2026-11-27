# 0026. Reconnaissance-First Investigation Architecture

## Status

Accepted — 2026-11-27

## Context

NetzZwergenWacht grew from a single-page auditor into an investigation engine with agentic
reasoning, but the acquisition layer did not grow with it. The consequence is an imbalance:
the product can reason at length about a single `EvidenceSnapshot` while being unable to answer
questions that require the application as a whole, such as "which template produced this defect
on 300 pages" or "which shared script fails on every locale".

A second consequence is dependency. When no model is configured, the agentic path degrades to a
single deterministic audit; if the audited surface is one page, the deterministic result is
correspondingly thin. That makes the product's value depend on an LLM, which inverts the intended
hierarchy.

## Decision

The diagnostic hierarchy is fixed and ordered:

1. Acquisition.
2. Observations.
3. Deterministic diagnostics.
4. Application intelligence.
5. Agentic reasoning.
6. Supported conclusions.

Each layer may only consume the layer below it. A higher layer must never compensate for a
missing lower layer.

Specific consequences of that ordering:

- **A deterministic baseline is mandatory.** Discovery, acquisition, observation extraction and
  the full deterministic rule set run with no model, no network service and no API key. Agentic
  investigation is an optional layer over that baseline.
- **Application-wide is the default scope for application workflows.** Single-page checking
  remains a first-class operation, but it is explicitly a single-page operation, not the whole
  product. Analysis functions that need cross-page evidence must be reachable from a workflow
  that actually acquires multiple pages.
- **Evidence precedes reasoning.** An investigation starts from a reconnaissance summary derived
  from retained evidence. The engine must not ask a model what to look at before it has something
  to look at.
- **Progressive depth.** Depth is selected by reconnaissance findings, not by a fixed pipeline.
  Cheap source-level diagnostics run on every eligible page; expensive instruments run on a
  representative and anomaly-driven sample.
- **Agent independence.** Every deterministic artefact — findings, coverage, systemic
  aggregation, reports, workbench views — must be complete and useful when the agentic layer is
  absent, misconfigured, failing, rate limited or cancelled.
- **Entry conditions.** Application-wide workflows require a validated target, an explicit
  policy, an explicit budget and an explicit scope. When reconnaissance is partial, every
  downstream result states how much of the application was actually observed, and
  application-wide defect rates are not reported from an unqualified sample.

## Alternatives considered

**Keep single-page as the primary unit and treat multi-page as patrol.** Rejected: patrol exists
for change detection across runs, not for first-contact understanding of an application. Using it
as the only multi-page path leaves the investigation engine structurally page-bound.

**Let the agent decide what to acquire.** Rejected: an agent cannot choose to inspect a resource
it has never been told exists, and per-decision acquisition is unbounded and unauditable.

**Require a model for application-wide analysis.** Rejected: it contradicts local-first operation
and makes reproducibility dependent on a third party.

## Consequences

- New acquisition work (Wave TA-1) precedes rule expansion. Adding rules that need resources
  before resources are acquired would produce rules that are skipped rather than wrong, but the
  priority is to acquire the evidence.
- Reports gain a mandatory coverage section. A finding without a stated inspected population is
  incomplete.
- The agentic investigation entry point gains a deterministic precondition: reconnaissance must
  have produced a summary, and the summary must carry explicit gaps.
- ADR 0016 (measurement honesty) and ADRs 0017–0021 remain in force without modification.
