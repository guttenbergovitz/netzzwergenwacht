# 0029. Diagnostic Rule Execution and Taxonomy

## Status

Accepted — 2026-11-27

## Context

Rules today are functions inside analyser modules: 235 `RULE_*` constants, each consumed by a
per-dwarf analyser invoked as `analysis::run_all(&snapshot)`. That shape works while every rule
reads one page snapshot. It does not survive the arrival of resource, origin, template, locale and
application scopes, because a rule then needs a different input than "this page".

Adding a new analyser per scope would duplicate registration, budget handling and reporting, and
would make it impossible to ask which rules could not run and why.

## Decision

Keep rules as ordinary Rust functions. Add a registration contract around them, not a DSL.

### Rule contract

Every rule declares, through its registration rather than through prose:

- stable identifier;
- diagnostic domain and owning dwarf;
- execution scope: element, page, resource, origin, application, template family, locale family,
  historical comparison, portfolio;
- evidence prerequisites: the typed observations it reads;
- observation dependencies that must be complete for a definitive verdict;
- methodology and confidence policy (measured, derived, heuristic, inferred);
- severity policy;
- applicability criteria (when the rule is not applicable rather than merely skipped);
- remediation guidance;
- rule version.

### Execution

- **Eligibility first.** A rule whose prerequisites are absent is not executed and produces
  `Unavailable` or `NotApplicable` with a reason. It never produces `Passed`.
- **Partial evidence produces qualified results.** Where the rule can conclude something from
  partial evidence, it does so and marks the result bounded, naming what was not observed.
- **Scopes are data.** The engine resolves a scope to an evidence selection, then runs matching
  rules over it. A page-scoped rule over a 500-page application runs 500 times because the
  selection is 500 pages, not because of special-casing.
- **Shared producers.** Observation extraction is separate from rule evaluation. One parsed
  document, one resource body and one browser session serve every rule in their scope.
- **Re-evaluation without acquisition.** When retained evidence satisfies the prerequisites, the
  rule runs from the store. A rule's own version and the collector version both participate in
  deciding whether retained evidence is acceptable.
- **External instruments are separate.** axe-core, Lighthouse and Nu results are stored as their
  own observations with their own provenance and are normalised only at presentation, never
  merged into a native rule's identity.

### Completeness

`CheckStatus` already distinguishes passed, failed, skipped and unavailable. The extension needed
is per-rule completeness metadata: inspected population, excluded population and the reason for
each exclusion. This is what makes a rule's silence interpretable.

## Alternatives considered

**A rule DSL with declarative selectors and expressions.** Rejected: the honest rules need real
computation (accessible-name resolution, canonical chains, statistical aggregation). A DSL would
cover the trivial third and become an obstacle for the rest.

**One analyser per rule.** Rejected: registration, dwarf attribution, budget accounting and
report ordering would be duplicated 400 times.

**Merge external instrument findings into native rule ids.** Rejected: it destroys provenance and
makes duplicate reports indistinguishable from corroboration.

**Add `Passed` for rules whose prerequisites were missing.** Rejected: it is the exact dishonesty
ADR 0016 forbids. Absence of evidence is not a pass.

## Consequences

- `AnalyserResult` gains per-check completeness and methodology where currently absent.
- The rule registry becomes the single place to answer "what does this product check, at which
  scope, with which evidence".
- The diagnostic validation matrix can be generated from the registry instead of maintained by
  hand.
- Rule count stops being a headline number; scope and evidence coverage become the reported
  measures.
