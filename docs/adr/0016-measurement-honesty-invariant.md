# 0016. Measurement Honesty Invariant for Observation Producers

## Status

Accepted

## Context

Operation Aufrüstung IV expanded the sensory surface substantially, but several
observations were emitted with placeholder values: FCP copied into the LCP field,
`total_cls_milli: 0`, `new_runtime_errors: 0`, `triggered_requests: 0`,
`observed_before_consent: true`, desktop control counts reused for mobile, and an
unqueried DNS CAA result. Those values are indistinguishable downstream from genuine
zero measurements, which violates the project's evidence-first principle and can
silently turn absence of evidence into apparent success.

Reviewing producers case by case had already failed once. A single system-wide
invariant is required so future collectors cannot reintroduce the same class of defect.

## Decision

1. **Absolute invariant**:
   > Every reported measurement must be traceable to an actual observation. Missing
   > evidence must never be represented as `0`, `false`, an empty collection, or an
   > inferred success.
2. **Type-driven absence**: an unobserved value is encoded as `Option::None` (or an
   explicit availability flag) in the domain contract, never as a zero default. Applied
   in this decision to `total_cls_milli`, `blocking_transfer_bytes`,
   `observed_before_consent`, and the responsive control counts.
3. **Source fidelity**: a field may only be populated from the observation it names.
   LCP render time comes from the `largest-contentful-paint` entry, CLS from
   `layout-shift` entries, interaction error and request deltas from listeners installed
   before the probe, and CAA from a bounded DNS-over-HTTPS query whose success is
   recorded separately from an empty answer.
4. **Interaction safety**: bounded interaction probes act only on native
   `details > summary` disclosure controls, never on links, form controls, submit
   buttons, or application-defined ARIA toggles whose handlers can have side effects.
5. **Verification**: the live Chromium suite runs as a required CI job, so sensory
   collectors cannot regress to placeholder values while the default `cargo test`
   silently ignores them.

## Consequences

- Consumers must handle `None` explicitly; the TUI renders `unobserved` rather than
  `0`, and offline queries keep their `Unavailable` status distinct from an empty page.
- Adding a new observation requires deciding its absence representation before it is
  serialised.
- The live suite adds CI time and depends on a headless Chromium installation, which is
  accepted as the cost of testing real browser behaviour.
