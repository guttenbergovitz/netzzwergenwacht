# 0018. Browser interaction safety and causal attribution

## Status

Accepted

## Context

The behavioural probe clicks disclosure controls and compares resource and runtime error
counters immediately before and after the click. That synchronous comparison cannot
observe behaviour scheduled through promises, timers, microtasks, fetches, navigation or
framework render loops, and it cannot prove that the interaction caused anything that
was observed. Native disclosure controls can also run application-defined handlers with
side effects, so semantic classification does not establish safety.

## Decision

1. **Passive acquisition is the default.** The collector observes the rendered page,
   focus traversal and browser-local state without dispatching application events.
2. **Active probes require an explicit policy.** A probe runs only when the current
   policy permits it, and only against a bounded candidate set. The permitted default
   class is a native `details > summary` disclosure control that is not inside a form or
   link and does not carry an application-defined ARIA toggle role.
3. **Network isolation is preferred over semantic assumptions.** During a probe, newly
   initiated requests are blocked where the browser protocol allows it, and the outcome
   is classified as a restricted behavioural probe rather than a full journey. Where
   blocking would invalidate the interpretation, the limitation is recorded instead of
   silently proceeding.
4. **Probes run inside an explicit observation window.** The sequence is: establish the
   boundary, record the baseline, execute the action, wait for a bounded window that
   includes microtasks and timers, record the resulting state, then attempt local state
   restoration. The window duration, termination reason and completeness are recorded.
5. **Attribution language reflects evidence strength.** Results are reported as
   "requests observed during the interaction window", "runtime errors observed during
   the interaction window" and "state changes associated with the interaction". Causal
   claims require stronger evidence than temporal co-occurrence.
6. **Zero activity requires a valid window.** A measured zero is reported only when the
   instrumentation was installed, the window was established, event collection stayed
   operational and the window terminated normally. Otherwise the counts remain absent.
7. **Restoration is best-effort and recorded.** Restoring a DOM attribute does not
   necessarily reverse application-side effects. The probe records whether restoration
   succeeded, and a failed restoration is surfaced rather than hidden.

## Consequences

- The trace becomes asynchronous, so the collector needs a bounded wait budget and must
  preserve partial observations when the budget expires.
- Some applications will show fewer behavioural observations, which is the intended
  trade-off: an honest restricted probe instead of a misleading journey claim.
- Active interaction beyond native disclosure controls is deferred until stronger
  isolation guarantees exist.
