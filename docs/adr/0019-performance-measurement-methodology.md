# 0019. Performance measurement methodology

## Status

Accepted

## Context

Laboratory browser observations were previously reported as if they were one coherent
performance measurement: FCP was copied into the LCP field, CLS was the arithmetic sum
of every layout shift in the session, long-task counters defaulted to zero when the
observer never ran, and every script and stylesheet resource contributed to
`blocking_transfer_bytes`. Those outputs are not reproducible definitions of the Core
Web Vitals and cannot be compared across captures.

## Decision

1. **LCP is reported only from a `largest-contentful-paint` entry.** The observed entry
   contributes its start time, render time and load time when the entry exposes them,
   together with the element reference and resource URL. FCP never populates an LCP
   field.
2. **Heuristic LCP candidates are separate.** A DOM-geometry candidate is serialised in
   its own field with an explicit `heuristic` label and never inherits measured timing.
   Phase attribution is only computed when every required timing is observed and
   compatible.
3. **CLS uses session windows.** Qualifying shifts (`!hadRecentInput`) are grouped into
   windows that continue while consecutive shifts are less than one second apart and
   last at most five seconds from the first shift. The reported value is the largest
   observed window score. The individual shifts, window boundaries and truncation state
   are retained.
4. **Observer presence is recorded.** LCP, layout-shift and long-task observations carry
   an installed/observed flag so that "no entry" is not confused with "observer never
   installed". A zero CLS is valid only for a successfully observed interval.
5. **Render-blocking attribution distinguishes classes.** Scripts are classified as
   parser-blocking, deferred, async, module or dynamically inserted; stylesheets record
   whether their media query matched. Only resources with an established blocking status
   contribute to confirmed blocking bytes. Potentially blocking and unknown resources
   are reported separately, and `blocking_transfer_bytes` is absent when the blocking
   status of any contributing resource is unknown.
6. **Clock domains are explicit.** Browser performance entries use the page time origin;
   protocol timestamps use monotonic browser time. Durations are never compared across
   domains, and ratios are derived only from same-domain observations.
7. **Provenance is recorded.** Performance evidence states that it is a laboratory
   observation of a single viewport without throttling unless a throttling profile was
   actually applied.

## Consequences

- The schema gains explicit LCP render/load timings, session-window boundaries and
  blocking classification.
- Some previously available numbers become absent, because the previous values were not
  measurements of the field they claimed to measure.
- Laboratory values are not presented as field data, and no claim is made that a single
  viewport observation represents real-user performance.
