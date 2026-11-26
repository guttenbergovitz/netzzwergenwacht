# 0021. Evidence retention and diagnostic lifecycle integrity

## Status

Accepted

## Context

The diagnostic event channel is bounded, so critical lifecycle events can be dropped
when the UI is slow, and a dropped event is currently indistinguishable from an event
that never happened. Agentic investigations historically returned `snapshot: None` to the
TUI, so the operator could not inspect the evidence behind a conclusion. Cancellation
relied on abrupt task abortion, which does not prove that child processes and outstanding
requests have terminated. Patrol execution from the TUI did not consistently reuse the
authoritative memory store.

## Decision

1. **The snapshot is authoritative.** Deterministic analysis, agentic investigation and
   offline exploration all read the same `EvidenceSnapshot`. Reports reference retained
   evidence rather than duplicating it.
2. **Retention is explicit.** A diagnostic artefact records whether the snapshot is
   retained, intentionally omitted (for example for size or sensitivity reasons), or
   unavailable. `None` never implies "no evidence existed".
3. **Event loss is observable.** Coalescable progress may be dropped and counted;
   critical lifecycle events may not be dropped silently. The transport records dropped
   counts and sequence gaps, and the TUI reconciles the final run state from the
   authoritative result rather than from the event stream alone.
4. **Cancellation reaches a confirmed terminal state.** A cancellation request moves the
   run through `Cancelling` to `Cancelled` only after child processes, browser sessions
   and outstanding HTTP work have been confirmed terminated. Deadline overruns escalate
   to `TerminationEscalated` instead of reporting a clean cancellation.
5. **Patrol memory is shared.** The TUI uses the same authoritative patrol memory as the
   headless CLI. A patrol is persistent, ephemeral, fresh or historical by explicit
   choice, and an unavailable memory store is reported rather than silently replaced by
   an empty one.
6. **Run identity isolates events.** Events carry a run identifier; stale events from a
   cancelled or completed run cannot mutate a later run's state.
7. **Raw page content is not retained by default.** Retained evidence keeps bounded,
   sanitised observations, and sensitive values are redacted as they are collected.

## Consequences

- The TUI gains a reconciliation path from the final artefact, which also makes partial
  and cancelled runs inspectable.
- Cancellation takes longer to report because it waits for confirmed cleanup.
- Patrol runs from the TUI now depend on a configured memory directory; when it is
  missing the operator sees an explicit message.
