# Architecture Decision Records (ADRs)

Short, factual records of significant technical decisions made in NetzZwergenWacht.

## Rules (KISS)

- One decision per file, named `NNNN-short-kebab-title.md` (for example, `0001-rewrite-netzzwergenwacht-in-rust.md`).
- Keep each ADR concise and grounded in verified facts.
- Record real context, the decision made, and its trade-offs. Do not invent teams, rollout schedules, governance boards, or approval workflows.
- Once accepted, an ADR is immutable aside from updating its status if superseded.

## Allowed statuses

- `Proposed`
- `Accepted`
- `Superseded by NNNN`

## Template

```markdown
# NNNN. Short descriptive title

## Status

Proposed | Accepted | Superseded by NNNN

## Context

What problem or constraint requires a decision, and what real options were considered?

## Decision

What was chosen and why.

## Consequences

What becomes easier, what becomes harder, and what risks or trade-offs are accepted.
```
