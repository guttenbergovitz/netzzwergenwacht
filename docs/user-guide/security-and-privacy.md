# Security and privacy

NetzZwergenWacht is an external auditing tool. It makes requests to systems you do not control, it
reads untrusted content, and — when you configure one — it sends diagnostic material to a language
model provider. This page states what happens to that data so the choice stays yours.

## Target validation

Every target is validated before any request is made. Only `http` and `https` are accepted, hostnames
are resolved and checked against the target policy, and private, loopback and link-local addresses are
rejected unless you explicitly pass `--allow-private` or set `[policy] allow_private = true`.

`nzw validate <url>` performs the same validation without fetching anything, which is the safe way to
check a policy decision.

## What leaves your network

| Destination | Data | When |
| --- | --- | --- |
| The target host | Ordinary HTTP requests from the collector | Always, for every audited page |
| The target's subresources | Requests issued by the headless browser | Only with browser-backed collection |
| Configured DNS-over-HTTPS resolver | The audited hostname, in a CAA query | Only when `[dns] caa_doh_endpoint` is set |
| Configured model provider | Prompts containing findings, headers, URLs, page text excerpts and citations | Only for agentic investigation, patrol synthesis or `--ai` |
| Nothing else | — | — |

There is no telemetry, no update check and no implicit external call.

### Model providers receive diagnostic content

When you configure a provider, the coordinator prompt includes the objective, the target URL, the
observations relevant to the current hypothesis, rendered text excerpts where the evidence query
engine legitimately exposes them (always as fingerprints, never raw block text), and the specialist
responses. That material goes to the provider's API.

Do not configure an external provider for targets whose content may not leave your network. Use a
local Ollama endpoint, or run deterministic audits only. `nzw config show` lists the resolved endpoint
per dwarf so there is no doubt where a request would go.

## Credentials

- The CLI reads credentials from environment variables named in configuration; it never writes them
  to disk.
- The workbench keeps an entered credential in memory only, scoped to `provider @ endpoint`, masked in
  the interface, excluded from `Debug` output, reports, events, history and patrol memory, and dropped
  when the process exits.
- A credential entered for one endpoint is not reused against another endpoint.
- Subprocesses (Chromium, Lighthouse, `axe`) are started with a restricted environment allow-list, so
  an API key present in your shell is not inherited by a child process.
- `nzw doctor` prints the credential *source* for the coordinator route, never a value.

Clearing a session credential takes effect for the next mission. A provider client that is already
running keeps the credential it was constructed with; cancel the run if that matters.

## Untrusted content

Page content is treated as hostile:

- HTML is parsed with a real parser; selectors and attribute values are length-bounded.
- Terminal output is sanitised: ANSI escape sequences, C0/C1 control characters, carriage returns,
  backspaces and Unicode bidirectional overrides are stripped before rendering.
- URLs shown in the interface have credentials and sensitive query parameters redacted.
- Raw block text is not placed in agent prompts; fingerprints and structural metadata are used
  instead.
- Cookie values are never retained, only names, scopes and byte lengths.

## Browser sandbox

The browser runs with its sandbox enabled. `NZW_ALLOW_UNSAFE_BROWSER_SANDBOX` exists for containerised
CI environments where the sandbox cannot start; it must not be set on a normal workstation, and it is
never enabled by configuration files or defaults.

## Evidence retention

Reports may retain the evidence snapshot they were derived from so the workbench can re-query it
offline. That snapshot contains bounded HTTP body text and rendered-text fingerprints. Delete stored
reports when the audited content is sensitive. Patrol memory under `.nzw/memory` stores page URLs,
template fingerprints, findings and anomaly history, not full page bodies.

## Honest reporting

Automated checks — accessibility especially — detect a bounded set of machine-detectable conditions.
They are not proof of WCAG or European Accessibility Act compliance, and NetzZwergenWacht does not
claim that they are. Temporal associations observed during a behavioural probe are reported as
associations, not as causal explanations.
