# Zwergenleitstand user guide

Zwergenleitstand ("dwarf control desk") is the interactive Ratatui workbench. It launches runs,
streams structured events, and lets you inspect the retained evidence behind every finding without
re-running collection.

```bash
nzw tui                                  # open the launcher
nzw tui https://example.org               # start a deterministic audit immediately
nzw tui https://example.org --mode investigate --config nzw.toml
nzw tui --report investigation.json       # explore a saved report offline
nzw tui --history audit-history.jsonl     # inspect stored audit history
```

## Mission Control (launcher)

Press `n` in any view, or start the workbench without a target, to open the launcher. It collects
everything a run needs:

| Row | Purpose |
| --- | --- |
| Target | URL to audit, investigate or patrol |
| Mode | `check` (deterministic), `investigate` (agentic) or `patrol` (autonomous) |
| Provider | `openai`, `anthropic` or `ollama` |
| Model | Model identifier; prefilled from the resolved configuration |
| Credential (session only) | Provider key, displayed as asterisks and never persisted |
| Browser / Axe / Lighthouse | Level 2 instruments for this run |
| Discover models | Queries the provider's advertised model list and fills the Model row |
| Test connection | Probes the provider with the entered route and reports the outcome |
| Start | Begins the run |

`Enter` activates the focused row, `Tab`/`Up`/`Down` move, `Space` or `Left`/`Right` toggle or cycle.
A model is optional for deterministic audits and required for `investigate`: starting an agentic
mission without a coordinator model reports an explicit error rather than silently substituting
another provider.

## Mission Review

`r` opens the review overlay. It shows the target, the mode and instruments, the provider and model,
the last connection outcome, the target policy and budget, and the resolved routing for every dwarf
with the configuration table each route came from. Nothing in the review contains a credential
value; the panel states that credentials are session-only.

`Enter` starts the mission from the review, `r` or `Esc` closes it.

## Views

| Key | View | Contents |
| --- | --- | --- |
| `1` | Overview | Run lifecycle, target surface, headline counts |
| `2` | Brigade | Per-dwarf activity: checks, findings, status |
| `3` | Targets | Discovered pages and their inspection state |
| `4` | Findings | Filterable findings with severity and evidence citations |
| `5` | Evidence | 19 evidence categories queried offline from the snapshot |
| `6` | Investigation | Hypotheses, citations, tool trace, specialist contributions |
| `7` | Topology | Application graph and coverage |
| `8` | History | Stored audit runs and regression comparisons |
| `9` | System | Collector availability, budgets, event delivery counters |

The Evidence view exposes the offline evidence query engine: HTTP and source, TLS, rendered content,
source-versus-rendered diff, network resources, browser timeline, request chains and failures,
runtime errors, interactive elements and application state, geometry and accessibility tree, security
and privacy, performance and media, SEO and structured data, responsive and links, visual artefacts,
service workers, TLS and CAA, plus the raw performance, accessibility, Lighthouse and axe panels.

Values that were not observed are shown as `unobserved`, `unavailable`, `partial`, `failed` or
`skipped`. A measured zero is shown as `0`, because it is a real observation.

## Keymap

### Global

| Key | Action |
| --- | --- |
| `1`–`9` | Select view |
| `j` / `Down` | Move selection down |
| `k` / `Up` | Move selection up |
| `h` / `Left` | Previous item, previous evidence category, or previous launcher value |
| `l` / `Right` | Next item, next evidence category, or next launcher value |
| `g` / `Home` | First item |
| `G` / `End` | Last item |
| `Enter` | Activate the selected item, launch from the launcher, or start from the review |
| `n` | Open Mission Control |
| `r` | Toggle Mission Review |
| `/` | Search |
| `s` | Cycle finding sort order |
| `v` | Cycle severity filter |
| `w` | Save the current report |
| `t` | Cycle theme (standard, high contrast, monochrome) |
| `a` | Toggle ASCII-only rendering |
| `c` | Cancel the active run |
| `?` | Toggle help |
| `q` | Quit |
| `Ctrl+C` | Quit |

### Launcher text entry

| Key | Action |
| --- | --- |
| `Char` | Append to the focused field |
| `Backspace` | Delete the last character |
| `Ctrl+u` | Clear the focused field |
| `Esc` | Close the launcher without starting |

### Mission Review

| Key | Action |
| --- | --- |
| `r` / `Esc` | Close the review |
| `Enter` | Start the mission |
| `q` | Quit |

## Running a mission

1. `n` to open Mission Control, or pass a URL on the command line.
2. Choose the mode. `check` needs nothing else; `investigate` needs a provider, model and credential;
   `patrol` uses persistent memory from `--memory-dir` (default `.nzw/memory`).
3. Select Level 2 instruments. Browser-backed evidence requires Node.js 22+ and Chromium; `nzw
   doctor` tells you whether they are available.
4. Optionally press `r` to review the resolved route, budget and policy.
5. `Enter` to start. The run streams collection, analysis and investigation events into the views.
6. Inspect findings in `4` and jump to their evidence in `5`.
7. `w` saves the report; `q` exits.

## Cancellation

`c` requests cooperative cancellation. The workbench reports `Cancelling` while the collection and
child processes stop, then either `Cancelled` once cleanup is confirmed or `TerminationEscalated` when
the cancellation deadline expires and the background task has to be force-terminated. It never shows
`Cancelled` for a run whose cleanup is still in progress.

## Offline exploration

`nzw tui --report <file>` loads a saved `AuditReport`, `InvestigationReport` or `PatrolReport` without
touching the network. Investigation and patrol reports carry the evidence snapshot they were derived
from, so the Evidence view and the offline query tools work unchanged. When a report omits the
snapshot, the workbench says the evidence is unavailable; it does not present an empty capture.

`nzw tui --history audit-history.jsonl` loads stored audit runs for regression inspection in the
History view.

## Accessibility of the interface itself

The workbench supports a high-contrast theme, a monochrome mode honouring `NO_COLOR`, and ASCII-only
borders for terminals without Unicode box drawing. Severity is always shown as a text badge
(`[CRIT]`, `[HIGH]`, `[MED ]`, `[LOW ]`, `[INFO]`) so colour is never the only signal. Terminal
output is sanitised: escape sequences, control characters and bidirectional overrides are stripped
before rendering, and credentials and URL query values are redacted.
