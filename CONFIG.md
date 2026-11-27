# Configuration

NetzZwergenWacht uses one TOML configuration model for the CLI and for Zwergenleitstand. Every
example in this document is a complete, valid file, and `examples/` contains the same files so they
can be copied and tested.

```bash
nzw config show                       # resolved configuration, secrets redacted
nzw config show --format json         # machine-readable form
nzw config show --config nzw.toml     # inspect a specific file
```

## Discovery and precedence

Configuration is resolved in this order, first match wins:

1. Per-run command-line overrides (`--timeout-secs`, `--allow-private`, `--browser`, …).
2. The file given by `--config <path>`.
3. The file named by `NZW_CONFIG`.
4. `nzw.toml` in the current working directory.
5. `$XDG_CONFIG_HOME/netzzwergenwacht/nzw.toml`, or `$HOME/.config/netzzwergenwacht/nzw.toml`.
6. Built-in defaults.

A file that is *not found* during discovery is normal: the defaults apply and `nzw config show`
reports `built-in defaults` as the source. A file that exists but cannot be parsed or validated is a
hard error — NetzZwergenWacht refuses to run with a configuration it does not understand rather than
silently ignoring an operator's intent.

Unknown keys are rejected. This is deliberate: a typo in `api_key_env` should fail loudly, not
quietly fall back to an unauthenticated provider.

## Minimal configuration

```toml
[models.default]
provider = "openai"
model = "your-model-id"
```

That is enough for deterministic audits; the model tables only matter for agentic work. `provider`
must be one of `openai`, `anthropic` or `ollama` (the historical `kind` spelling is still accepted).

## Providers

```toml
# OpenAI or an OpenAI-compatible gateway
[models.default]
provider = "openai"
model = "gpt-4.1-mini"
api_key_env = "OPENAI_API_KEY"

# Anthropic Messages API
[models.kommandant]
provider = "anthropic"
model = "claude-sonnet-4-5"
api_key_env = "ANTHROPIC_API_KEY"

# Local Ollama; loopback HTTP is allowed
[models.dokumentation]
provider = "ollama"
model = "llama3.1:8b"
base_url = "http://127.0.0.1:11434"
```

OpenRouter is an OpenAI-compatible endpoint rather than a distinct provider:

```toml
[models.default]
provider = "openai"
model = "your-openrouter-model-id"
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"
```

`base_url` must use `https`, except for loopback hosts (`localhost`, `127.0.0.1`, `::1`), where
plain `http` is accepted for local model servers. Embedded credentials in a URL are rejected, and
the endpoint is part of the credential scope, so a key entered for one endpoint is never silently
reused against another.

## Model routing

Routing resolves at three levels, most specific first:

| Level | Table | Applies to |
| --- | --- | --- |
| Per dwarf | `[models.dwarfs.<key>]` | One named member of the brigade |
| Role | `[models.kommandant]`, `[models.specialist]`, `[models.dokumentation]` | Coordinator, analysts, report writer |
| Default | `[models.default]` | Everything else |

Dwarf keys are the ASCII forms of the registry names:

`netz`, `sicherheits`, `leistungs`, `struktur`, `zugaenglichkeits`, `such`, `inhalts`,
`gestaltungs`, `browser`, `dokumentations`, `kommandant`.

```toml
[models.default]
provider = "openai"
model = "your-default-model-id"

[models.kommandant]
provider = "anthropic"
model = "your-coordinator-model-id"
api_key_env = "ANTHROPIC_API_KEY"

[models.dwarfs.sicherheits]
provider = "openai"
model = "your-security-model-id"
```

`nzw config show` lists the resolved route, its origin table and the credential *source* for every
dwarf. The Mission Review in the workbench shows the same resolution before a mission starts.

## Credential sources

Credentials are resolved in this order:

1. The session credential store (workbench only): keyed by `provider @ endpoint`, entered in Mission
   Control, masked, cleared when the session ends.
2. The environment variable named by `api_key_env` in the matching model table.
3. The provider's conventional variable.

| Provider | Conventional variables, in order |
| --- | --- |
| OpenAI-compatible | `NZW_LLM_API_KEY`, `OPENCODE_API_KEY`, `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Ollama | none required |

`api_key_env` is a variable *name*, never a secret:

```toml
[models.default]
provider = "openai"
model = "your-model-id"
api_key_env = "TEAM_GATEWAY_KEY"
```

## Session credentials

The workbench never writes a credential to disk. A key typed into Mission Control goes into a
session store scoped to the provider and endpoint, is displayed only as asterisks, is excluded from
`Debug` output, reports, events, history and subprocess environments, and is discarded when the
process exits.

Consequences worth knowing:

- Starting a new session means entering the key again. That is the intended trade-off.
- Changing the endpoint invalidates the stored credential, because the scope no longer matches.
- Clearing a credential affects the next mission; a client that is already running keeps the
  credential it was constructed with, so cancel the run if you need the key gone immediately.

## Budgets

```toml
[budget]
audit_timeout_secs = 60
http_timeout_secs = 20
max_redirects = 5
max_response_bytes = 10485760
max_concurrency = 4
```

| Key | Meaning | Bounds |
| --- | --- | --- |
| `audit_timeout_secs` | End-to-end deadline for a collection run | 1–3600 |
| `http_timeout_secs` | Per-request timeout | 1–3600 |
| `max_redirects` | Redirects followed before giving up | 0–100 |
| `max_response_bytes` | Body size cap | ≥ 1 |
| `max_concurrency` | Concurrent requests in batch and crawl | 1–64 |

A budget is a hard bound, not a target. When it is exhausted the run reports that it was truncated
rather than pretending the observation set is complete.

## Diagnostic instruments

```toml
[policy]
require_collectors = ["browser", "axe"]
```

`require_collectors` names Level 2 collectors (`browser`, `lighthouse`, `axe`) that must have
produced evidence for the quality gate to pass. An unavailable collector then fails the gate
explicitly instead of being silently absent.

Level 2 collection is still requested per run: `--browser`, `--axe`, `--lighthouse` for the CLI and
the corresponding toggles in Mission Control.

## Target policy

```toml
[policy]
allow_private = false
fail_on_severity = "high"
max_critical = 0
max_high = 2
```

`allow_private` (or `--allow-private`) permits loopback and private-network targets for local
testing. It is off by default because the engine is designed for external auditing. Enabling it does
not disable the remaining target validation, and it is never enabled implicitly by a configuration
file you did not intend to use.

## DNS and TLS

```toml
[dns]
caa_doh_endpoint = "https://cloudflare-dns.com/dns-query"
```

DNS CAA records are only queried when an endpoint is configured. Without `[dns]` no external
resolver is contacted at all — a local-first default, because a CAA lookup discloses the hostname to
the resolver. The endpoint must use `https` (loopback is exempt for a local resolver) and the lookup
is bounded by the remaining audit deadline, a 3-second ceiling and a 64 KiB response limit.

The observation is recorded as *direct CAA records observed for the queried hostname*. Absence of a
record at that name is not a statement about inherited policy up the DNS tree.

## Patrol memory

```toml
# no configuration keys; pass the directory instead
```

```bash
nzw patrol https://example.org --memory-dir .nzw/memory
nzw tui --memory-dir .nzw/memory
```

`.nzw/memory` is the shared default. Patrols read application identity, previously discovered pages,
anomaly history and stale-page metadata from it, then write the new run back. The workbench uses the
same directory, so a patrol started from the TUI continues the application's history instead of
starting from nothing. A missing or unwritable memory directory is reported as a warning, never
treated as an empty first patrol.

## Report retention

Investigation and patrol reports keep the evidence snapshot they were derived from, so
`nzw tui --report <file>` can re-query the same observations offline. When a report deliberately
omits the snapshot, the workbench shows the evidence as unavailable rather than as an empty capture.

Raw page text is bounded by `max_response_bytes` and only retained as part of that snapshot; delete
stored reports when the audited content is sensitive.

## Interaction policies

Behavioural probing is passive by default. The browser collectors never click controls unless the
restricted behavioural probe is enabled for that collection, and those probes are limited to native
disclosure controls outside forms and links. A probe records an observation window, the requests and
runtime errors observed inside it, and whether local state restoration succeeded. Those are
associations, not causal attributions, and the report says so.

## Environment variables

These are the variables the implementation actually reads.

| Variable | Used for |
| --- | --- |
| `NZW_CONFIG` | Configuration file path, part of discovery |
| `NZW_LLM_API_KEY` | Credential for OpenAI-compatible providers |
| `NZW_LLM_MODEL` | Model override for the default provider |
| `NZW_LLM_BASE_URL` | Endpoint override for the default provider |
| `OPENCODE_API_KEY`, `OPENCODE_BASE_URL`, `OPENCODE_MODEL`, `OPENCODE_SESSION_ID` | OpenCode-compatible fallbacks |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `OLLAMA_API_KEY` | Provider credentials |
| `NZW_CHROMIUM_BIN` | Explicit Chromium/Chrome binary for the CDP harness |
| `NZW_AXE_BIN` | Explicit `axe` binary |
| `NZW_BROWSER_POLICY` | Browser policy override |
| `NZW_ALLOW_UNSAFE_BROWSER_SANDBOX` | Disables the browser sandbox; CI containers only |
| `NZW_LOAD_TIMEOUT_MS`, `NZW_TIMEOUT_MS` | Browser observation timeout overrides |
| `NO_COLOR`, `TERM` | Terminal colour and glyph detection |

## Troubleshooting

**`invalid configuration at models.default.base_url: plain http is only permitted for loopback
endpoints`** — remote providers must use `https`. Only `localhost` and loopback IPs may use plain
`http`.

**`unknown dwarf key`** — check the key list above; `models.dwarfs.kommandantzwerg` is not a key,
`models.dwarfs.kommandant` is.

**`agentic investigation needs a model configured for KommandantZwerg`** — the coordinator has no
resolvable route. Enter a model in Mission Control, or add `[models.kommandant]` /
`[models.default]` to a configuration file and pass `--config`.

**Connection test reports `authentication rejected`** — the endpoint answered but refused the
credential. Check the variable named by `api_key_env`, or re-enter the session credential.

**Connection test reports `model unavailable`** — the credential was accepted but the model name is
not served at that endpoint. Use model discovery or enter the provider's exact identifier.

**Browser collectors report `unsupported`** — Node.js 22 or newer is required for the built-in
`WebSocket` client. Run `nzw doctor`.

**CAA outcome `not attempted`** — no `[dns] caa_doh_endpoint` is configured. This is the default and
not an error.
