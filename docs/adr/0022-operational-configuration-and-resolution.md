# 0022. Operational configuration and resolution

## Status

Accepted

## Context

`AppConfig` already models `[budget]`, `[policy]`, `[models]` and `[dns]`, and
`ModelRoutingConfig::resolve_for_dwarf` already resolves per-dwarf overrides before role
overrides before the default. The resolver is, however, only reachable through
`nzw check --config`, `nzw batch --config` and `nzw patrol --config`.

`nzw tui` has no `--config` at all, the launcher holds no provider, model or budget
fields, and the agentic branch of the TUI constructs its provider from environment
variables. The workbench therefore ignores `[models]`, `[budget]`, `[dns]` and
`[policy]`. Documentation compounds the problem: `CONFIG.md` documents `kind = …` while
`ModelSpec` requires `provider`, so every published example fails to parse, and nothing
in the test suite would have noticed.

An operator consequently has to read the source to know what configuration exists, and
has no way to confirm what configuration a run actually used.

## Decision

1. **One configuration model.** `AppConfig` remains the single authoritative schema for
   the CLI and the Zwergenleitstand. No TUI-specific configuration struct, file or
   loader is introduced. The TUI receives a resolved `AppConfig` and a session overlay,
   never its own schema.
2. **Deterministic precedence.** Values resolve in this order, highest first:
   1. per-run overrides (CLI flags or Mission Control session edits);
   2. environment configuration (`NZW_LLM_MODEL`, `NZW_LLM_BASE_URL`, credential
      variables);
   3. an explicitly named configuration file (`--config`);
   4. the discovered user configuration file;
   5. built-in defaults.
   Credential resolution is a separate contract (ADR 0023) because a credential is
   scoped to a provider endpoint rather than merely overridden.
3. **Discovery is explicit and non-fatal.** When `--config` is absent: `NZW_CONFIG`,
   then `./nzw.toml`, then `$XDG_CONFIG_HOME/netzzwergenwacht/nzw.toml` falling back to
   `$HOME/.config/netzzwergenwacht/nzw.toml`. A missing file is normal and is reported
   as "built-in defaults in effect", never as an error and never as an empty config.
   A file that exists but fails to parse is a hard error.
4. **Schema integrity is enforced.** Config structs reject unknown fields so a typo can
   no longer silently disable a section. `provider` is the canonical key and `kind` is
   accepted only as a documented `serde` alias for the historical spelling. Invalid
   enum values, non-HTTPS DNS endpoints, zero budgets and empty model identifiers are
   reported with the offending field path.
5. **Resolution is inspectable.** `AppConfig` produces a redacted effective
   configuration summary (sources, budgets, policy, routing per dwarf, DNS endpoint,
   memory and output paths, credential source names but never secret values).
   `nzw config show` and `nzw doctor` print it; the Mission Review panel renders the
   same structure. One renderer, three consumers.
6. **Per-run immutability.** Starting a mission snapshots the resolved configuration
   into an immutable run configuration. Later edits in the launcher apply to the next
   mission only; an executing mission cannot observe mutated settings.
7. **CLI parity.** Flags that already exist in the CLI (`--config`, `--allow-private`,
   timeouts, collectors, `--fail-on`) gain TUI equivalents backed by the same fields.
   No TUI control is exposed unless the underlying run path consumes it.

## Consequences

- Configuration behaviour becomes testable without a terminal: parse, resolve, validate
  and summarise are pure functions over `AppConfig` plus an override struct.
- `deny_unknown_fields` is a breaking change for configuration files that carry extra
  keys; those files now fail with a clear message instead of silently losing data.
- The historical `kind` spelling keeps working through an alias so existing operator
  files do not break on upgrade.
- Documentation examples can be executed as tests, closing the gap that allowed
  `kind` to remain in `CONFIG.md` after the struct had moved on.
- Environment variables remain supported but are no longer the only way to configure a
  provider, and are never the mechanism for session credentials.
