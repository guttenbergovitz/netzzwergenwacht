# 0023. Session credentials and secret management

## Status

Accepted

## Context

Provider credentials are currently resolved exclusively from process environment
variables inside `RigCompletionProvider::from_model_spec` and `from_env`
(`NZW_LLM_API_KEY`, `OPENCODE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`OLLAMA_API_KEY`). The `Debug` implementation already redacts the key, but nothing else
in the system knows the value is sensitive: it is an ordinary `Option<String>` inside
the provider struct.

An operator who starts `nzw tui` without exporting a key has no way to supply one. The
obvious shortcut — calling `std::env::set_var` from the launcher — would leak the secret
into every child process, including Chromium, Lighthouse and axe-core, and into any
future environment dump.

## Decision

1. **Session store, scoped by provider and endpoint.** A `SessionCredentialStore` holds
   secrets in memory, keyed by the pair `(ProviderKind, normalised endpoint)`. There is
   no single global API key: a credential entered for `https://api.openai.com/v1` is not
   offered to `https://example.invalid/v1`.
2. **Secrets are typed, not plain strings.** Values are stored as `secrecy::SecretString`
   with `zeroize` enabled, so the value is zeroised on replacement, on explicit clear and
   on drop at process exit. Best-effort zeroisation is described as best-effort: copies
   already handed to a provider client or the allocator are not claimed to be scrubbed.
3. **Resolution order during construction.** Session store entry for the resolved
   `(provider, endpoint)` → the `api_key_env` named in `ModelSpec` → the provider's
   documented default variable. The resolved *source* is recorded as a label
   (`session`, `env:NAME`, `none`, `unavailable`) and shown in Mission Review; the value
   never is.
4. **Endpoint trust is explicit.** Custom endpoints must be `https` unless they resolve
   to a loopback address, must not contain embedded credentials, and must be displayed
   before execution. Reusing a session credential against a different endpoint requires
   an explicit operator confirmation; the store never forwards silently.
5. **Masked input is a dedicated widget.** The credential field masks characters,
   supports editing, paste, clear and replacement, and is not part of the general text
   input history. It is excluded from `Debug` output, serialised application state and
   any report or event payload.
6. **No secret leaves the process boundary by accident.** Credentials are not written to
   TOML, session files, reports, history, patrol memory, evidence snapshots, prompts or
   diagnostic events. Provider error messages are sanitised before display or logging.
   External subprocesses (Chromium, Node, Lighthouse, axe) receive an explicit
   environment allow-list that strips `NZW_LLM_API_KEY`, `*_API_KEY` and
   `NZW_LLM_BASE_URL` unless a specific instrument needs them.
7. **Clearing is defined.** `Clear session credentials` removes all session secrets
   immediately. Settings for the next mission are unaffected; an already constructed
   provider client keeps the credential it was built with. Where a provider cannot
   function without the cleared secret, the operator must cancel and restart. This
   behaviour is stated in the TUI and covered by a test.
8. **Rejected approaches.** Persisting secrets in configuration files, mutating the
   process environment as the session mechanism, an unrestricted global key, OS keyring
   integration (no implementation exists in the repository and it is not required for
   readiness), and passing secrets as command-line arguments.

## Consequences

- Interactive use becomes possible without pre-exported environment variables while
  headless pipelines keep working unchanged.
- Provider construction must take credentials as an argument rather than reading the
  environment implicitly; the current implicit fallback remains only for callers that
  have no session store.
- Subprocess adapters need an explicit environment policy, which also improves
  reproducibility of browser-dependent tests.
- Zeroisation provides defence in depth, not a guarantee; documentation states this
  limitation rather than implying that memory is scrubbed everywhere.
