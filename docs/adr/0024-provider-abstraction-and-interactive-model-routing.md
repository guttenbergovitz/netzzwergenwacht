# 0024. Provider abstraction and interactive model routing

## Status

Accepted

## Context

Provider handling is split. `RigCompletionProvider` wraps `rig-core` and supports
OpenAI-compatible endpoints, Anthropic and Ollama. `RigProviderRouter` builds a provider
per dwarf from `ModelRoutingConfig`, and `CachedProviderRouter` caches those providers
for patrol execution. `nzw patrol` and `nzw check --ai` use that routing.

`run_investigation` and its variants instead accept a single `&dyn LlmProvider`, so every
hypothesis, specialist consultation and evaluation in an agentic investigation uses one
model regardless of `[models]`. `src/investigation/mod.rs` even carries a `P1` note
about accepting a `ProviderRouter`. The TUI additionally bypasses routing entirely by
calling `OpenAiCompatibleProvider::from_env()`.

There is also no way to select a provider or model interactively, no model discovery and
no connection test, so an operator cannot tell whether configuration is merely present
or actually usable.

## Decision

1. **One provider stack.** `rig-core` through `RigCompletionProvider`, selected by
   `ProviderKind`, remains the only implementation. Interactive configuration builds the
   same type, from a resolved `ModelSpec` plus a scoped credential. No second client,
   HTTP wrapper or provider abstraction is added.
2. **Supported families are stated plainly.** `openai` (OpenAI and OpenAI-compatible
   endpoints such as OpenRouter, vLLM, `LiteLLM` and the OpenCode gateway), `anthropic`
   and `ollama`. Everything else is presented as "OpenAI-compatible endpoint", never as
   a native integration. `ProviderKind` is the only provider identifier in
   configuration.
3. **Investigation accepts a router.** `run_investigation*` gains a `ProviderRouter`
   parameter and resolves a provider per dwarf for hypothesis generation, specialist
   consultation, re-consultation, evaluation and report synthesis, mirroring patrol.
   Existing single-provider callers pass a router that returns the same provider for
   every dwarf, preserving current behaviour and tests.
4. **Routing levels come from existing configuration.** Shared, role-based and per-dwarf
   routing are the three shapes of `ModelRoutingConfig`; the TUI edits those fields and
   calls `resolve_for_dwarf`. The dwarf list is read from the brigade registry, so no
   second registry can drift.
5. **Effective routing is visible.** Mission Review shows the resolved provider and model
   for each agent together with whether the value is inherited (`default`, `specialist`,
   `kommandant`, `dokumentation`) or explicitly overridden.
6. **Model discovery is optional and bounded.** Where the provider exposes a documented
   catalogue (`GET {base_url}/models` for OpenAI-compatible endpoints, `GET
   {base_url}/api/tags` for Ollama), the operator may request it explicitly: 8-second
   timeout, 256 KiB response cap, 200 identifiers retained, credentials resolved only for
   the configured endpoint. Discovery failure keeps manual entry available and is
   reported as a discovery failure, not as an authentication result.
7. **Connection testing distinguishes the questions.** Configuration validation,
   endpoint reachability, authentication, model availability and model invocation are
   separate outcomes: `NotTested`, `Testing`, `Reachable`, `AuthenticationRejected`,
   `ModelUnavailable`, `RateLimited`, `ProviderError`, `TimedOut`, `InvocationSucceeded`,
   `Cancelled`. A stored API key never renders as "Connected". A billable invocation test
   is a separate explicit action with a token-cost warning.
8. **Results are invalidated by change.** A connection result carries a fingerprint of
   provider, endpoint, model and credential source; editing any of them resets the result
   to `NotTested` instead of leaving a stale success.
9. **No silent substitution.** If a provider cannot be constructed or invoked, the
   operator chooses: retry, edit configuration, select another model, continue with
   deterministic diagnostics, or cancel. Continuing deterministically is recorded in the
   report as "agentic investigation not completed". Automatic fallback remains available
   only as an explicit configuration choice.

## Consequences

- Agentic investigations finally honour `[models]`, and the routing that patrol already
  used becomes uniform across the product.
- Investigation signatures change; existing call sites pass a single-provider router.
- Connection testing adds no dependency: bounded `reqwest` requests reuse the existing
  HTTP client configuration.
- Discovery and invocation results are explicitly *not* claims about empirical model
  quality; they report reachability and invocation only.
