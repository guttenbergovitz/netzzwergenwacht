//! Session-scoped provider credentials.
//!
//! `NetzZwergenWacht` never persists secrets. A credential entered in the workbench
//! lives in [`SessionCredentialStore`] for the lifetime of the process, is keyed by
//! provider plus normalised endpoint so a key is never offered to a different
//! endpoint, and is wiped on drop through [`zeroize`].
//!
//! Resolution order is deliberate: a credential pasted for this session wins over
//! configuration, configuration names an environment variable, and only then does the
//! provider default variable apply. The resolved [`CredentialSource`] is recorded so
//! reports and the Mission Review can state *where* a credential came from without
//! revealing it.
//!
//! Zeroization is best-effort: it clears the buffer this process owns, but cannot
//! recall copies made by the operating system, a library, or a swap file.

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

use crate::config::{ModelSpec, ProviderKind};

/// Marker used when a provider has no configured endpoint override.
const PROVIDER_DEFAULT_ENDPOINT: &str = "(provider default)";

/// Where a resolved credential came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    /// Pasted into this session through the workbench.
    Session,
    /// Read from an environment variable.
    Environment(String),
    /// The provider needs no credential (for example a local Ollama server).
    NotRequired,
}

impl CredentialSource {
    /// Returns a display label that never contains the secret.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Session => "session".to_owned(),
            Self::Environment(name) => format!("env:{name}"),
            Self::NotRequired => "not required".to_owned(),
        }
    }
}

/// A secret held in memory for the lifetime of the process.
///
/// The value is zeroized on drop and never rendered by [`fmt::Debug`]. It deliberately
/// does not implement `Serialize`: nothing serialises a credential by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionSecret(Zeroizing<String>);

impl SessionSecret {
    /// Wraps `value`, rejecting empty input so an accidental blank entry cannot be
    /// mistaken for a working credential.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty or whitespace only.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err("credential must not be empty".to_owned());
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Wraps an already zeroizing buffer, keeping the same emptiness rule.
    fn from_zeroizing(value: Zeroizing<String>) -> Result<Self, String> {
        if value.trim().is_empty() {
            return Err("credential must not be empty".to_owned());
        }
        Ok(Self(value))
    }

    /// Exposes the secret to the provider client.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns a fixed-width mask for display. The length and content never vary, so
    /// the mask cannot leak the secret's shape.
    #[must_use]
    pub fn masked(&self) -> &'static str {
        "********"
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSecret([REDACTED])")
    }
}

/// Editable buffer for a secret typed into an interface.
///
/// The buffer zeroizes its contents on drop and on replacement, so a partially typed
/// credential is not left as plain heap text. It deliberately exposes no `&str`, only a
/// fixed-width mask, and converts to a [`SessionSecret`] by moving the buffer out.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SessionBuffer {
    value: Zeroizing<String>,
}

impl SessionBuffer {
    /// Creates an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one character.
    pub fn push(&mut self, ch: char) {
        self.value.push(ch);
    }

    /// Removes the last character.
    pub fn pop(&mut self) {
        self.value.pop();
    }

    /// Discards the typed content and zeroizes it.
    pub fn clear(&mut self) {
        self.value.clear();
    }

    /// Whether nothing has been typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Number of typed characters, used for input bounds.
    #[must_use]
    pub fn char_count(&self) -> usize {
        self.value.chars().count()
    }

    /// Returns a fixed-width mask. The length never varies, so the mask cannot leak
    /// the secret's shape.
    #[must_use]
    pub fn masked(&self) -> String {
        if self.value.is_empty() {
            "(not set)".to_owned()
        } else {
            "********".to_owned()
        }
    }

    /// Moves the typed value into a [`SessionSecret`], leaving the buffer empty.
    pub fn take(&mut self) -> Option<SessionSecret> {
        let value = std::mem::take(&mut self.value);
        SessionSecret::from_zeroizing(value).ok()
    }
}

impl fmt::Debug for SessionBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionBuffer")
            .field("credential", &self.masked())
            .finish()
    }
}

/// The provider/endpoint pair a credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialScope {
    /// Provider family.
    pub provider: ProviderKind,
    /// Normalised endpoint, or a marker when the provider default applies.
    pub endpoint: String,
}

impl CredentialScope {
    /// Builds a scope from a provider and an optional endpoint override.
    #[must_use]
    pub fn new(provider: ProviderKind, base_url: Option<&str>) -> Self {
        Self {
            provider,
            endpoint: normalise_endpoint(base_url),
        }
    }

    /// Derives the scope a [`ModelSpec`] targets.
    #[must_use]
    pub fn for_model_spec(spec: &ModelSpec) -> Self {
        Self::new(spec.provider, spec.base_url.as_deref())
    }

    /// Returns a display label that identifies the endpoint without the secret.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} @ {}", self.provider.as_str(), self.endpoint)
    }
}

fn normalise_endpoint(base_url: Option<&str>) -> String {
    let Some(raw) = base_url else {
        return PROVIDER_DEFAULT_ENDPOINT.to_owned();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return PROVIDER_DEFAULT_ENDPOINT.to_owned();
    }
    // Lowercase the scheme and host so the same endpoint typed differently reuses one
    // credential, while preserving any path (which may be case sensitive).
    let trimmed = trimmed.trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = match rest.split_once('/') {
                Some((authority, path)) => (authority, Some(path)),
                None => (rest, None),
            };
            match path {
                Some(path) => format!(
                    "{}://{}/{}",
                    scheme.to_ascii_lowercase(),
                    authority.to_ascii_lowercase(),
                    path
                ),
                None => format!(
                    "{}://{}",
                    scheme.to_ascii_lowercase(),
                    authority.to_ascii_lowercase()
                ),
            }
        }
        None => trimmed.to_ascii_lowercase(),
    }
}

/// A credential resolved for one provider request.
#[derive(Debug)]
pub struct ResolvedCredential {
    /// The secret to hand to the client.
    pub secret: SessionSecret,
    /// Where it came from.
    pub source: CredentialSource,
}

/// Session-only credential storage keyed by provider and endpoint.
///
/// The store is intentionally not serialisable and its [`fmt::Debug`] output lists
/// scopes only, so neither a log line nor a report can capture a key.
#[derive(Default, Clone)]
pub struct SessionCredentialStore {
    entries: BTreeMap<CredentialScope, SessionSecret>,
}

impl SessionCredentialStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores `secret` for `scope`, replacing and zeroizing any previous value.
    pub fn insert(&mut self, scope: CredentialScope, secret: SessionSecret) {
        self.entries.insert(scope, secret);
    }

    /// Removes the credential for `scope`.
    ///
    /// Returns `true` when a credential was present. A run already holding a resolved
    /// credential keeps using it; the removal applies to subsequent resolutions.
    pub fn remove(&mut self, scope: &CredentialScope) -> bool {
        self.entries.remove(scope).is_some()
    }

    /// Forgets every session credential.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Reports whether a session credential exists for `scope`.
    #[must_use]
    pub fn contains(&self, scope: &CredentialScope) -> bool {
        self.entries.contains_key(scope)
    }

    /// Lists the scopes that currently hold a session credential.
    #[must_use]
    pub fn scopes(&self) -> Vec<&CredentialScope> {
        self.entries.keys().collect()
    }

    /// Resolves the credential for `spec`, preferring the session store.
    ///
    /// The environment is read through `env` so tests can exercise every precedence
    /// branch without mutating process-wide state.
    #[must_use]
    pub fn resolve_with(
        &self,
        spec: &ModelSpec,
        env: impl Fn(&str) -> Option<String>,
    ) -> Option<ResolvedCredential> {
        let scope = CredentialScope::for_model_spec(spec);
        if let Some(secret) = self.entries.get(&scope) {
            return Some(ResolvedCredential {
                secret: secret.clone(),
                source: CredentialSource::Session,
            });
        }
        if let Some(name) = &spec.api_key_env
            && let Some(secret) = env(name).and_then(|value| SessionSecret::new(value).ok())
        {
            return Some(ResolvedCredential {
                secret,
                source: CredentialSource::Environment(name.clone()),
            });
        }
        // A provider default variable belongs to that provider's own endpoint. Sending
        // `OPENAI_API_KEY` to a custom base URL would disclose a credential to a third
        // party, so a custom endpoint requires an explicit `api_key_env` or a session
        // credential.
        if spec.base_url.is_none() {
            for name in provider_default_variables(spec.provider) {
                if let Some(secret) = env(name).and_then(|value| SessionSecret::new(value).ok()) {
                    return Some(ResolvedCredential {
                        secret,
                        source: CredentialSource::Environment((*name).to_owned()),
                    });
                }
            }
        }
        if spec.provider == ProviderKind::Ollama {
            return Some(ResolvedCredential {
                secret: SessionSecret::new("unused").unwrap_or_else(|_| {
                    // `unused` is a non-empty constant, so this branch is unreachable.
                    SessionSecret(Zeroizing::new("unused".to_owned()))
                }),
                source: CredentialSource::NotRequired,
            });
        }
        None
    }

    /// Resolves the credential for `spec` from the process environment.
    #[must_use]
    pub fn resolve(&self, spec: &ModelSpec) -> Option<ResolvedCredential> {
        self.resolve_with(spec, |name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
    }

    /// Returns an identity for the resolved credential used to invalidate a stale
    /// connection-test result.
    ///
    /// The fingerprint contains the scope, model and credential *source*, never the
    /// secret, so it is safe to record in a report.
    #[must_use]
    pub fn fingerprint(&self, spec: &ModelSpec, env: impl Fn(&str) -> Option<String>) -> String {
        let scope = CredentialScope::for_model_spec(spec);
        let source = self
            .resolve_with(spec, env)
            .map_or_else(|| "none".to_owned(), |resolved| resolved.source.label());
        format!("{}|{}|{}", scope.label(), spec.model, source)
    }
}

impl fmt::Debug for SessionCredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scopes: Vec<String> = self.entries.keys().map(CredentialScope::label).collect();
        f.debug_struct("SessionCredentialStore")
            .field("scopes", &scopes)
            .finish()
    }
}

fn provider_default_variables(provider: ProviderKind) -> &'static [&'static str] {
    match provider {
        ProviderKind::OpenAi => &["NZW_LLM_API_KEY", "OPENCODE_API_KEY", "OPENAI_API_KEY"],
        ProviderKind::Anthropic => &["ANTHROPIC_API_KEY"],
        ProviderKind::Ollama => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(provider: ProviderKind, base_url: Option<&str>) -> ModelSpec {
        ModelSpec {
            provider,
            model: "test-model".to_owned(),
            base_url: base_url.map(str::to_owned),
            api_key_env: None,
        }
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let mut store = SessionCredentialStore::new();
        let scope = CredentialScope::new(ProviderKind::OpenAi, None);
        store.insert(
            scope.clone(),
            SessionSecret::new("canary-secret-value").expect("non-empty secret"),
        );

        let store_debug = format!("{store:?}");
        assert!(store_debug.contains("openai"), "scope should be visible");
        assert!(
            !store_debug.contains("canary-secret-value"),
            "store debug output leaked the secret"
        );

        let resolved = store
            .resolve_with(&spec(ProviderKind::OpenAi, None), |_| None)
            .expect("session credential");
        assert!(!format!("{resolved:?}").contains("canary-secret-value"));
        assert_eq!(resolved.source, CredentialSource::Session);
    }

    #[test]
    fn session_credential_wins_over_environment() {
        let mut store = SessionCredentialStore::new();
        store.insert(
            CredentialScope::new(ProviderKind::OpenAi, None),
            SessionSecret::new("session-key").expect("non-empty"),
        );
        let resolved = store
            .resolve_with(&spec(ProviderKind::OpenAi, None), |_| {
                Some("environment-key".to_owned())
            })
            .expect("credential");
        assert_eq!(resolved.secret.expose(), "session-key");
    }

    #[test]
    fn credentials_are_scoped_to_the_endpoint() {
        let mut store = SessionCredentialStore::new();
        store.insert(
            CredentialScope::new(ProviderKind::OpenAi, Some("https://gateway.example/v1")),
            SessionSecret::new("gateway-key").expect("non-empty"),
        );

        let other_endpoint = store.resolve_with(
            &spec(ProviderKind::OpenAi, Some("https://other.example/v1")),
            |_| None,
        );
        assert!(
            other_endpoint.is_none(),
            "a credential must not follow the provider to another endpoint"
        );

        let same_endpoint = store
            .resolve_with(
                &spec(ProviderKind::OpenAi, Some("https://GATEWAY.example/v1/")),
                |_| None,
            )
            .expect("normalised endpoint should match");
        assert_eq!(same_endpoint.secret.expose(), "gateway-key");
    }

    #[test]
    fn clearing_a_credential_revokes_later_resolution() {
        let mut store = SessionCredentialStore::new();
        let scope = CredentialScope::new(ProviderKind::Anthropic, None);
        store.insert(
            scope.clone(),
            SessionSecret::new("anthropic-key").expect("non-empty"),
        );
        assert!(store.remove(&scope));
        assert!(!store.remove(&scope));
        assert!(
            store
                .resolve_with(&spec(ProviderKind::Anthropic, None), |_| None)
                .is_none()
        );
    }

    #[test]
    fn configuration_environment_name_is_preferred_over_provider_default() {
        let mut configuration = spec(ProviderKind::OpenAi, None);
        configuration.api_key_env = Some("TEAM_GATEWAY_KEY".to_owned());
        let store = SessionCredentialStore::new();
        let resolved = store
            .resolve_with(&configuration, |name| match name {
                "TEAM_GATEWAY_KEY" => Some("team-key".to_owned()),
                "NZW_LLM_API_KEY" => Some("fallback-key".to_owned()),
                _ => None,
            })
            .expect("credential");
        assert_eq!(resolved.secret.expose(), "team-key");
        assert_eq!(
            resolved.source,
            CredentialSource::Environment("TEAM_GATEWAY_KEY".to_owned())
        );
    }

    #[test]
    fn session_buffer_masks_and_moves_without_leaking() {
        let mut buffer = SessionBuffer::new();
        assert!(buffer.is_empty());
        for ch in "canary-buffer-7c".chars() {
            buffer.push(ch);
        }
        assert_eq!(buffer.char_count(), 16);
        assert_eq!(buffer.masked(), "********");
        assert!(
            !format!("{buffer:?}").contains("canary"),
            "buffer Debug leaked"
        );

        let secret = buffer.take().expect("typed value becomes a secret");
        assert!(buffer.is_empty());
        assert_eq!(secret.expose(), "canary-buffer-7c");
    }

    #[test]
    fn custom_endpoint_never_receives_a_provider_default_key() {
        let store = SessionCredentialStore::new();
        let custom = ModelSpec {
            base_url: Some("https://gateway.example.com/v1".to_owned()),
            ..ModelSpec::default()
        };
        let resolved = store.resolve_with(&custom, |name| match name {
            "NZW_LLM_API_KEY" | "OPENCODE_API_KEY" | "OPENAI_API_KEY" => {
                Some("sk-provider-default".to_owned())
            }
            _ => None,
        });
        assert!(
            resolved.is_none(),
            "a provider default key must not be offered to a custom endpoint"
        );

        let explicit = ModelSpec {
            api_key_env: Some("GATEWAY_API_KEY".to_owned()),
            ..custom
        };
        let resolved = store
            .resolve_with(&explicit, |name| {
                (name == "GATEWAY_API_KEY").then(|| "gateway-key".to_owned())
            })
            .expect("explicit variable is honoured for a custom endpoint");
        assert_eq!(
            resolved.source,
            CredentialSource::Environment("GATEWAY_API_KEY".to_owned())
        );
    }

    #[test]
    fn fingerprint_tracks_source_without_exposing_the_secret() {
        let store = SessionCredentialStore::new();
        let fingerprint = store.fingerprint(&spec(ProviderKind::Anthropic, None), |_| {
            Some("canary-secret-value".to_owned())
        });
        assert!(fingerprint.contains("env:ANTHROPIC_API_KEY"));
        assert!(!fingerprint.contains("canary-secret-value"));
    }
}
