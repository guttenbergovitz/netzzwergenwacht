//! Contract tests for session credentials.
//!
//! These guard the promise that a credential entered in the workbench stays in memory,
//! is never offered to another endpoint, and never appears in debug output.

use netzzwergenwacht::config::{ModelSpec, ProviderKind};
use netzzwergenwacht::credentials::{CredentialScope, SessionCredentialStore, SessionSecret};
use netzzwergenwacht::intelligence::{LlmProvider, RigCompletionProvider};

const CANARY: &str = "canary-session-secret-4f2a";

fn openai_spec(base_url: Option<&str>) -> ModelSpec {
    ModelSpec {
        provider: ProviderKind::OpenAi,
        model: "test-model".to_owned(),
        base_url: base_url.map(str::to_owned),
        api_key_env: None,
    }
}

#[test]
fn session_credential_reaches_the_provider_without_being_logged() {
    let mut store = SessionCredentialStore::new();
    let scope = CredentialScope::new(ProviderKind::OpenAi, None);
    store.insert(scope, SessionSecret::new(CANARY).expect("non-empty canary"));

    let resolved = store
        .resolve_with(&openai_spec(None), |_| None)
        .expect("session credential resolves");
    let provider = RigCompletionProvider::from_resolved_spec(&openai_spec(None), &resolved)
        .expect("provider builds from a resolved credential");

    assert_eq!(provider.model_name(), "test-model");
    assert!(!format!("{provider:?}").contains(CANARY));
    assert!(!format!("{store:?}").contains(CANARY));
}

#[test]
fn a_session_credential_never_follows_the_provider_to_another_endpoint() {
    let mut store = SessionCredentialStore::new();
    store.insert(
        CredentialScope::new(ProviderKind::OpenAi, Some("https://gateway.example/v1")),
        SessionSecret::new(CANARY).expect("non-empty canary"),
    );

    assert!(
        store
            .resolve_with(&openai_spec(Some("https://other.example/v1")), |_| None)
            .is_none()
    );
    assert!(
        store.resolve_with(&openai_spec(None), |_| None).is_none(),
        "the provider default endpoint must be a distinct scope"
    );
    assert!(
        store
            .resolve_with(&openai_spec(Some("https://gateway.example/v1")), |_| None)
            .is_some()
    );
}

#[test]
fn clearing_the_store_discards_every_session_credential() {
    let mut store = SessionCredentialStore::new();
    store.insert(
        CredentialScope::new(ProviderKind::OpenAi, None),
        SessionSecret::new(CANARY).expect("non-empty canary"),
    );
    store.insert(
        CredentialScope::new(ProviderKind::Anthropic, None),
        SessionSecret::new(CANARY).expect("non-empty canary"),
    );
    assert_eq!(store.scopes().len(), 2);

    store.clear();
    assert_eq!(store.scopes().len(), 0);
    assert!(store.resolve_with(&openai_spec(None), |_| None).is_none());
}
