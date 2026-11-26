//! Contract tests for the shared operational configuration model (ADR 0022).
//!
//! Every shipped example must parse and validate, unknown fields and impossible values
//! must be rejected rather than silently ignored, discovery precedence must follow the
//! documented order, and the resolved view must never expose credential material.

use std::path::PathBuf;

use netzzwergenwacht::brigade::DwarfId;
use netzzwergenwacht::config::{
    AppConfig, ConfigDiscovery, ConfigError, ConfigSource, ProviderKind,
};
use netzzwergenwacht::domain::TargetPolicy;

const EXAMPLES: [(&str, &str); 9] = [
    (
        "config-minimal.toml",
        include_str!("../examples/config-minimal.toml"),
    ),
    (
        "config-openai.toml",
        include_str!("../examples/config-openai.toml"),
    ),
    (
        "config-anthropic.toml",
        include_str!("../examples/config-anthropic.toml"),
    ),
    (
        "config-ollama.toml",
        include_str!("../examples/config-ollama.toml"),
    ),
    (
        "config-openrouter.toml",
        include_str!("../examples/config-openrouter.toml"),
    ),
    (
        "config-hybrid-routing.toml",
        include_str!("../examples/config-hybrid-routing.toml"),
    ),
    (
        "config-per-dwarf.toml",
        include_str!("../examples/config-per-dwarf.toml"),
    ),
    (
        "policy-gates.toml",
        include_str!("../examples/policy-gates.toml"),
    ),
    (
        "dns-resolver.toml",
        include_str!("../examples/dns-resolver.toml"),
    ),
];

fn parse(raw: &str) -> AppConfig {
    toml::from_str::<AppConfig>(raw).expect("example must parse")
}

#[test]
fn every_shipped_example_parses_and_validates() {
    for (name, raw) in EXAMPLES {
        let config = toml::from_str::<AppConfig>(raw)
            .unwrap_or_else(|err| panic!("{name} must parse: {err}"));
        config
            .validate()
            .unwrap_or_else(|err| panic!("{name} must validate: {err}"));
    }
}

#[test]
fn resolved_examples_are_usable_after_interpretation() {
    let ollama = parse(include_str!("../examples/config-ollama.toml"));
    ollama.validate().expect("loopback endpoint is permitted");
    let spec = ollama.models.resolve_for_dwarf(DwarfId::Netz);
    assert_eq!(spec.provider, ProviderKind::Ollama);

    let hybrid = parse(include_str!("../examples/config-hybrid-routing.toml"));
    hybrid.validate().expect("role routing validates");
    assert_eq!(
        hybrid
            .models
            .resolve_for_dwarf(DwarfId::Kommandant)
            .provider,
        ProviderKind::Anthropic
    );
    assert_eq!(
        hybrid.models.resolve_origin_for_dwarf(DwarfId::Kommandant),
        "models.kommandant"
    );
    assert_eq!(
        hybrid.models.resolve_origin_for_dwarf(DwarfId::Such),
        "models.specialist"
    );

    let per_dwarf = parse(include_str!("../examples/config-per-dwarf.toml"));
    per_dwarf.validate().expect("per-dwarf routing validates");
    assert_eq!(
        per_dwarf
            .models
            .resolve_for_dwarf(DwarfId::Sicherheits)
            .provider,
        ProviderKind::Anthropic
    );
    assert_eq!(
        per_dwarf
            .models
            .resolve_origin_for_dwarf(DwarfId::Sicherheits),
        "models.dwarfs"
    );
    assert_eq!(
        per_dwarf.models.resolve_origin_for_dwarf(DwarfId::Such),
        "models.default"
    );
}

#[test]
fn legacy_kind_spelling_is_accepted_as_a_provider_alias() {
    let config = parse(
        r#"
[models.default]
kind = "anthropic"
model = "claude-example"
"#,
    );
    config.validate().expect("alias configuration validates");
    assert_eq!(config.models.default.provider, ProviderKind::Anthropic);
}

#[test]
fn unknown_fields_are_rejected_rather_than_ignored() {
    let err = toml::from_str::<AppConfig>(
        r#"
[models.default]
provider = "openai"
model = "example"
mystery_setting = true
"#,
    )
    .expect_err("unknown field must fail to parse");
    assert!(
        err.to_string().contains("mystery_setting"),
        "error should name the offending field: {err}"
    );
}

#[test]
fn unknown_dwarf_keys_are_rejected_with_their_configuration_path() {
    let config = parse(
        r#"
[models.dwarfs.netzzwerg]
provider = "openai"
model = "example"
"#,
    );
    match config.validate() {
        Err(ConfigError::Validation { field, .. }) => {
            assert_eq!(field, "models.dwarfs.netzzwerg");
        }
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn remote_plain_http_endpoints_are_rejected_but_loopback_is_permitted() {
    let remote = parse(
        r#"
[models.default]
provider = "openai"
model = "example"
base_url = "http://api.example.com/v1"
"#,
    );
    assert!(
        remote.validate().is_err(),
        "plain http to a remote host must be rejected"
    );

    let loopback = parse(
        r#"
[models.default]
provider = "ollama"
model = "example"
base_url = "http://localhost:11434"
"#,
    );
    loopback.validate().expect("loopback http is permitted");

    let credentials = parse(
        r#"
[models.default]
provider = "openai"
model = "example"
base_url = "https://user:secret@api.example.com/v1"
"#,
    );
    assert!(
        credentials.validate().is_err(),
        "embedded credentials must be rejected"
    );
}

#[test]
fn invalid_budget_and_policy_values_are_rejected() {
    let zero_concurrency = parse(
        r"
[budget]
max_concurrency = 0
",
    );
    assert!(zero_concurrency.validate().is_err());

    let unknown_collector = parse(
        r#"
[policy]
require_collectors = ["browser", "telepathy"]
"#,
    );
    assert!(unknown_collector.validate().is_err());
}

#[test]
fn discovery_prefers_explicit_then_environment_then_working_then_user() {
    let root = std::env::temp_dir().join(format!("nzw-config-contract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("cwd")).expect("create working directory");
    std::fs::create_dir_all(root.join("user")).expect("create user directory");

    let explicit = root.join("explicit.toml");
    let environment = root.join("environment.toml");
    let local = root.join("cwd").join("nzw.toml");
    let user = root.join("user").join("nzw.toml");
    for (path, model) in [
        (&explicit, "explicit-model"),
        (&environment, "environment-model"),
        (&local, "local-model"),
        (&user, "user-model"),
    ] {
        std::fs::write(
            path,
            format!("[models.default]\nprovider = \"openai\"\nmodel = \"{model}\"\n"),
        )
        .expect("write configuration");
    }

    let discovery = ConfigDiscovery {
        explicit: Some(explicit.clone()),
        environment: Some(environment.clone()),
        working_directory: root.join("cwd"),
        user_config: Some(user.clone()),
    };
    let loaded = discovery.resolve().expect("explicit file wins");
    assert_eq!(loaded.source, ConfigSource::ExplicitFile(explicit));
    assert_eq!(loaded.config.models.default.model, "explicit-model");

    let discovery = ConfigDiscovery {
        explicit: None,
        ..discovery.clone()
    };
    let loaded = discovery.resolve().expect("environment file wins next");
    assert_eq!(loaded.source, ConfigSource::EnvironmentFile(environment));
    assert_eq!(loaded.config.models.default.model, "environment-model");

    let discovery = ConfigDiscovery {
        explicit: None,
        environment: None,
        ..discovery
    };
    let loaded = discovery
        .resolve()
        .expect("working directory file wins next");
    assert_eq!(loaded.source, ConfigSource::WorkingDirectory(local));
    assert_eq!(loaded.config.models.default.model, "local-model");

    std::fs::remove_file(root.join("cwd").join("nzw.toml")).expect("remove local file");
    let loaded = discovery
        .resolve()
        .expect("user configuration is the last file");
    assert_eq!(loaded.source, ConfigSource::UserConfig(user));
    assert_eq!(loaded.config.models.default.model, "user-model");

    std::fs::remove_file(root.join("user").join("nzw.toml")).expect("remove user file");
    let loaded = discovery.resolve().expect("defaults apply without a file");
    assert_eq!(loaded.source, ConfigSource::BuiltInDefaults);
    assert_eq!(loaded.config.target_policy(), TargetPolicy::PublicOnly);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn missing_explicit_configuration_is_an_error_not_a_silent_default() {
    let discovery = ConfigDiscovery {
        explicit: Some(PathBuf::from("/nonexistent/nzw.toml")),
        environment: None,
        working_directory: std::env::temp_dir(),
        user_config: None,
    };
    assert!(discovery.resolve().is_err());
}

#[test]
fn effective_configuration_is_redacted_and_explains_its_origins() {
    let config = parse(include_str!("../examples/config-hybrid-routing.toml"));
    let effective = config.effective(&ConfigSource::BuiltInDefaults);

    let json = serde_json::to_string(&effective).expect("effective view serialises");
    assert!(!json.contains("sk-"), "no secret material may appear");
    assert_eq!(effective.routes.len(), 11, "one route per registered dwarf");

    let kommandant = effective
        .routes
        .iter()
        .find(|route| route.agent == "kommandant")
        .expect("kommandant route present");
    assert_eq!(kommandant.origin, "models.kommandant");
    assert_eq!(kommandant.credential_reference, "env:ANTHROPIC_API_KEY");

    let netz = effective
        .routes
        .iter()
        .find(|route| route.agent == "netz")
        .expect("netz route present");
    assert_eq!(netz.origin, "models.specialist");
    assert_eq!(netz.display_name, "NetzZwerg");

    let lines = effective.render_lines();
    let joined = lines.join("\n");
    assert!(joined.contains("Configuration source"));
    assert!(joined.contains("models.kommandant"));
    assert!(!joined.contains("sk-"));
}
