//! Operational readiness contracts.
//!
//! These tests protect the entry points an operator relies on: the documented
//! workflow, the tooling surface, and the guarantee that diagnosis never leaks a
//! credential value. They run offline and touch no network.

use netzzwergenwacht::doctor::{DoctorStatus, diagnose, resolve_config};
use netzzwergenwacht::events::DiagnosticRunMode;
use netzzwergenwacht::tui::AppState;

const README: &str = include_str!("../README.md");
const CONFIG_DOC: &str = include_str!("../CONFIG.md");
const TASKFILE: &str = include_str!("../Taskfile.yml");
const WORKBENCH_GUIDE: &str = include_str!("../docs/user-guide/zwergenleitstand.md");

#[test]
fn readme_documents_the_operational_workflow() {
    for heading in [
        "## What is NetzZwergenWacht?",
        "## What can it investigate?",
        "## Quick start",
        "## Installation",
        "## Diagnostic instruments",
        "## Starting Zwergenleitstand",
        "## Deterministic audits",
        "## Agentic investigations",
        "## Autonomous patrols",
        "## Provider and model configuration",
        "## Reports and historical comparison",
        "## Architecture",
        "## Security and privacy",
        "## Known limitations",
        "## Development",
        "## Documentation",
        "## Licence",
    ] {
        assert!(
            README.contains(heading),
            "README is missing the `{heading}` section"
        );
    }

    assert!(
        README.contains("task setup")
            && README.contains("task doctor")
            && README.contains("task tui"),
        "quick start must follow the documented setup, doctor, tui sequence"
    );
    assert!(
        README.contains("cargo run --locked -- doctor"),
        "quick start must offer a Cargo equivalent"
    );
}

#[test]
fn readme_never_documents_commands_that_do_not_exist() {
    assert!(
        !README.contains("--level2"),
        "`nzw tui` has no `--level2` flag; documents must not invent flags"
    );
    for flag in ["--browser", "--axe", "--lighthouse", "--config"] {
        assert!(
            README.contains(flag),
            "documented workbench flags must include {flag}"
        );
    }
}

#[test]
fn taskfile_exposes_the_documented_tasks() {
    for task in [
        "setup:",
        "doctor:",
        "dev:",
        "tui:",
        "run:",
        "build:",
        "install:",
        "uninstall:",
        "test:browser:",
        "test:integration:",
        "test:crawler:",
        "test:store:",
        "test:recon:",
        "bench:store:",
        "bench:crawler:",
        "scan:",
        "tui:scan:",
        "check:",
        "check:all:",
    ] {
        assert!(
            TASKFILE.contains(task),
            "Taskfile is missing the `{task}` task"
        );
    }
}

#[test]
fn taskfile_uses_one_variable_name_for_the_target_url() {
    let directives: Vec<&str> = TASKFILE
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    let body = directives.join("\n");
    assert!(
        !body.contains("vars: [TARGET]"),
        "a task still requires TARGET; URL is the canonical argument name"
    );
    assert!(
        body.contains("{{.URL | default .TARGET | default .DEFAULT_URL}}"),
        "entry-point tasks must accept URL and keep TARGET as a legacy alias"
    );
    for line in directives {
        assert!(
            !line.contains("TARGET="),
            "documented task usage still advertises TARGET: {line}"
        );
    }
}

#[test]
fn configuration_documentation_covers_every_documented_surface() {
    for topic in [
        "Discovery and precedence",
        "Provider",
        "Model routing",
        "Credential sources",
        "Session credentials",
        "Budgets",
        "Target policy",
        "DNS and TLS",
        "Patrol memory",
        "Report retention",
        "Troubleshooting",
    ] {
        assert!(
            CONFIG_DOC.contains(topic),
            "CONFIG.md is missing the `{topic}` section"
        );
    }
}

#[test]
fn workbench_guide_documents_the_actual_keymap() {
    for key in ["`1`", "`5`", "`n`", "`r`", "`w`", "`c`", "`?`", "`q`"] {
        assert!(
            WORKBENCH_GUIDE.contains(key),
            "workbench guide is missing the {key} key"
        );
    }
    assert!(
        WORKBENCH_GUIDE.contains("Mission Review"),
        "workbench guide must document the Mission Review overlay"
    );
    assert!(
        WORKBENCH_GUIDE.contains("TerminationEscalated"),
        "workbench guide must document escalated cancellation"
    );
}

#[test]
fn doctor_reports_structured_state_without_credential_values() {
    let (config, source) = resolve_config(None);
    let report = diagnose(&config, source.as_deref());

    let json = serde_json::to_string(&report).expect("doctor report serialises");
    assert!(json.contains("\"checks\""), "report lists its checks");
    assert!(
        !json.contains("api_key") && !json.contains("API_KEY"),
        "doctor output must name credential sources, never values"
    );

    for check in &report.checks {
        assert!(
            !check.detail.contains("sk-"),
            "a credential-shaped value leaked into `{}`",
            check.id
        );
        if matches!(
            check.status,
            DoctorStatus::Missing | DoctorStatus::Unsupported
        ) {
            assert!(
                !check.hint.is_empty(),
                "a blocking check must explain how to fix it: {}",
                check.id
            );
        }
    }

    assert_eq!(
        report.is_ready(),
        report.blocking_count == 0 && report.config_error.is_none(),
        "readiness must follow the blocking checks"
    );
}

#[test]
fn invalid_configuration_blocks_readiness_with_a_field_name() {
    let (config, source) = resolve_config(Some(
        std::path::Path::new("examples/does-not-exist.toml").to_path_buf(),
    ));
    let error = config.expect_err("missing explicit configuration must fail");
    let message = error.to_string();

    let report = diagnose(&Err(error), source.as_deref());
    assert!(!report.is_ready());
    assert!(
        report.config_error.as_deref() == Some(message.as_str()),
        "the report must carry the exact configuration error"
    );
}

#[test]
fn launcher_defaults_to_a_passive_deterministic_mission() {
    let state = AppState::default();
    assert_eq!(state.launcher.mode, DiagnosticRunMode::DeterministicCheck);
    assert!(
        !state.launcher.enable_browser && !state.launcher.enable_axe,
        "Level 2 collection must be opt-in"
    );
    assert!(
        !state.launcher.open || state.launcher.error_message.is_none(),
        "a fresh launcher must not present an error"
    );
}
