//! `NetzZwergenWacht` CLI entry point.

use std::process::ExitCode;

use netzzwergenwacht::domain::{AuditTarget, TargetPolicy};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("nzw {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("validate") => {
            let Some(raw_url) = args.next() else {
                eprintln!("usage: nzw validate <url>");
                return ExitCode::FAILURE;
            };
            match AuditTarget::parse(&raw_url, TargetPolicy::PublicOnly) {
                Ok(target) => {
                    println!(
                        "valid target: {} (host: {})",
                        target.as_str(),
                        target.host()
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("invalid target: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            println!(
                "NetzZwergenWacht {} (Phase 0 Rust core skeleton; see docs/roadmap.md)",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
    }
}
