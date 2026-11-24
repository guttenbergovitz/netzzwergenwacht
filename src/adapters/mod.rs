//! Bounded external tool and browser adapters.
//!
//! External measurement engines (such as Lighthouse, headless Chromium, and
//! `axe-core`) run as isolated, timeout-bounded subprocesses and record tool
//! version and execution status.

pub mod axe;
pub mod browser;
pub mod lighthouse;

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// Executes an external command within `timeout`, returning stdout on success.
///
/// Ensures stdin is closed, stdout/stderr are piped, and the child process is
/// killed on drop if the timeout expires or the future is cancelled.
pub(crate) async fn run_bounded_command(
    label: &str,
    cmd: &mut Command,
    timeout: Duration,
) -> Result<String, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(err)) => return Err(format!("failed to launch {label}: {err}")),
        Err(_) => {
            return Err(format!(
                "{label} timed out after {} ms",
                timeout.as_millis()
            ));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{label} exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
