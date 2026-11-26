//! Bounded external tool and browser adapters.
//!
//! External measurement engines (such as Lighthouse, headless Chromium, and
//! `axe-core`) run as isolated, timeout-bounded subprocesses with capped
//! stdout/stderr buffers and record tool version and execution status.

pub mod axe;
pub mod browser;
pub mod lighthouse;

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Maximum bytes read from an external adapter's stdout or stderr (16 MiB).
const MAX_ADAPTER_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Environment variables an adapter subprocess may inherit.
///
/// Provider credentials never appear here. Measurement engines need the search path,
/// a writable temporary directory and their own `NZW_*` tuning knobs; everything else
/// is dropped so a pasted session credential cannot leak into a child process.
const SUBPROCESS_ENV_ALLOW_LIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "XDG_CACHE_HOME",
    "NZW_CHROMIUM_BIN",
    "NZW_AXE_BIN",
    "NZW_BROWSER_POLICY",
    "NZW_ALLOW_UNSAFE_BROWSER_SANDBOX",
    "NZW_LOAD_TIMEOUT_MS",
    "NZW_TIMEOUT_MS",
];

/// Restricts `cmd` to [`SUBPROCESS_ENV_ALLOW_LIST`].
///
/// The child starts from an empty environment, so any variable not on the list —
/// including API keys and session credentials — is absent rather than merely
/// unmentioned.
fn apply_restricted_environment(cmd: &mut Command) {
    cmd.env_clear();
    for name in SUBPROCESS_ENV_ALLOW_LIST {
        if let Ok(value) = std::env::var(name) {
            cmd.env(name, value);
        }
    }
}

/// Executes an external command within `timeout`, returning stdout on success.
///
/// Ensures stdin is closed, stdout/stderr are piped and capped at
/// [`MAX_ADAPTER_OUTPUT_BYTES`], and the child process is killed on drop if
/// the timeout expires or the future is cancelled.
pub(crate) async fn run_bounded_command(
    label: &str,
    cmd: &mut Command,
    timeout: Duration,
) -> Result<String, String> {
    tracing::debug!(
        adapter = label,
        timeout_ms = timeout.as_millis(),
        "spawning bounded adapter"
    );
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_restricted_environment(cmd);
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|err| format!("failed to launch {label}: {err}"))?;
    let child_pid = child.id();

    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| format!("{label} stdout pipe unavailable"))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| format!("{label} stderr pipe unavailable"))?;

    let io_future = async {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut stdout_take = stdout_pipe.take((MAX_ADAPTER_OUTPUT_BYTES + 1) as u64);
        let mut stderr_take = stderr_pipe.take((MAX_ADAPTER_OUTPUT_BYTES + 1) as u64);
        let (out_res, err_res, status_res) = tokio::join!(
            stdout_take.read_to_end(&mut stdout_buf),
            stderr_take.read_to_end(&mut stderr_buf),
            child.wait(),
        );
        out_res.map_err(|e| format!("failed to read {label} stdout: {e}"))?;
        err_res.map_err(|e| format!("failed to read {label} stderr: {e}"))?;
        let status = status_res.map_err(|e| format!("failed to wait for {label}: {e}"))?;
        Ok::<_, String>((stdout_buf, stderr_buf, status))
    };

    let (stdout_buf, stderr_buf, status) =
        if let Ok(res) = tokio::time::timeout(timeout, io_future).await {
            res?
        } else {
            terminate_process_group(&mut child, child_pid).await;
            return Err(format!(
                "{label} timed out after {} ms",
                timeout.as_millis()
            ));
        };

    if stdout_buf.len() > MAX_ADAPTER_OUTPUT_BYTES {
        terminate_process_group(&mut child, child_pid).await;
        return Err(format!(
            "{label} stdout exceeded {MAX_ADAPTER_OUTPUT_BYTES} bytes cap"
        ));
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_buf);
        return Err(format!("{label} exited with {status}: {}", stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&stdout_buf).into_owned())
}

async fn terminate_process_group(child: &mut tokio::process::Child, pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pgid) = pid {
        let _ = Command::new("kill")
            .arg("-9")
            .arg(format!("-{pgid}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn adapter_subprocess_environment_is_restricted_to_the_allow_list() {
        // `sh` adds a few variables of its own (`PWD`, `SHLVL`, `_`); everything else
        // must have come from the allow-list.
        const SHELL_INJECTED: &[&str] = &["PWD", "SHLVL", "_"];

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("env");
        let output = run_bounded_command("env probe", &mut cmd, Duration::from_secs(10))
            .await
            .expect("environment probe should run");

        let mut names = Vec::new();
        for line in output.lines() {
            if let Some((name, _)) = line.split_once('=') {
                names.push(name.to_owned());
            }
        }
        for name in &names {
            assert!(
                SUBPROCESS_ENV_ALLOW_LIST.contains(&name.as_str())
                    || SHELL_INJECTED.contains(&name.as_str()),
                "adapter subprocess inherited unexpected variable `{name}`"
            );
            assert!(
                !name.ends_with("_API_KEY") && !name.starts_with("NZW_LLM"),
                "credential variable `{name}` leaked into an adapter subprocess"
            );
        }
    }
}
