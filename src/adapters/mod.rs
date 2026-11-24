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

    let mut child = cmd
        .spawn()
        .map_err(|err| format!("failed to launch {label}: {err}"))?;

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
            let _ = child.kill().await;
            return Err(format!(
                "{label} timed out after {} ms",
                timeout.as_millis()
            ));
        };

    if stdout_buf.len() > MAX_ADAPTER_OUTPUT_BYTES {
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
