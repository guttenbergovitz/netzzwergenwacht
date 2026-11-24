//! Bounded headless Chromium browser runtime adapter.
//!
//! Launches a controlled Node.js + Chromium CDP subprocess within an explicit
//! timeout to capture [`BrowserEvidence`] (console errors, failed subresource
//! requests, and per-viewport layout / broken-image observations).

use std::time::Duration;

use tokio::process::Command;

use crate::adapters::run_bounded_command;
use crate::domain::{AuditTarget, BrowserEvidence, CollectorOutcome};

const CDP_HARNESS_JS: &str = r"
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const targetUrl = process.argv[2];
if (!targetUrl) {
  console.error('missing target URL');
  process.exit(2);
}

const candidates = [
  process.env.NZW_CHROMIUM_BIN,
  'chromium',
  'google-chrome',
  '/opt/homebrew/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

function findBrowser() {
  for (const bin of candidates) {
    if (bin.includes(path.sep)) {
      if (fs.existsSync(bin)) return bin;
    } else {
      return bin;
    }
  }
  return 'chromium';
}

(async () => {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nzw-chrome-'));
  const chromeArgs = [
    '--headless=new',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--remote-debugging-port=0',
    `--user-data-dir=${userDataDir}`,
    'about:blank',
  ];
  if (process.env.NZW_ALLOW_UNSAFE_BROWSER_SANDBOX === '1') {
    chromeArgs.splice(1, 0, '--no-sandbox');
  }
  const chrome = spawn(findBrowser(), chromeArgs, { stdio: ['ignore', 'ignore', 'pipe'] });

  let ws;
  try {
    const wsUrl = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Chromium DevTools startup timed out')), 10000);
      let stderr = '';
      chrome.stderr.on('data', (chunk) => {
        stderr += chunk.toString();
        const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
        if (match) {
          clearTimeout(timer);
          resolve(match[1]);
        }
      });
      chrome.once('error', (err) => { clearTimeout(timer); reject(err); });
      chrome.once('exit', (code) => { clearTimeout(timer); reject(new Error(`Chromium exited early (${code}): ${stderr.trim()}`)); });
    });

    const baseHttp = wsUrl.replace(/^ws:/, 'http:').replace(/\/devtools\/browser\/.*$/, '');
    const versionRes = await fetch(`${baseHttp}/json/version`);
    const versionJson = versionRes.ok ? await versionRes.json() : {};
    const browserVersion = versionJson.Browser || null;

    const listRes = await fetch(`${baseHttp}/json/list`);
    const targets = await listRes.json();
    const pageTarget = targets.find((t) => t.type === 'page') || targets[0];
    if (!pageTarget || !pageTarget.webSocketDebuggerUrl) {
      throw new Error('No page target found in Chromium DevTools');
    }

    ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', (e) => reject(new Error('CDP WebSocket error')), { once: true });
    });

    let nextId = 1;
    const pending = new Map();
    const consoleErrors = [];
    const failedRequests = [];
    const reqUrls = new Map();
    let loadResolve = null;

    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message || 'CDP error'));
        else resolve(msg.result);
        return;
      }
      if (msg.method === 'Runtime.consoleAPICalled' && msg.params?.type === 'error') {
        const text = (msg.params.args || []).map((a) => a.value ?? a.description ?? '').join(' ').trim();
        consoleErrors.push({ level: 'error', text: text || 'console.error' });
      } else if (msg.method === 'Runtime.exceptionThrown') {
        const text = msg.params?.exceptionDetails?.text || 'Uncaught exception';
        consoleErrors.push({ level: 'exception', text });
      } else if (msg.method === 'Network.requestWillBeSent') {
        reqUrls.set(msg.params.requestId, msg.params.request?.url || '');
      } else if (msg.method === 'Network.loadingFailed') {
        failedRequests.push({
          url: reqUrls.get(msg.params.requestId) || '',
          error_text: msg.params.errorText || 'loading failed',
          status_code: null,
        });
      } else if (msg.method === 'Network.responseReceived' && msg.params?.response?.status >= 400) {
        failedRequests.push({
          url: msg.params.response.url || '',
          error_text: `HTTP ${msg.params.response.status}`,
          status_code: msg.params.response.status,
        });
      } else if (msg.method === 'Page.loadEventFired' && loadResolve) {
        loadResolve();
        loadResolve = null;
      }
    });

    const call = (method, params = {}) => new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });

    await call('Page.enable');
    await call('Runtime.enable');
    await call('Network.enable');

    const loaded = new Promise((resolve) => {
      loadResolve = resolve;
      setTimeout(resolve, 15000);
    });
    await call('Page.navigate', { url: targetUrl });
    await loaded;

    const finalRes = await call('Runtime.evaluate', { expression: 'window.location.href', returnByValue: true });
    const finalUrl = finalRes?.result?.value || targetUrl;

    const viewports = [];
    for (const vp of [
      { name: 'mobile', width: 390, height: 844 },
      { name: 'desktop', width: 1280, height: 720 },
    ]) {
      await call('Emulation.setDeviceMetricsOverride', {
        width: vp.width,
        height: vp.height,
        deviceScaleFactor: 1,
        mobile: vp.name === 'mobile',
      });
      const evalRes = await call('Runtime.evaluate', {
        expression: `(() => ({
          has_horizontal_overflow: document.documentElement.scrollWidth > window.innerWidth,
          broken_images: Array.from(document.images)
            .filter((img) => img.complete && img.naturalWidth === 0)
            .map((img) => ({ src: img.currentSrc || img.getAttribute('src') || '', natural_width: 0 })),
        }))()`,
        returnByValue: true,
      });
      const val = evalRes?.result?.value || { has_horizontal_overflow: false, broken_images: [] };
      viewports.push({
        viewport_name: vp.name,
        width: vp.width,
        height: vp.height,
        has_horizontal_overflow: Boolean(val.has_horizontal_overflow),
        broken_images: Array.isArray(val.broken_images) ? val.broken_images : [],
        screenshot_path: null,
      });
    }

    process.stdout.write(JSON.stringify({
      final_url: finalUrl,
      browser_version: browserVersion,
      console_errors: consoleErrors,
      failed_requests: failedRequests,
      viewports,
    }));
  } finally {
    if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    chrome.kill('SIGKILL');
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
})().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
";

/// Runs a headless Chromium CDP session against `target` within `timeout`.
///
/// Requires `node` (v22+ with built-in `WebSocket`) and a Chromium binary
/// (`NZW_CHROMIUM_BIN` or `chromium` / `google-chrome`).
pub async fn run_browser(
    target: &AuditTarget,
    timeout: Duration,
) -> CollectorOutcome<BrowserEvidence> {
    let mut cmd = Command::new("node");
    cmd.arg("-e").arg(CDP_HARNESS_JS).arg(target.as_str());

    let stdout = match run_bounded_command("browser", &mut cmd, timeout).await {
        Ok(out) => out,
        Err(error) => return CollectorOutcome::Failed { error },
    };

    match parse_browser_json(&stdout) {
        Ok(evidence) => CollectorOutcome::Captured { data: evidence },
        Err(error) => CollectorOutcome::Failed { error },
    }
}

/// Parses raw JSON produced by the browser adapter into [`BrowserEvidence`].
///
/// # Errors
///
/// Returns an error string if the payload is not valid [`BrowserEvidence`] JSON
/// or has an empty `final_url`.
pub fn parse_browser_json(raw: &str) -> Result<BrowserEvidence, String> {
    let evidence: BrowserEvidence =
        serde_json::from_str(raw).map_err(|e| format!("invalid browser evidence JSON: {e}"))?;
    if evidence.final_url.trim().is_empty() {
        return Err("browser evidence JSON has empty `final_url`".to_owned());
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_browser_evidence_json_fixture() {
        let raw = r#"{
            "final_url": "https://example.org/",
            "browser_version": "HeadlessChrome/131.0",
            "console_errors": [
                { "level": "error", "text": "Uncaught TypeError" }
            ],
            "failed_requests": [
                { "url": "https://example.org/missing.js", "error_text": "HTTP 404", "status_code": 404 }
            ],
            "viewports": [
                {
                    "viewport_name": "mobile",
                    "width": 390,
                    "height": 844,
                    "has_horizontal_overflow": true,
                    "broken_images": [{ "src": "/broken.png", "natural_width": 0 }],
                    "screenshot_path": null
                }
            ]
        }"#;

        let parsed = parse_browser_json(raw).unwrap();
        assert_eq!(parsed.final_url, "https://example.org/");
        assert_eq!(parsed.console_errors.len(), 1);
        assert_eq!(parsed.failed_requests.len(), 1);
        assert_eq!(parsed.viewports.len(), 1);
        assert!(parsed.viewports[0].has_horizontal_overflow);
    }

    #[test]
    fn rejects_empty_final_url() {
        let raw = r#"{
            "final_url": "   ",
            "browser_version": null,
            "console_errors": [],
            "failed_requests": [],
            "viewports": []
        }"#;
        assert!(parse_browser_json(raw).is_err());
    }
}
