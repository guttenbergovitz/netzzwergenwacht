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
    const hydrationErrors = [];
    const failedRequests = [];
    const reqUrls = new Map();
    const reqMeta = new Map();
    const resourcesByReqId = new Map();
    const stylesheetUrls = new Map();
    let navStartTs = null;
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
      if (msg.method === 'Runtime.consoleAPICalled' && (msg.params?.type === 'error' || msg.params?.type === 'warning')) {
        const text = (msg.params.args || []).map((a) => a.value ?? a.description ?? '').join(' ').trim();
        const lower = text.toLowerCase();
        if (lower.includes('hydration') || lower.includes('did not match')) {
          hydrationErrors.push(text || 'hydration mismatch');
        }
        if (msg.params?.type === 'error') {
          const isCsp = lower.includes('content security policy') || lower.includes('refused to ');
          consoleErrors.push({
            level: 'error',
            text: text || 'console.error',
            error_kind: isCsp ? 'csp_violation' : 'console_error',
            source_url: msg.params?.stackTrace?.callFrames?.[0]?.url || null,
            line_number: typeof msg.params?.stackTrace?.callFrames?.[0]?.lineNumber === 'number'
              ? msg.params.stackTrace.callFrames[0].lineNumber + 1
              : null,
          });
        }
      } else if (msg.method === 'Runtime.exceptionThrown') {
        const details = msg.params?.exceptionDetails || {};
        const text = details.exception?.description || details.text || 'Uncaught exception';
        const lower = text.toLowerCase();
        if (lower.includes('hydration') || lower.includes('did not match')) {
          hydrationErrors.push(text);
        }
        const isRejection = (details.text || '').toLowerCase().includes('in promise') || lower.includes('unhandledrejection');
        consoleErrors.push({
          level: 'exception',
          text,
          error_kind: isRejection ? 'unhandled_rejection' : 'uncaught_exception',
          source_url: details.url || null,
          line_number: typeof details.lineNumber === 'number' ? details.lineNumber + 1 : null,
        });
      } else if (msg.method === 'Network.requestWillBeSent') {
        if (navStartTs === null && typeof msg.params.timestamp === 'number') {
          navStartTs = msg.params.timestamp;
        }
        reqUrls.set(msg.params.requestId, msg.params.request?.url || '');
        reqMeta.set(msg.params.requestId, {
          initiator_type: msg.params.initiator?.type ? String(msg.params.initiator.type).toLowerCase() : null,
          initiator_url: msg.params.initiator?.url || msg.params.initiator?.stack?.callFrames?.[0]?.url || null,
          start_time_ms: (navStartTs !== null && typeof msg.params.timestamp === 'number')
            ? Math.max(0, Math.round((msg.params.timestamp - navStartTs) * 1000))
            : null,
          priority: msg.params.request?.initialPriority || null,
          start_ts: typeof msg.params.timestamp === 'number' ? msg.params.timestamp : null,
        });
      } else if (msg.method === 'CSS.styleSheetAdded') {
        const hdr = msg.params?.header;
        if (hdr?.styleSheetId) {
          stylesheetUrls.set(hdr.styleSheetId, hdr.sourceURL || 'inline');
        }
      } else if (msg.method === 'Network.loadingFailed') {
        failedRequests.push({
          url: reqUrls.get(msg.params.requestId) || '',
          error_text: msg.params.errorText || 'loading failed',
          status_code: null,
        });
      } else if (msg.method === 'Network.responseReceived') {
        const resp = msg.params?.response;
        const rUrl = resp?.url || '';
        const meta = reqMeta.get(msg.params.requestId) || {};
        if (resp?.status >= 400) {
          failedRequests.push({
            url: rUrl,
            error_text: `HTTP ${resp.status}`,
            status_code: resp.status,
          });
        }
        const headers = Object.fromEntries(
          Object.entries(resp?.headers || {}).map(([k, v]) => [k.toLowerCase(), String(v)])
        );
        resourcesByReqId.set(msg.params.requestId, {
          url: rUrl,
          resource_type: String(msg.params?.type || 'other').toLowerCase(),
          request_id: msg.params.requestId || null,
          initiator_type: meta.initiator_type || null,
          initiator_url: meta.initiator_url || null,
          start_time_ms: meta.start_time_ms ?? null,
          status_code: typeof resp?.status === 'number' ? resp.status : null,
          priority: meta.priority || null,
          mime_type: resp?.mimeType || null,
          transfer_size: null,
          duration_ms: null,
          protocol: resp?.protocol || null,
          cache_control: headers['cache-control'] || null,
          content_encoding: headers['content-encoding'] || null,
        });
      } else if (msg.method === 'Network.loadingFinished') {
        const rec = resourcesByReqId.get(msg.params.requestId);
        const meta = reqMeta.get(msg.params.requestId);
        if (rec) {
          if (typeof msg.params.encodedDataLength === 'number') {
            rec.transfer_size = Math.max(0, Math.round(msg.params.encodedDataLength));
          }
          if (meta?.start_ts !== null && typeof msg.params.timestamp === 'number') {
            rec.duration_ms = Math.max(0, Math.round((msg.params.timestamp - meta.start_ts) * 1000));
          }
        }
      } else if (msg.method === 'Fetch.requestPaused') {
        const reqUrl = msg.params?.request?.url || '';
        const blocked = isForbiddenSubresourceUrl(reqUrl);
        if (blocked) {
          failedRequests.push({ url: reqUrl, error_text: 'BlockedByPolicy', status_code: null });
          ws.send(JSON.stringify({
            id: nextId++,
            method: 'Fetch.failRequest',
            params: { requestId: msg.params.requestId, errorReason: 'BlockedByClient' },
          }));
        } else {
          ws.send(JSON.stringify({
            id: nextId++,
            method: 'Fetch.continueRequest',
            params: { requestId: msg.params.requestId },
          }));
        }
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

    const isForbiddenSubresourceUrl = (raw) => {
      if (process.env.NZW_BROWSER_POLICY !== 'public_only') return false;
      try {
        const u = new URL(raw);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return false; // allow data:/blob:
        const h = u.hostname.toLowerCase();
        return h === 'localhost'
          || h.endsWith('.local')
          || h === '::1'
          || /^127\./.test(h)
          || /^10\./.test(h)
          || /^192\.168\./.test(h)
          || /^169\.254\./.test(h)
          || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h);
      } catch {
        return true;
      }
    };

    await call('Page.enable');
    await call('Runtime.enable');
    await call('Network.enable');
    try {
      await call('Profiler.enable');
      await call('Profiler.startPreciseCoverage', { callCount: false, detailed: true });
    } catch {}
    try {
      await call('DOM.enable');
      await call('CSS.enable');
      await call('CSS.startRuleUsageTracking');
    } catch {}
    await call('Page.addScriptToEvaluateOnNewDocument', {
      source: `window.__nzwCspViolations = [];
      window.addEventListener('securitypolicyviolation', (e) => { if (window.__nzwCspViolations.length < 50) window.__nzwCspViolations.push({ directive: e.violatedDirective || '', blocked_uri: e.blockedURI || '', source_file: e.sourceFile || null, line_number: e.lineNumber || null }); });
      window.__nzwPerf = { lcpMs: null, lcpElement: null, lcpUrl: null, cls: 0, shiftCount: 0, longTaskCount: 0, longTaskTotalMs: 0, maxLongTaskMs: 0 };
      try {
        new PerformanceObserver((list) => {
          for (const e of list.getEntries()) {
            window.__nzwPerf.lcpMs = Math.round(e.startTime);
            window.__nzwPerf.lcpElement = e.element ? (e.element.tagName.toLowerCase() + (e.element.id ? '#' + e.element.id : '')) : null;
            window.__nzwPerf.lcpUrl = e.url || null;
          }
        }).observe({ type: 'largest-contentful-paint', buffered: true });
        new PerformanceObserver((list) => {
          for (const e of list.getEntries()) {
            if (!e.hadRecentInput) { window.__nzwPerf.cls += e.value || 0; window.__nzwPerf.shiftCount++; }
          }
        }).observe({ type: 'layout-shift', buffered: true });
        new PerformanceObserver((list) => {
          for (const e of list.getEntries()) {
            const d = Math.round(e.duration || 0);
            window.__nzwPerf.longTaskCount++;
            window.__nzwPerf.longTaskTotalMs += d;
            if (d > window.__nzwPerf.maxLongTaskMs) window.__nzwPerf.maxLongTaskMs = d;
          }
        }).observe({ type: 'longtask', buffered: true });
      } catch {}`,
    });
    if (process.env.NZW_BROWSER_POLICY === 'public_only') {
      await call('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
    }

    let loadTimedOut = false;
    const loaded = new Promise((resolve) => {
      loadResolve = resolve;
      setTimeout(() => {
        loadTimedOut = true;
        resolve();
      }, 15000);
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
        expression: `(() => {
          let smallText = 0;
          for (const el of Array.from(document.querySelectorAll('p, span, a, li, td, label, button')).slice(0, 250)) {
            if (!el.textContent || !el.textContent.trim()) continue;
            const r = el.getBoundingClientRect();
            if (r.width <= 0 || r.height <= 0) continue;
            const fs = parseFloat(getComputedStyle(el).fontSize || '16');
            if (fs > 0 && fs < 12) smallText++;
          }
          let smallTap = 0;
          let offscreenControls = 0;
          for (const el of Array.from(document.querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea')).slice(0, 200)) {
            const r = el.getBoundingClientRect();
            if (r.width > 0 && r.height > 0) {
              if (r.width < 44 || r.height < 44) smallTap++;
              if (r.right < 0 || r.left > window.innerWidth) offscreenControls++;
            }
          }
          let fixedTopHeight = 0;
          for (const el of Array.from(document.querySelectorAll('header, nav, [role=\'banner\'], div')).slice(0, 120)) {
            const cs = getComputedStyle(el);
            if (cs.position === 'fixed' || cs.position === 'sticky') {
              const r = el.getBoundingClientRect();
              if (r.top <= 40 && r.height > 0 && r.width > window.innerWidth * 0.5) {
                if (r.height > fixedTopHeight) fixedTopHeight = r.height;
              }
            }
          }
          const fixedPct = window.innerHeight > 0 ? Math.min(100, Math.round((fixedTopHeight / window.innerHeight) * 100)) : 0;
          return {
            has_horizontal_overflow: document.documentElement.scrollWidth > window.innerWidth,
            broken_images: Array.from(document.images)
              .filter((img) => img.complete && img.naturalWidth === 0)
              .map((img) => ({ src: img.currentSrc || img.getAttribute('src') || '', natural_width: 0 })),
            small_text_nodes: smallText,
            small_tap_targets: smallTap,
            offscreen_controls: offscreenControls,
            fixed_header_height_pct: fixedPct,
          };
        })()`,
        returnByValue: true,
      });
      const val = evalRes?.result?.value || { has_horizontal_overflow: false, broken_images: [], small_text_nodes: 0, small_tap_targets: 0, offscreen_controls: 0, fixed_header_height_pct: 0 };
      viewports.push({
        viewport_name: vp.name,
        width: vp.width,
        height: vp.height,
        has_horizontal_overflow: Boolean(val.has_horizontal_overflow),
        broken_images: Array.isArray(val.broken_images) ? val.broken_images : [],
        small_text_nodes: Number(val.small_text_nodes || 0),
        small_tap_targets: Number(val.small_tap_targets || 0),
        offscreen_controls: Number(val.offscreen_controls || 0),
        fixed_header_height_pct: Number(val.fixed_header_height_pct || 0),
        screenshot_path: null,
      });
    }

    const domAndImagesRes = await call('Runtime.evaluate', {
      expression: `(() => {
        const vh = window.innerHeight || 720;
        const vw = window.innerWidth || 1280;
        const imgs = Array.from(document.images).slice(0, 100).map((img) => {
          const r = img.getBoundingClientRect();
          const inVp = r.width > 0 && r.height > 0 && r.top < vh && r.bottom > 0 && r.left < vw && r.right > 0;
          return {
            src: img.currentSrc || img.getAttribute('src') || '',
            natural_width: Math.round(img.naturalWidth || 0),
            natural_height: Math.round(img.naturalHeight || 0),
            rendered_width: Math.round(r.width || 0),
            rendered_height: Math.round(r.height || 0),
            in_initial_viewport: inVp,
            loading: img.getAttribute('loading') || null,
          };
        });
        const renderedText = (document.body?.innerText || '').trim();
        const renderedWords = renderedText ? renderedText.split(/\s+/).length : 0;
        const nav = performance.getEntriesByType('navigation')[0];
        const p = window.__nzwPerf || {};
        const pos = (v) => (typeof v === 'number' && v >= 0 ? Math.round(v) : null);
        const perfObs = nav ? {
          dns_ms: pos(nav.domainLookupEnd - nav.domainLookupStart),
          tcp_ms: pos(nav.connectEnd - nav.connectStart),
          tls_ms: nav.secureConnectionStart > 0 ? pos(nav.connectEnd - nav.secureConnectionStart) : null,
          ttfb_ms: pos(nav.responseStart - nav.requestStart),
          download_ms: pos(nav.responseEnd - nav.responseStart),
          dom_interactive_ms: pos(nav.domInteractive),
          dom_content_loaded_ms: pos(nav.domContentLoadedEventEnd),
          load_event_ms: pos(nav.loadEventEnd),
          lcp_ms: p.lcpMs ?? null,
          lcp_element: p.lcpElement || null,
          lcp_url: p.lcpUrl || null,
          cls_thousandths: typeof p.cls === 'number' ? Math.round(p.cls * 1000) : null,
          layout_shift_count: p.shiftCount || 0,
          long_task_count: p.longTaskCount || 0,
          long_task_total_ms: p.longTaskTotalMs || 0,
          max_long_task_ms: p.maxLongTaskMs || 0,
        } : null;
        let safeCount = (fn) => { try { return fn(); } catch { return 0; } };
        const storageSummary = {
          local_storage_keys: safeCount(() => window.localStorage.length),
          session_storage_keys: safeCount(() => window.sessionStorage.length),
          document_cookie_count: safeCount(() => document.cookie ? document.cookie.split(';').filter((c) => c.trim().length > 0).length : 0),
        };
        return {
          rendered_dom_elements: document.querySelectorAll('*').length,
          rendered_images: imgs,
          rendered_images_truncated: document.images.length > 100,
          rendered_word_count: renderedWords,
          csp_violations: Array.isArray(window.__nzwCspViolations) ? window.__nzwCspViolations : [],
          performance: perfObs,
          storage_summary: storageSummary,
        };
      })()`,
      returnByValue: true,
    });
    const domAndImages = domAndImagesRes?.result?.value || {};
    let axTreeSummary = null;
    try {
      await call('Accessibility.enable');
      const axRes = await call('Accessibility.getFullAXTree');
      const nodes = Array.isArray(axRes?.nodes) ? axRes.nodes : [];
      const capped = nodes.slice(0, 5000);
      const interactiveRoles = new Set(['button', 'link', 'textbox', 'checkbox', 'radio', 'combobox', 'menuitem', 'tab', 'switch', 'slider']);
      let ignoredNodes = 0;
      let interactiveWithoutName = 0;
      let hiddenFocusable = 0;
      for (const n of capped) {
        if (n.ignored) ignoredNodes++;
        const role = String(n.role?.value || '').toLowerCase();
        const name = String(n.name?.value || '').trim();
        if (!n.ignored && interactiveRoles.has(role) && !name) interactiveWithoutName++;
        const isFocusable = Array.isArray(n.properties) && n.properties.some((pr) => pr.name === 'focusable' && pr.value?.value === true);
        if (n.ignored && isFocusable) hiddenFocusable++;
      }
      axTreeSummary = {
        total_nodes: capped.length,
        ignored_nodes: ignoredNodes,
        interactive_without_name: interactiveWithoutName,
        hidden_focusable_count: hiddenFocusable,
        truncated: nodes.length > 5000,
      };
    } catch {}
    const computeDisjointUsedBytes = (flatRanges) => {
      if (flatRanges.length === 0) return 0;
      flatRanges.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
      const stack = [];
      let pos = 0;
      let used = 0;
      for (const r of flatRanges) {
        while (stack.length > 0 && stack[stack.length - 1].end <= r.start) {
          const top = stack.pop();
          if (top.end > pos && top.count > 0) used += (top.end - pos);
          if (top.end > pos) pos = top.end;
        }
        if (stack.length > 0 && r.start > pos) {
          if (stack[stack.length - 1].count > 0) used += (r.start - pos);
          pos = r.start;
        } else if (r.start > pos) {
          pos = r.start;
        }
        stack.push(r);
      }
      while (stack.length > 0) {
        const top = stack.pop();
        if (top.end > pos && top.count > 0) used += (top.end - pos);
        if (top.end > pos) pos = top.end;
      }
      return used;
    };
    let coverageSummary = {
      js_total_bytes: 0,
      js_used_bytes: 0,
      css_total_bytes: 0,
      css_used_bytes: 0,
      js_scripts_sampled: 0,
      css_rules_sampled: 0,
      top_unused_scripts: [],
      top_unused_stylesheets: [],
    };
    let hasCoverage = false;
    try {
      const jsCov = await call('Profiler.takePreciseCoverage');
      const scripts = Array.isArray(jsCov?.result) ? jsCov.result : [];
      const perScript = [];
      for (const s of scripts) {
        let maxEnd = 0;
        const flat = [];
        for (const fn of Array.isArray(s.functions) ? s.functions : []) {
          for (const r of Array.isArray(fn.ranges) ? fn.ranges : []) {
            if (typeof r.startOffset === 'number' && typeof r.endOffset === 'number' && r.endOffset > r.startOffset) {
              if (r.endOffset > maxEnd) maxEnd = r.endOffset;
              flat.push({ start: r.startOffset, end: r.endOffset, count: Number(r.count || 0) });
            }
          }
        }
        if (maxEnd > 0) {
          const used = computeDisjointUsedBytes(flat);
          coverageSummary.js_scripts_sampled++;
          coverageSummary.js_total_bytes += maxEnd;
          coverageSummary.js_used_bytes += used;
          perScript.push({ url: s.url || 'inline', total_bytes: maxEnd, used_bytes: used });
        }
      }
      perScript.sort((a, b) => (b.total_bytes - b.used_bytes) - (a.total_bytes - a.used_bytes));
      coverageSummary.top_unused_scripts = perScript.slice(0, 15);
      await call('Profiler.stopPreciseCoverage');
      hasCoverage = true;
    } catch {}
    try {
      const cssCov = await call('CSS.stopRuleUsageTracking');
      const rules = Array.isArray(cssCov?.ruleUsage) ? cssCov.ruleUsage : [];
      const bySheet = new Map();
      for (const r of rules) {
        if (typeof r.startOffset === 'number' && typeof r.endOffset === 'number' && r.endOffset > r.startOffset) {
          const len = r.endOffset - r.startOffset;
          coverageSummary.css_rules_sampled++;
          coverageSummary.css_total_bytes += len;
          if (r.used) coverageSummary.css_used_bytes += len;
          const sid = r.styleSheetId || 'inline';
          const entry = bySheet.get(sid) || { url: stylesheetUrls.get(sid) || 'inline', total_bytes: 0, used_bytes: 0 };
          entry.total_bytes += len;
          if (r.used) entry.used_bytes += len;
          bySheet.set(sid, entry);
        }
      }
      const perSheet = Array.from(bySheet.values());
      perSheet.sort((a, b) => (b.total_bytes - b.used_bytes) - (a.total_bytes - a.used_bytes));
      coverageSummary.top_unused_stylesheets = perSheet.slice(0, 15);
      hasCoverage = true;
    } catch {}
    let behaviouralA11y = null;
    let behObs = {
      tab_stops_observed: 0,
      tabbable_candidates: 0,
      focus_trap_detected: false,
      missing_focus_indicator_count: 0,
      open_dialogs_count: 0,
      dialog_escape_closed: null,
      focus_sequence: [],
      tab_budget_exhausted: false,
      modal_focus_escaped: false,
      obscured_focus_count: 0,
      focus_lost_after_dialog_close: null,
      skip_link_effective: null,
      unfocusable_aria_controls_count: 0,
    };
    let hasBeh = false;
    try {
      const preBehRes = await call('Runtime.evaluate', {
        expression: `(() => {
          const vis = (el) => { const r = el.getBoundingClientRect(); const st = getComputedStyle(el); return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none'; };
          const candidates = Array.from(document.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]')).filter((el) => el.getAttribute('tabindex') !== '-1' && vis(el)).length;
          const dialogs = Array.from(document.querySelectorAll('dialog[open], [aria-modal=true]')).filter(vis).length;
          const unfocusableAria = Array.from(document.querySelectorAll('[role=button], [role=link]')).filter((el) => {
            if (!vis(el)) return false;
            const tag = el.tagName.toLowerCase();
            if (tag === 'button' || (tag === 'a' && el.hasAttribute('href')) || tag === 'input' || tag === 'summary') return false;
            const ti = el.getAttribute('tabindex');
            return ti === null || Number(ti) < 0;
          }).length;
          return { candidates, dialogs, unfocusableAria };
        })()`,
        returnByValue: true,
      });
      const preBeh = preBehRes?.result?.value || {};
      behObs.tabbable_candidates = Number(preBeh.candidates || 0);
      behObs.open_dialogs_count = Number(preBeh.dialogs || 0);
      behObs.unfocusable_aria_controls_count = Number(preBeh.unfocusableAria || 0);
      const seenStops = new Set();
      const seq = [];
      let trappedInModalOnly = true;
      let tabPresses = 0;
      let brokeEarly = false;
      for (let step = 0; step < 25; step++) {
        tabPresses++;
        await call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
        await call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
        const focusRes = await call('Runtime.evaluate', {
          expression: `(() => {
            const el = document.activeElement;
            if (!el || el === document.body || el === document.documentElement) return null;
            const idPart = el.id ? '#' + el.id : '';
            const rect = el.getBoundingClientRect();
            const key = el.tagName.toLowerCase() + idPart + '@' + Math.round(rect.left) + ',' + Math.round(rect.top);
            const st = getComputedStyle(el);
            const focusVis = el.matches(':focus-visible');
            const noOutline = st.outlineStyle === 'none' || parseFloat(st.outlineWidth || '0') === 0;
            const noShadow = !st.boxShadow || st.boxShadow === 'none';
            const noBorder = st.borderTopStyle === 'none' || parseFloat(st.borderTopWidth || '0') === 0 || st.borderTopColor === 'rgba(0, 0, 0, 0)';
            const inDialog = Boolean(el.closest('dialog[open], [aria-modal=true]'));
            let obscured = false;
            if (rect.width > 2 && rect.height > 2) {
              const pts = [
                [rect.left + rect.width / 2, rect.top + rect.height / 2],
                [rect.left + 2, rect.top + 2],
                [rect.right - 2, rect.bottom - 2],
              ];
              let blocked = 0;
              for (const [px, py] of pts) {
                const cx = Math.min(Math.max(px, 0), window.innerWidth - 1);
                const cy = Math.min(Math.max(py, 0), window.innerHeight - 1);
                const hit = document.elementFromPoint(cx, cy);
                if (hit && !el.contains(hit) && !hit.contains(el)) blocked++;
              }
              if (blocked >= 2) obscured = true;
            }
            return { key, missingIndicator: Boolean(focusVis && noOutline && noShadow && noBorder), inDialog, obscured };
          })()`,
          returnByValue: true,
        });
        const info = focusRes?.result?.value;
        if (info && info.key) {
          if (behObs.open_dialogs_count > 0 && !info.inDialog) {
            behObs.modal_focus_escaped = true;
          }
          if (!info.inDialog) trappedInModalOnly = false;
          if (!seenStops.has(info.key)) {
            seenStops.add(info.key);
            if (info.missingIndicator) behObs.missing_focus_indicator_count++;
            if (info.obscured) behObs.obscured_focus_count++;
          }
          seq.push(info.key);
          if (seq.length >= 4 && seq.slice(-3).every((k) => k === info.key)) {
            if (!(behObs.open_dialogs_count > 0 && trappedInModalOnly)) behObs.focus_trap_detected = true;
            brokeEarly = true;
            break;
          }
          if (seq.length >= 6 && new Set(seq.slice(-6)).size <= 2 && behObs.tabbable_candidates > 3) {
            if (!(behObs.open_dialogs_count > 0 && trappedInModalOnly)) behObs.focus_trap_detected = true;
            brokeEarly = true;
            break;
          }
        }
      }
      behObs.focus_sequence = seq;
      behObs.tab_budget_exhausted = tabPresses === 25 && !brokeEarly;
      behObs.tab_stops_observed = seenStops.size;
      if (behObs.open_dialogs_count > 0) {
        await call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
        await call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
        const afterEsc = await call('Runtime.evaluate', {
          expression: `(() => {
            const openCount = Array.from(document.querySelectorAll('dialog[open], [aria-modal=true]')).filter((el) => { const r = el.getBoundingClientRect(); const st = getComputedStyle(el); return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none'; }).length;
            const ae = document.activeElement;
            const lostFocus = !ae || ae === document.body || ae === document.documentElement;
            return { openCount, lostFocus };
          })()`,
          returnByValue: true,
        });
        const escInfo = afterEsc?.result?.value || {};
        behObs.dialog_escape_closed = Number(escInfo.openCount || 0) < behObs.open_dialogs_count;
        if (behObs.dialog_escape_closed) {
          behObs.focus_lost_after_dialog_close = Boolean(escInfo.lostFocus);
        }
      }
      const skipRes = await call('Runtime.evaluate', {
        expression: `(() => {
          const links = Array.from(document.querySelectorAll('a[href]')).filter((a) => (a.getAttribute('href') || '').startsWith('#')).slice(0, 5);
          const skip = links.find((a) => /skip|main|content|sprung|inhalt/i.test((a.textContent || '') + ' ' + (a.getAttribute('aria-label') || '')));
          if (!skip) return null;
          const targetId = (skip.getAttribute('href') || '').slice(1);
          const target = targetId ? document.getElementById(targetId) : null;
          if (!target) return false;
          const prevY = window.scrollY;
          skip.click();
          const ae = document.activeElement;
          return target === ae || target.contains(ae) || window.scrollY !== prevY;
        })()`,
        returnByValue: true,
      });
      if (typeof skipRes?.result?.value === 'boolean') {
        behObs.skip_link_effective = skipRes.result.value;
      }
      hasBeh = true;
    } catch {}
    for (const v of Array.isArray(domAndImages.csp_violations) ? domAndImages.csp_violations : []) {
      consoleErrors.push({
        level: 'error',
        text: `CSP violation (${v.directive}): blocked ${v.blocked_uri}`,
        error_kind: 'csp_violation',
        source_url: v.source_file || null,
        line_number: typeof v.line_number === 'number' && v.line_number > 0 ? v.line_number : null,
      });
    }
    const allResources = Array.from(resourcesByReqId.values());
    const resourcesTruncated = allResources.length > 200;
    const resources = allResources.slice(0, 200);

    process.stdout.write(JSON.stringify({
      final_url: finalUrl,
      browser_version: browserVersion,
      load_timed_out: loadTimedOut,
      console_errors: consoleErrors,
      hydration_errors: hydrationErrors,
      failed_requests: failedRequests,
      viewports,
      resources,
      resources_truncated: resourcesTruncated,
      rendered_images: Array.isArray(domAndImages.rendered_images) ? domAndImages.rendered_images : [],
      rendered_images_truncated: Boolean(domAndImages.rendered_images_truncated),
      rendered_dom_elements: typeof domAndImages.rendered_dom_elements === 'number' ? domAndImages.rendered_dom_elements : null,
      rendered_word_count: typeof domAndImages.rendered_word_count === 'number' ? domAndImages.rendered_word_count : null,
      ax_tree: axTreeSummary,
      performance: domAndImages.performance || null,
      storage_summary: domAndImages.storage_summary || null,
      coverage: hasCoverage ? coverageSummary : null,
      behavioural_a11y: hasBeh ? behObs : behaviouralA11y,
      provenance: {
        viewport: 'mobile (390x844), desktop (1280x720)',
        throttling_profile: 'unthrottled',
        origin: 'lab',
        captured_at: new Date().toISOString(),
      },
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

/// Runs a headless Chromium CDP session against `target` within `timeout`
/// using [`crate::domain::TargetPolicy::PublicOnly`].
///
/// Requires `node` (v22+ with built-in `WebSocket`) and a Chromium binary
/// (`NZW_CHROMIUM_BIN` or `chromium` / `google-chrome`).
pub async fn run_browser(
    target: &AuditTarget,
    timeout: Duration,
) -> CollectorOutcome<BrowserEvidence> {
    run_browser_with_policy(target, timeout, crate::domain::TargetPolicy::PublicOnly).await
}

/// Runs a headless Chromium CDP session against `target` within `timeout`,
/// propagating `policy` to the CDP `Fetch` subresource/redirect guard.
pub async fn run_browser_with_policy(
    target: &AuditTarget,
    timeout: Duration,
    policy: crate::domain::TargetPolicy,
) -> CollectorOutcome<BrowserEvidence> {
    let policy_env = match policy {
        crate::domain::TargetPolicy::PublicOnly => "public_only",
        crate::domain::TargetPolicy::AllowPrivate => "allow_private",
    };
    let mut cmd = Command::new("node");
    cmd.arg("-e")
        .arg(CDP_HARNESS_JS)
        .arg(target.as_str())
        .env("NZW_BROWSER_POLICY", policy_env);

    let stdout = match run_bounded_command("browser", &mut cmd, timeout).await {
        Ok(out) => out,
        Err(error) => return CollectorOutcome::Failed { error },
    };

    parse_browser_outcome(&stdout)
}

#[derive(Debug, serde::Deserialize)]
struct RawBrowserOutput {
    #[serde(default)]
    load_timed_out: bool,
    #[serde(flatten)]
    evidence: BrowserEvidence,
}

/// Parses raw JSON produced by the browser adapter into a [`CollectorOutcome`].
///
/// Returns [`CollectorOutcome::Partial`] when `load_timed_out` is `true` so
/// downstream analysers know `Page.loadEventFired` did not complete within
/// the navigation deadline.
#[must_use]
pub fn parse_browser_outcome(raw: &str) -> CollectorOutcome<BrowserEvidence> {
    let parsed: RawBrowserOutput = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return CollectorOutcome::Failed {
                error: format!("invalid browser evidence JSON: {e}"),
            };
        }
    };
    if parsed.evidence.final_url.trim().is_empty() {
        return CollectorOutcome::Failed {
            error: "browser evidence JSON has empty `final_url`".to_owned(),
        };
    }
    let mut warnings = Vec::new();
    if parsed.load_timed_out {
        warnings.push(
            "Page.loadEventFired timed out after 15000 ms; DOM metrics captured before full load"
                .to_owned(),
        );
    }
    if parsed.evidence.resources_truncated {
        warnings.push(
            "Browser subresource list truncated at 200 entries; waterfall analysis is partial"
                .to_owned(),
        );
    }
    if parsed.evidence.rendered_images_truncated {
        warnings.push(
            "Rendered image list truncated at 100 entries; image geometry analysis is partial"
                .to_owned(),
        );
    }
    if parsed
        .evidence
        .ax_tree
        .as_ref()
        .is_some_and(|t| t.truncated)
    {
        warnings.push(
            "Accessibility tree truncated at 5000 nodes; AX tree analysis is partial".to_owned(),
        );
    }
    if warnings.is_empty() {
        CollectorOutcome::Captured {
            data: parsed.evidence,
        }
    } else {
        CollectorOutcome::Partial {
            data: parsed.evidence,
            warnings,
        }
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
        assert!(matches!(
            parse_browser_outcome(raw),
            CollectorOutcome::Failed { .. }
        ));
    }

    #[test]
    fn load_timed_out_produces_partial_outcome_with_warning() {
        let raw = r#"{
            "final_url": "https://example.org/",
            "browser_version": "HeadlessChrome/131.0",
            "load_timed_out": true,
            "console_errors": [],
            "failed_requests": [],
            "viewports": []
        }"#;
        match parse_browser_outcome(raw) {
            CollectorOutcome::Partial { data, warnings } => {
                assert_eq!(data.final_url, "https://example.org/");
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].contains("Page.loadEventFired timed out"));
            }
            other => panic!("expected Partial outcome, got {other:?}"),
        }
    }

    #[test]
    fn load_completed_produces_captured_outcome() {
        let raw = r#"{
            "final_url": "https://example.org/",
            "browser_version": "HeadlessChrome/131.0",
            "load_timed_out": false,
            "console_errors": [],
            "failed_requests": [],
            "viewports": []
        }"#;
        assert!(matches!(
            parse_browser_outcome(raw),
            CollectorOutcome::Captured { .. }
        ));
    }

    #[test]
    fn truncated_resources_or_images_produce_partial_outcome() {
        let raw = r#"{
            "final_url": "https://example.org/",
            "browser_version": "HeadlessChrome/131.0",
            "load_timed_out": false,
            "resources_truncated": true,
            "rendered_images_truncated": true,
            "console_errors": [],
            "failed_requests": [],
            "viewports": []
        }"#;
        match parse_browser_outcome(raw) {
            CollectorOutcome::Partial { data, warnings } => {
                assert!(data.resources_truncated);
                assert!(data.rendered_images_truncated);
                assert_eq!(warnings.len(), 2);
            }
            other => panic!("expected Partial outcome, got {other:?}"),
        }
    }
}
