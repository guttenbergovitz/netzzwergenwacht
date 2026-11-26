const TIMELINE_EVENT_LIMIT = 512;

function timelineToken(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value) ? value : null;
}

function timelineOrigin(value) {
  if (typeof value !== 'string' || value.length > 4096) return null;
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin.length <= 512
      ? url.origin : null;
  } catch {
    return null;
  }
}

function sanitizeEndpointPath(value) {
  if (typeof value !== 'string' || value.length > 4096) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    const pathname = url.pathname || '/';
    if (!pathname.startsWith('/') || /[\x00-\x1f\x7f?#]/.test(pathname)) return null;
    return pathname.length <= 256 ? pathname : pathname.slice(0, 256);
  } catch {
    return null;
  }
}

function timelineNumber(value, scale = 1) {
  if (typeof value !== 'number') return null;
  const number = Math.round(value * scale);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function timelineStatus(response) {
  const status = response?.status;
  return Number.isInteger(status) && status >= 100 && status <= 599 ? status : null;
}

function classifyCacheSource(response) {
  if (!response || typeof response !== 'object') return null;
  if (response.fromServiceWorker === true) return 'service_worker';
  if (response.fromPrefetchCache === true) return 'prefetch_cache';
  if (response.fromDiskCache === true) return 'disk_cache';
  if (response.status === 304) return 'revalidated_304';
  return 'network';
}

function extractPhaseTimings(timing) {
  if (!timing || typeof timing !== 'object') return null;
  const delta = (start, end) => {
    if (typeof start !== 'number' || typeof end !== 'number') return null;
    if (start < 0 || end < 0 || end < start) return null;
    const ms = Math.round(end - start);
    return Number.isSafeInteger(ms) && ms >= 0 ? ms : null;
  };
  const dns_ms = delta(timing.dnsStart, timing.dnsEnd);
  const connect_ms = delta(timing.connectStart, timing.connectEnd);
  const tls_ms = delta(timing.sslStart, timing.sslEnd);
  const send_ms = delta(timing.sendStart, timing.sendEnd);
  const ttfb_ms = typeof timing.receiveHeadersStart === 'number'
    ? delta(timing.sendEnd, timing.receiveHeadersStart)
    : delta(timing.sendEnd, timing.receiveHeadersEnd);
  if (dns_ms === null && connect_ms === null && tls_ms === null && send_ms === null && ttfb_ms === null) {
    return null;
  }
  return { dns_ms, connect_ms, tls_ms, send_ms, ttfb_ms };
}

function createBrowserTimeline() {
  const events = [];
  const hops = new Map();
  const policyBlocked = new Set();
  let truncated = false;

  function record(kind, params, details = {}, options = {}) {
    if (events.length >= TIMELINE_EVENT_LIMIT) {
      truncated = true;
      return;
    }
    const id = timelineToken(options.policy ? params.networkId : params.requestId);
    const runtime = kind === 'runtime_error';
    const timestamp = timelineNumber(params.timestamp, runtime ? 1_000 : 1_000_000);
    events.push({
      sequence: events.length + 1,
      kind,
      time: timestamp === null ? null : { clock: runtime ? 'unix' : 'monotonic', microseconds: timestamp },
      request: id === null ? null : { id, hop: hops.get(id) ?? null },
      frame: timelineToken(params.frameId),
      loader: timelineToken(params.loaderId),
      ...details,
    });
  }

  return {
    observe(method, params) {
      if (method === 'Network.requestWillBeSent') {
        const id = timelineToken(params.requestId);
        const redirect = params.redirectResponse && params.redirectResponse.status !== 304;
        if (redirect) {
          record('redirect', params, {
            status: timelineStatus(params.redirectResponse),
            origin: timelineOrigin(params.redirectResponse.url),
            endpoint_path: sanitizeEndpointPath(params.redirectResponse.url),
          });
        }
        if (id !== null && events.length < TIMELINE_EVENT_LIMIT) {
          const previous = hops.get(id);
          const hop = redirect ? (previous == null ? null : previous + 1) : 0;
          hops.set(id, hop);
        }
        record('request_started', params, {
          method: timelineToken(params.request?.method),
          origin: timelineOrigin(params.request?.url),
          endpoint_path: sanitizeEndpointPath(params.request?.url),
          resource_type: timelineToken(params.type ? String(params.type).toLowerCase() : null),
          initiator_type: timelineToken(params.initiator?.type ? String(params.initiator.type).toLowerCase() : null),
        });
      } else if (method === 'Network.responseReceived') {
        record('response', params, {
          status: timelineStatus(params.response),
          origin: timelineOrigin(params.response?.url),
          endpoint_path: sanitizeEndpointPath(params.response?.url),
          mime_type: typeof params.response?.mimeType === 'string' && params.response.mimeType.length <= 128
            ? params.response.mimeType.toLowerCase() : null,
          cache_source: classifyCacheSource(params.response),
          timings: extractPhaseTimings(params.response?.timing),
        });
      } else if (method === 'Network.loadingFinished') {
        record('completed', params, { encoded_bytes: timelineNumber(params.encodedDataLength) });
      } else if (method === 'Network.loadingFailed') {
        if (policyBlocked.delete(timelineToken(params.requestId))) return;
        record(params.blockedReason || params.corsErrorStatus ? 'browser_blocked'
          : params.canceled === true ? 'cancelled' : 'network_failure', params);
      }
    },
    runtime(params, category) {
      record('runtime_error', params, { category });
    },
    policyBlock(params) {
      const id = timelineToken(params.networkId);
      if (id !== null && events.length < TIMELINE_EVENT_LIMIT) policyBlocked.add(id);
      record(
        'policy_blocked',
        params,
        {
          origin: timelineOrigin(params.request?.url),
          endpoint_path: sanitizeEndpointPath(params.request?.url),
          resource_type: timelineToken(params.resourceType ? String(params.resourceType).toLowerCase() : null),
        },
        { policy: true }
      );
    },
    finish(loadTimedOut) {
      return { events, truncated, end: loadTimedOut ? 'load_timed_out' : 'observation_ended' };
    },
  };
}
