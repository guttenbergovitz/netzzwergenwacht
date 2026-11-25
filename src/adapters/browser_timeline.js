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

function timelineNumber(value, scale = 1) {
  if (typeof value !== 'number') return null;
  const number = Math.round(value * scale);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function timelineStatus(response) {
  const status = response?.status;
  return Number.isInteger(status) && status >= 100 && status <= 599 ? status : null;
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
        });
      } else if (method === 'Network.responseReceived') {
        record('response', params, {
          status: timelineStatus(params.response),
          origin: timelineOrigin(params.response?.url),
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
      record('policy_blocked', params, { origin: timelineOrigin(params.request?.url) }, { policy: true });
    },
    finish(loadTimedOut) {
      return { events, truncated, end: loadTimedOut ? 'load_timed_out' : 'observation_ended' };
    },
  };
}
