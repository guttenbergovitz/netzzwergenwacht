const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const create = vm.runInThisContext(
  fs.readFileSync('src/adapters/browser_timeline.js', 'utf8') + '\ncreateBrowserTimeline',
);
const timeline = create();
const request = {
  requestId: 'fixture.1',
  frameId: 'frame',
  loaderId: 'loader',
  timestamp: 1,
  request: { method: 'GET', url: 'https://user:secret@example.org/secret?secret#secret' },
};
timeline.observe('Network.requestWillBeSent', request);
timeline.observe('Network.responseReceived', {requestId: 'fixture.1', response: {status: 304}});
timeline.observe('Network.loadingFailed', {requestId: 'fixture.1', canceled: true});
timeline.policyBlock({networkId: 'fixture.1'});
timeline.observe('Network.loadingFailed', {requestId: 'fixture.1', blockedReason: 'inspector'});
timeline.observe('Network.loadingFailed', {requestId: 'fixture.2', blockedReason: 'csp'});
timeline.policyBlock({});
timeline.observe('Network.requestWillBeSent', {...request, requestId: 'unknown', redirectResponse: {status: 302}});
timeline.observe('Network.requestWillBeSent', {...request, requestId: 'unknown', redirectResponse: {status: 301}});
const observed = timeline.finish(false);
assert.deepEqual(observed.events.map(event => event.kind), [
  'request_started', 'response', 'cancelled', 'policy_blocked', 'browser_blocked',
  'policy_blocked', 'redirect', 'request_started', 'redirect', 'request_started',
]);
assert.equal(observed.events[1].status, 304);
assert.equal(observed.events[1].time, null);
assert.equal(observed.events[3].request.hop, 0);
assert.equal(observed.events[5].request, null);
assert.equal(observed.events[7].request.hop, null);
assert.equal(observed.events[9].request.hop, null);
assert.equal(observed.events[0].origin, 'https://example.org');
assert.equal(observed.events[0].time.microseconds, 1_000_000);
assert.ok(!JSON.stringify(observed).includes('secret'));
for (let index = 0; index < 600; index++) {
  timeline.runtime({timestamp: 1000}, 'console_error');
}
const capped = timeline.finish(true);
assert.equal(capped.events.length, 512);
assert.equal(capped.truncated, true);
assert.equal(capped.end, 'load_timed_out');
assert.deepEqual(capped.events[10].time, {clock: 'unix', microseconds: 1_000_000});
