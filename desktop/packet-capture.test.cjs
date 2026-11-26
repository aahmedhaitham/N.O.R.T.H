const assert = require('node:assert/strict');
const { test } = require('node:test');
const { makePacketCapture } = require('./packet-capture.cjs');

const prefix = 'north://app/api/desktop/capture/';
const device = '\\Device\\NPF_Loopback';

function start(seconds, options = {}) {
  const { marker = 'local', signal } = options;
  return new Request(prefix + 'start', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-North-Capture': marker },
    body: JSON.stringify({ device, seconds }), signal,
  });
}

test('desktop capture lists stable adapters and accepts live batches and quick captures', async () => {
  const durations = [];
  const capture = makePacketCapture({ isWindows: true, locate: async () => 'dumpcap',
    async execute(_executable, args) {
      if (args[0] === '-D') return { stdout: `1. ${device} (Loopback)` };
      assert.deepEqual(args.slice(0, 5), ['-i', device, '-y', 'NULL', '-p']);
      durations.push(args.find((value) => value.startsWith('duration:')));
      return { stdout: Buffer.alloc(28) };
    },
  });
  const listing = await capture(new Request(prefix + 'interfaces'));
  assert.deepEqual(await listing.json(), { interfaces: [{ device, label: 'Loopback' }] });
  for (const seconds of [3, 10]) {
    const response = await capture(start(seconds));
    assert.equal(response.status, 200);
    assert.equal((await response.arrayBuffer()).byteLength, 28);
  }
  assert.deepEqual(durations, ['duration:3', 'duration:10']);
  assert.equal((await capture(start(3, { marker: '' }))).status, 403);
  assert.equal((await capture(start(31))).status, 422);
  const controller = new AbortController();
  controller.abort();
  assert.equal((await capture(start(3, { signal: controller.signal }))).status, 204);
  assert.equal(durations.length, 2);
});
