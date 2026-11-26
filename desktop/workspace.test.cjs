const assert = require('node:assert/strict');
const test = require('node:test');
const { desktopStartup, workspaceOrigin, parseWorkspaceConnection } = require('./workspace.cjs');

test('accepts an HTTPS workspace origin only', () => {
  assert.equal(workspaceOrigin(' https://north.example.com/ '), 'https://north.example.com');
  for (const address of [
    'http://north.example.com', 'file:///secrets', 'https://user:pass@north.example.com',
    'https://north.example.com/api/cloud/status', 'https://north.example.com/?x=1', null,
  ]) assert.throws(() => workspaceOrigin(address));
});

test('cloud-only startup uses a bundled HTTPS service origin', () => {
  assert.deepEqual(desktopStartup(), { cloudOnly: false });
  assert.deepEqual(desktopStartup({ cloudOnly: true, origin: 'https://north.example.com/' }),
    { cloudOnly: true, origin: 'https://north.example.com' });
  assert.throws(() => desktopStartup({ cloudOnly: true }));
  assert.throws(() => desktopStartup({ cloudOnly: true, origin: 'http://north.example.com' }));
});

test('workspace setup rejects malformed and oversized IPC data', () => {
  assert.equal(parseWorkspaceConnection(' https://north.example.com/ '), 'https://north.example.com');
  for (const payload of [{ address: 'https://north.example.com' }, [], '', null,
    'https://north.example.com/' + 'x'.repeat(2048), 'https://north.example.com/;Start-Process']) {
    assert.throws(() => parseWorkspaceConnection(payload));
  }
});
