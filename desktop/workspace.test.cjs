const assert = require('node:assert/strict');
const test = require('node:test');
const { desktopStartup, workspaceOrigin } = require('./workspace.cjs');

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
