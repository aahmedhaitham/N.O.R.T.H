const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readJson } = require('../frontend/src/readJson.ts');

test('JSON requests reject empty, unreadable, failed and timed out replies without exposing response text', async (t) => {
  const mocked = t.mock.method(globalThis, 'fetch', async () => Response.json({ rules: [] }));
  assert.deepEqual(await readJson('/api/local/rules'), { rules: [] });
  for (const response of [
    new Response('', { headers: { 'Content-Type': 'application/json' } }),
    new Response('internal details', { headers: { 'Content-Type': 'application/json' } }),
    new Response('<html>internal details</html>'),
    Response.json({ detail: 'internal details' }, { status: 500 }),
  ]) {
    mocked.mock.mockImplementation(async () => response);
    await assert.rejects(readJson('/api/local/rules'), (error) => !error.message.includes('internal details'));
  }
  mocked.mock.mockImplementation((_url, { signal }) => new Promise((_resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout did not propagate')), 100);
    signal.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
  }));
  await assert.rejects(readJson('/api/local/rules', undefined, 10), { name: 'TimeoutError' });
});
