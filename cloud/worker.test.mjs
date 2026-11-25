import assert from 'node:assert/strict';
import test from 'node:test';
import worker from './worker.mjs';

const root = 'https://north.example';
const secrets = { NORTH_ACCESS_KEY: 'access'.repeat(8), NORTH_INGEST_KEY: 'ingest'.repeat(8),
  NORTH_SESSION_SECRET: 'session'.repeat(8) };
const id = 'a'.repeat(24);

test('private workspace requires separate collection and operator credentials', async () => {
  let saved;
  const env = { ...secrets, DB: { prepare: (sql) => ({
    bind: (payload, updated_at) => ({ run: async () => { saved = { payload, updated_at }; } }),
    first: async () => { assert.match(sql, /SELECT/); return saved; },
  }) } };
  const call = (path, options) => worker.fetch(new Request(root + path, options), env);
  const post = (body, headers = {}) => ({ method: 'POST', body: JSON.stringify(body), headers });
  const data = { cases: [{ id }], events: [{ id, timestamp: '2026-11-25T00:00:00+00:00', kind: 1 }],
    network: { assets: [], links: [] }, reports: { [id]: 'sample report' } };

  assert.equal((await call('/api/cases')).status, 401);
  assert.equal((await call('/api/cloud/snapshot', post(data))).status, 401);
  assert.equal((await call('/api/cloud/snapshot', post(data, {
    Authorization: 'Bearer ' + secrets.NORTH_INGEST_KEY,
  }))).status, 200);
  assert.equal((await call('/api/cloud/login', post({ key: secrets.NORTH_ACCESS_KEY }))).status, 403);
  const login = await call('/api/cloud/login', post({ key: secrets.NORTH_ACCESS_KEY }, { Origin: root }));
  assert.equal(login.status, 200);
  const cookie = login.headers.get('Set-Cookie');
  assert.match(cookie, /HttpOnly; Secure; SameSite=Strict/);
  const headers = { Cookie: cookie.split(';')[0] };
  assert.deepEqual(await (await call('/api/cases', { headers })).json(), [{ id }]);
  assert.equal((await (await call('/api/events?kind=1', { headers })).json()).events.length, 1);
  assert.equal(await (await call('/api/cases/' + id + '/report', { headers })).text(), 'sample report');
  assert.equal((await call('/api/cases', { headers: { Cookie: headers.Cookie + 'x' } })).status, 401);
});
