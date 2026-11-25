import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import worker from './worker.mjs';

const root = 'https://north.example';
const secrets = { NORTH_ACCESS_KEY: 'access'.repeat(8), NORTH_INGEST_KEY: 'ingest'.repeat(8),
  NORTH_SESSION_SECRET: 'session'.repeat(8) };
const id = 'a'.repeat(24);

function d1(sqlite) {
  const bind = (statement, values = []) => ({
    bind: (...next) => bind(statement, next),
    all: async () => ({ results: statement.all(...values) }),
    first: async () => statement.get(...values) ?? null,
    run: () => statement.run(...values),
  });
  return {
    prepare: (sql) => bind(sqlite.prepare(sql)),
    batch: async (queries) => {
      sqlite.exec('BEGIN');
      try {
        for (const query of queries) query.run();
        sqlite.exec('COMMIT');
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    },
  };
}

test('cloud sources keep independent event and investigation history', async (t) => {
  const sqlite = new DatabaseSync(':memory:');
  t.after(() => sqlite.close());
  sqlite.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  const env = { ...secrets, DB: d1(sqlite) };
  const call = (path, options) => worker.fetch(new Request(root + path, options), env);
  const post = (body, headers = {}) => ({ method: 'POST', body: JSON.stringify(body), headers });
  const data = { source: { id: 'alpha', label: 'Collector A' }, cases: [{ id, evidence: [] }],
    events: [{ id, timestamp: '2026-11-25T00:00:00.000000+00:00', kind: 1, host: 'first-host' }],
    network: { assets: [], links: [] }, reports: { [id]: 'sample report' } };

  assert.equal((await call('/api/cases')).status, 401);
  assert.equal((await call('/api/cloud/snapshot', post(data))).status, 401);
  assert.equal((await call('/api/cloud/snapshot', post(data, {
    Authorization: 'Bearer ' + secrets.NORTH_INGEST_KEY,
  }))).status, 200);
  const collectorHeaders = { Authorization: 'Bearer ' + secrets.NORTH_INGEST_KEY };
  assert.equal((await call('/api/cloud/snapshot', post(data, collectorHeaders))).status, 200);
  assert.equal((await call('/api/cloud/snapshot', post({
    ...data, source: { id: 'beta', label: 'Collector B' }, cases: [],
    events: [{ ...data.events[0], host: 'second-host' }], reports: {},
  }, collectorHeaders))).status, 200);
  assert.equal((await call('/api/cloud/snapshot', post({
    ...data, events: [], cases: [], reports: {},
  }, collectorHeaders))).status, 200);
  assert.equal((await call('/api/cloud/login', post({ key: secrets.NORTH_ACCESS_KEY }))).status, 403);
  const login = await call('/api/cloud/login', post({ key: secrets.NORTH_ACCESS_KEY }, { Origin: root }));
  assert.equal(login.status, 200);
  const cookie = login.headers.get('Set-Cookie');
  assert.match(cookie, /HttpOnly; Secure; SameSite=Strict/);
  const headers = { Cookie: cookie.split(';')[0] };
  const status = await (await call('/api/cloud/status', { headers })).json();
  assert.deepEqual(status.sources.map((item) => item.id).sort(), ['alpha', 'beta']);
  assert.deepEqual(await (await call('/api/cases?source=alpha', { headers })).json(), [{ id, evidence: [] }]);
  const alpha = await (await call('/api/events?kind=1&source=alpha', { headers })).json();
  const beta = await (await call('/api/events?source=beta', { headers })).json();
  assert.equal(alpha.events.length, 1);
  assert.equal(alpha.events[0].host, 'first-host');
  assert.equal(beta.events[0].host, 'second-host');
  assert.equal(await (await call('/api/cases/' + id + '/report?source=alpha', { headers })).text(), 'sample report');
  assert.equal((await call('/api/cases/' + id + '/report?source=beta', { headers })).status, 404);
  assert.equal((await call('/api/cases', { headers: { Cookie: headers.Cookie + 'x' } })).status, 401);
});
