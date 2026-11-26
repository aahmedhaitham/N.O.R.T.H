import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
    run: () => ({ meta: { changes: statement.run(...values).changes } }),
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

test('Google sign-in creates an isolated workspace after state and PKCE checks', async (t) => {
  const sqlite = new DatabaseSync(':memory:');
  t.after(() => sqlite.close());
  sqlite.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  const env = { ...secrets, DB: d1(sqlite), NORTH_GOOGLE_CLIENT_ID: 'example-client',
    NORTH_GOOGLE_CLIENT_SECRET: 'example-secret' };
  const call = (path, headers) => worker.fetch(new Request(root + path, { headers }), env);
  const start = await call('/api/cloud/auth/google');
  const destination = new URL(start.headers.get('Location'));
  const state = destination.searchParams.get('state');
  const callback = '/api/cloud/auth/google/callback';
  const cookie = start.headers.get('Set-Cookie').split(';')[0];
  assert.equal(destination.origin, 'https://accounts.google.com');
  assert.equal(destination.searchParams.get('code_challenge_method'), 'S256');

  const fetchBefore = globalThis.fetch;
  t.after(() => { globalThis.fetch = fetchBefore; });
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push(url);
    assert.equal(options.redirect, 'manual');
    if (url === 'https://oauth2.googleapis.com/token') {
      assert.equal(options.body.get('redirect_uri'), root + callback);
      assert.equal(createHash('sha256').update(options.body.get('code_verifier')).digest('base64url'),
        destination.searchParams.get('code_challenge'));
      return Response.json({ access_token: 'test-token' });
    }
    assert.equal(url, 'https://openidconnect.googleapis.com/v1/userinfo');
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    return Response.json({ sub: 'google-test-user' });
  };
  assert.equal((await call(callback + '?code=example&state=wrong', { Cookie: cookie })).headers.get('Location'),
    '/?sign_in_failed=session');
  assert.deepEqual(calls, []);
  const signedIn = await call(callback + '?code=example&state=' + state, { Cookie: cookie });
  assert.equal(signedIn.headers.get('Location'), '/');
  const session = signedIn.headers.getSetCookie().find((value) => value.startsWith('__Host-north_session=')).split(';')[0];
  assert.deepEqual(await (await call('/api/cloud/status', { Cookie: session })).json(),
    { signed_in: true, sources: [], waiting_collectors: [] });
  assert.equal(sqlite.prepare('SELECT count(*) AS count FROM cloud_accounts').get().count, 1);
  const desktopPost = (operation, payload, cookie) => worker.fetch(new Request(root + '/api/cloud/desktop/' + operation, {
    method: 'POST', headers: { Origin: root, ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(payload),
  }), env);
  const verifier = 'e'.repeat(64);
  const challenge = createHash('sha256').update(verifier).digest('hex');
  const { ticket } = await (await desktopPost('start', { challenge })).json();
  assert.equal((await desktopPost('approve', { ticket })).status, 401);
  assert.equal((await desktopPost('exchange', { ticket, verifier })).status, 202);
  globalThis.fetch = async () => new Response(null, { status: 302, headers: { Location: 'https://other.example/' } });
  const redirected = await call(callback + '?code=example&state=' + state, { Cookie: cookie });
  assert.equal(redirected.headers.get('Location'), '/?sign_in_failed=exchange');
  assert.equal((await desktopPost('approve', { ticket }, session)).status, 200);
  assert.equal((await desktopPost('exchange', { ticket, verifier: 'f'.repeat(64) })).status, 403);
  const exchange = await desktopPost('exchange', { ticket, verifier });
  assert.equal(exchange.status, 200);
  const desktopCookie = exchange.headers.get('Set-Cookie').split(';')[0];
  assert.equal((await call('/api/cloud/status', { Cookie: desktopCookie })).status, 200);
  assert.equal((await desktopPost('approve', { ticket }, session)).status, 409);
  assert.equal((await desktopPost('exchange', { ticket, verifier })).status, 202);
  const logout = await worker.fetch(new Request(root + '/api/cloud/logout', {
    method: 'POST', headers: { Origin: root, Cookie: session },
  }), env);
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('Set-Cookie'), /Max-Age=0/);
  assert.equal((await call('/api/cloud/status', { Cookie: session })).status, 401);
  assert.equal((await desktopPost('approve', { ticket }, session)).status, 401);
  assert.equal((await call('/api/cloud/status', { Cookie: desktopCookie })).status, 200);
  const untilExpiry = sqlite.prepare('SELECT expires_at FROM cloud_revoked_sessions').get().expires_at;
  await worker.scheduled({ scheduledTime: untilExpiry * 1000 }, env);
  assert.equal(sqlite.prepare('SELECT count(*) AS count FROM cloud_revoked_sessions').get().count, 0);
});

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
  const health = await call('/api/cloud/health', { method: 'HEAD' });
  assert.equal(health.status, 204);
  assert.equal(health.headers.get('Cache-Control'), 'no-store');
  assert.equal(await health.text(), '');
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
  const network = await (await call('/api/network?source=alpha', { headers })).json();
  assert.equal(network.collector_synced_at, status.sources.find((item) => item.id === 'alpha').updated_at);
  assert.deepEqual(await (await call('/api/cases?source=alpha', { headers })).json(), [{ id, evidence: [], review_status: 'open' }]);
  const alpha = await (await call('/api/events?kind=1&source=alpha', { headers })).json();
  const beta = await (await call('/api/events?source=beta', { headers })).json();
  assert.equal(alpha.events.length, 1);
  assert.equal(alpha.events[0].host, 'first-host');
  assert.equal(beta.events[0].host, 'second-host');
  assert.equal(await (await call('/api/cases/' + id + '/report?source=alpha', { headers })).text(), 'sample report');
  assert.equal((await call('/api/cases/' + id + '/report?source=beta', { headers })).status, 404);
  assert.equal((await call('/api/cases', { headers: { Cookie: headers.Cookie + 'x' } })).status, 401);

  const pairings = '/api/cloud/pairings';
  const operator = { ...headers, Origin: root };
  assert.equal((await call(pairings)).status, 401);
  assert.equal((await call(pairings, post({ label: 'Laptop' }, headers))).status, 403);
  const created = await call(pairings, post({ label: 'Laptop' }, operator));
  assert.equal(created.status, 201);
  const pairing = await created.json();
  assert.match(pairing.token, /^[a-f0-9]{64}$/);
  const scopedSnapshot = { ...data, source: { id: pairing.source_id, label: 'Laptop' } };
  const scopedKey = { Authorization: 'Bearer ' + pairing.token };
  assert.equal((await call('/api/cloud/snapshot', post(scopedSnapshot, collectorHeaders))).status, 403);
  assert.equal((await call('/api/cloud/snapshot', post(data, scopedKey))).status, 403);
  assert.equal((await call('/api/cloud/snapshot', post(scopedSnapshot, scopedKey))).status, 200);
  const list = await (await call(pairings, { headers })).json();
  assert.equal(list.pairings[0].source_id, pairing.source_id);
  assert.ok(list.pairings[0].updated_at);
  assert.equal(list.pairings[0].token, undefined);
  assert.equal(list.pairings[0].token_hash, undefined);
  const revoke = pairings + '/' + pairing.source_id + '/revoke';
  assert.equal((await call(revoke, post({}, headers))).status, 403);
  assert.equal((await call(revoke, post({}, operator))).status, 200);
  assert.equal((await call('/api/cloud/snapshot', post(scopedSnapshot, scopedKey))).status, 401);
  const history = await (await call('/api/events?source=' + pairing.source_id, { headers })).json();
  assert.equal(history.events.length, 1);

  const connection = { id, kind: 3, destination: '192.0.2.25', host: 'desk',
    timestamp: '2026-11-25T00:01:00.000000+00:00', raw: { private: 'never-sent-to-ai' } };
  const incident = { ...data, cases: [{ id, evidence: [connection] }] };
  assert.equal((await call('/api/cloud/snapshot', post(incident, collectorHeaders))).status, 200);
  const evidenceId = 'b'.repeat(24);
  assert.equal((await call('/api/cloud/snapshot', post({ ...data, source: { id: 'beta', label: 'Collector B' },
    cases: [], reports: {}, events: [
      { ...connection, id: evidenceId, source_ip: connection.destination, destination: '' },
      { ...connection, id: 'c'.repeat(24), timestamp: '2026-11-25T00:15:00.000000+00:00' },
    ] }, collectorHeaders))).status, 200);
  const related = '/api/cases/' + id + '/related?source=alpha';
  assert.equal((await call(related)).status, 401);
  const matches = (await (await call(related, { headers })).json()).matches;
  assert.deepEqual(matches.map((match) => [match.id, match.collector]), [[evidenceId, 'Collector B']]);
  const rawEvent = '/api/events/' + evidenceId;
  assert.equal((await call(rawEvent + '?source=alpha', { headers })).status, 404);
  assert.equal((await (await call(rawEvent + '?source=beta', { headers })).json()).raw.private, 'never-sent-to-ai');
  const draft = '/api/cases/' + id + '/draft?source=alpha';
  assert.equal((await call(draft, post({}, headers))).status, 403);
  const fallback = await (await call(draft, post({}, operator))).json();
  assert.equal(fallback.provider, 'evidence');
  assert.equal(fallback.reason, 'ai_disabled');
  let modelInput;
  env.AI = { run: async (model, input) => {
    assert.equal(model, '@cf/meta/llama-3.3-70b-instruct-fp8-fast');
    modelInput = input;
    return { response: { finding_ids: [1] } };
  } };
  const ranked = await (await call(draft, post({}, operator))).json();
  assert.equal(ranked.provider, 'cloud-ai');
  assert.deepEqual(ranked.claims[0].evidence_ids, [id]);
  assert.doesNotMatch(JSON.stringify(modelInput), /never-sent-to-ai|192\.0\.2\.25|desk/);
  env.AI = { run: async () => ({ response: '{"finding_ids":[99]}' }) };
  assert.deepEqual(await (await call(draft, post({}, operator))).json(), { ...fallback, reason: 'ai_output' });
  assert.equal(typeof modelInput.prompt, 'string');
  assert.equal(modelInput.response_format.type, 'json_schema');
  env.AI = { run: async () => { throw new Error('provider unavailable'); } };
  assert.deepEqual(await (await call(draft, post({}, operator))).json(), { ...fallback, reason: 'ai_unavailable' });

  const accountKey = 'c'.repeat(64);
  sqlite.prepare('INSERT INTO cloud_accounts (id, access_key_hash) VALUES (?, ?)')
    .run('account-one', createHash('sha256').update(accountKey).digest('hex'));
  const accountLogin = await call('/api/cloud/login', post({ key: accountKey }, { Origin: root }));
  assert.equal(accountLogin.status, 200);
  const accountHeaders = { Origin: root, Cookie: accountLogin.headers.get('Set-Cookie').split(';')[0] };
  assert.deepEqual((await (await call('/api/cloud/status', { headers: accountHeaders })).json()).sources, []);
  assert.equal((await call('/api/network?source=alpha', { headers: accountHeaders })).status, 404);
  const ownPairingResponse = await call(pairings, post({ label: 'Private collector' }, accountHeaders));
  assert.equal(ownPairingResponse.status, 201);
  const ownPairing = await ownPairingResponse.json();
  const waiting = await (await call('/api/cloud/status', { headers: accountHeaders })).json();
  assert.deepEqual(waiting.waiting_collectors, [{ id: ownPairing.source_id, label: ownPairing.label }]);
  const otherWaiting = await (await call('/api/cloud/status', { headers })).json();
  assert.ok(!otherWaiting.waiting_collectors.some((item) => item.id === ownPairing.source_id));
  const ownHeaders = { Authorization: 'Bearer ' + ownPairing.token };
  const ownSnapshot = { ...incident, source: { id: ownPairing.source_id, label: 'Ignored' }, events: [connection],
    network: { ...incident.network, linux_journal: { state: 'ready' } } };
  assert.equal((await call('/api/cloud/snapshot', post(ownSnapshot, ownHeaders))).status, 200);
  const synced = await (await call('/api/cloud/status', { headers: accountHeaders })).json();
  assert.deepEqual(synced.waiting_collectors, []);
  assert.equal(synced.sources[0].platform, 'Linux');
  assert.equal((await call('/api/network?source=' + ownPairing.source_id, { headers })).status, 404);
  const labelPath = '/api/network/device-labels?source=' + ownPairing.source_id;
  const label = { mac: '020000000042', label: 'Lab phone' };
  assert.equal((await call(labelPath, post(label, { ...accountHeaders, Origin: 'https://example.test' }))).status, 403);
  assert.equal((await call(labelPath, post(label, { ...headers, Origin: root }))).status, 404);
  assert.equal((await call(labelPath, post(label, accountHeaders))).status, 200);
  assert.deepEqual(await (await call(labelPath, { headers: accountHeaders })).json(), { labels: [label] });
  assert.equal((await call(labelPath, { headers })).status, 404);
  assert.equal((await call(labelPath, post({ ...label, label: '' }, accountHeaders))).status, 200);
  assert.deepEqual(await (await call(labelPath, { headers: accountHeaders })).json(), { labels: [] });
  for (const endpoint of [
    '/api/events', '/api/events/' + id, '/api/cases', '/api/cases/' + id + '/report',
    '/api/cases/' + id + '/related',
  ]) {
    assert.equal((await call(endpoint + '?source=' + ownPairing.source_id, { headers })).status, 404);
    assert.equal((await call(endpoint + '?source=alpha', { headers: accountHeaders })).status, 404);
  }
  assert.equal((await call('/api/cases/' + id + '/draft?source=' + ownPairing.source_id, post({}, operator))).status, 404);
  assert.deepEqual((await (await call('/api/cases/' + id + '/related', { headers: accountHeaders })).json()).matches, []);
  assert.equal((await (await call(related, { headers })).json()).matches.length, 1);
  assert.equal((await call(pairings + '/' + ownPairing.source_id + '/revoke', post({}, operator))).status, 404);
  assert.equal((await (await call(pairings, { headers: accountHeaders })).json()).pairings.length, 1);
  assert.equal((await (await call(pairings, { headers })).json()).pairings.some((item) => item.source_id === ownPairing.source_id), false);
  const secondKey = 'd'.repeat(64);
  sqlite.prepare('INSERT INTO cloud_accounts (id, access_key_hash) VALUES (?, ?)')
    .run('account-two', createHash('sha256').update(secondKey).digest('hex'));
  const secondLogin = await call('/api/cloud/login', post({ key: secondKey }, { Origin: root }));
  assert.equal(secondLogin.status, 200);
  const secondHeaders = { Origin: root, Cookie: secondLogin.headers.get('Set-Cookie').split(';')[0] };
  const settings = '/api/cloud/settings';
  assert.equal((await call(settings)).status, 401);
  assert.equal((await call(settings, post({ ai_enabled: false }, headers))).status, 403);
  assert.equal((await call(settings, post({ ai_enabled: 'false' }, accountHeaders))).status, 422);
  assert.equal((await call(settings, post({ ai_enabled: false }, accountHeaders))).status, 200);
  assert.equal((await (await call(settings, { headers: accountHeaders })).json()).ai_enabled, false);
  assert.equal((await (await call(settings, { headers: secondHeaders })).json()).ai_enabled, true);
  env.AI = { run: async () => assert.fail('An opted-out workspace must not call AI') };
  assert.equal((await (await call('/api/cases/' + id + '/draft', post({}, accountHeaders))).json()).reason, 'ai_disabled');
  assert.equal((await call(settings, post({ ai_enabled: true }, accountHeaders))).status, 200);
  const reviewPath = '/api/cases/' + id + '/review?source=' + ownPairing.source_id;
  const review = { status: 'investigating', notes: 'Analyst note', revision: 0 };
  assert.equal((await call(reviewPath, { headers: secondHeaders })).status, 404);
  assert.equal((await call(reviewPath, post(review, secondHeaders))).status, 404);
  assert.equal((await (await call(reviewPath, { headers: accountHeaders })).json()).status, 'open');
  const savedReview = await (await call(reviewPath, post(review, accountHeaders))).json();
  assert.equal(savedReview.notes, 'Analyst note');
  assert.equal(savedReview.revision, 1);
  assert.equal((await call(reviewPath, post(review, accountHeaders))).status, 409);
  assert.deepEqual(await (await call(reviewPath, { headers: accountHeaders })).json(), savedReview);
  const searches = '/api/cloud/saved-searches';
  const savedSearch = await call(searches, post({ action: 'save', label: 'Process starts', query: '', kind: '1' }, accountHeaders));
  assert.equal(savedSearch.status, 201);
  const search = await savedSearch.json();
  assert.deepEqual((await (await call(searches, { headers: accountHeaders })).json()).searches, [search]);
  assert.deepEqual((await (await call(searches, { headers: secondHeaders })).json()).searches, []);
  assert.equal((await call(searches, post({ action: 'remove', id: search.id }, secondHeaders))).status, 404);
  assert.equal((await call(searches, post({ action: 'remove', id: search.id }, accountHeaders))).status, 200);
  assert.equal((await call('/api/events?source=' + ownPairing.source_id, { headers: secondHeaders })).status, 404);
  assert.deepEqual((await (await call(pairings, { headers: secondHeaders })).json()).pairings, []);
  assert.equal((await call(draft, post({}, secondHeaders))).status, 404);
  const hour = Math.floor(Date.now() / 3600000) * 3600;
  const quota = sqlite.prepare(`INSERT INTO cloud_usage_limits VALUES (?, ?, ?, ?)
    ON CONFLICT(account_id, operation) DO UPDATE SET window_start = excluded.window_start, used = excluded.used`);
  quota.run('account-one', 'snapshot', hour, 600);
  const throttled = await call('/api/cloud/snapshot', post(ownSnapshot, ownHeaders));
  assert.equal(throttled.status, 429);
  assert.ok(Number(throttled.headers.get('Retry-After')) > 0);
  assert.equal((await call('/api/cloud/snapshot', post(incident, collectorHeaders))).status, 200);
  quota.run('account-one', 'snapshot', hour - 3600, 600);
  assert.equal((await call('/api/cloud/snapshot', post(ownSnapshot, ownHeaders))).status, 200);
  quota.run('account-one', 'ai-brief', hour, 20);
  env.AI = { run: async () => ({ response: { finding_ids: [1] } }) };
  assert.equal((await (await call('/api/cases/' + id + '/draft', post({}, accountHeaders))).json()).reason, 'ai_limit');
  assert.equal((await (await call(draft, post({}, operator))).json()).provider, 'cloud-ai');
  quota.run(':service', 'ai-brief', hour, 200);
  env.AI = { run: async () => assert.fail('The shared quota must prevent a model call') };
  assert.equal((await (await call(draft, post({}, operator))).json()).reason, 'ai_capacity');
  env.NORTH_HOSTED_RETENTION_DAYS = '30';
  await worker.scheduled({ scheduledTime: Date.parse(connection.timestamp) + 31 * 86400000 }, env);
  const ownQuery = '?source=' + ownPairing.source_id;
  assert.equal((await (await call('/api/events' + ownQuery, { headers: accountHeaders })).json()).events.length, 0);
  assert.deepEqual(await (await call('/api/cases' + ownQuery, { headers: accountHeaders })).json(), []);
  assert.equal((await call('/api/cases/' + id + '/report' + ownQuery, { headers: accountHeaders })).status, 404);
  assert.equal((await call('/api/cases/' + id + '/report?source=alpha', { headers })).status, 200);
  const expired = { ...connection, timestamp: '2000-01-01T00:00:00.000000+00:00' };
  assert.equal((await call('/api/cloud/snapshot', post({
    ...ownSnapshot, events: [expired], cases: [{ id, evidence: [expired] }],
  }, ownHeaders))).status, 200);
  assert.equal((await (await call('/api/events' + ownQuery, { headers: accountHeaders })).json()).events.length, 0);
  assert.deepEqual(await (await call('/api/cases' + ownQuery, { headers: accountHeaders })).json(), []);
  const recent = { ...connection, timestamp: new Date().toISOString().replace('Z', '000+00:00') };
  assert.equal((await call('/api/cloud/snapshot', post({
    ...ownSnapshot, events: [recent], cases: [{ id, evidence: [recent] }],
  }, ownHeaders))).status, 200);
  assert.equal((await (await call('/api/events' + ownQuery, { headers: accountHeaders })).json()).events.length, 1);
  assert.equal((await call('/api/cases/' + id + '/report' + ownQuery, { headers: accountHeaders })).status, 200);
  const replaceKey = pairings + '/' + ownPairing.source_id + '/replace-key';
  assert.equal((await call(replaceKey, post({}, secondHeaders))).status, 404);
  assert.equal((await call(replaceKey, post({}, { ...accountHeaders, Origin: 'https://example.test' }))).status, 403);
  const replacement = await call(replaceKey, post({}, accountHeaders));
  assert.equal(replacement.status, 200);
  const replacementPairing = await replacement.json();
  assert.equal(replacementPairing.source_id, ownPairing.source_id);
  assert.match(replacementPairing.token, /^[0-9a-f]{64}$/);
  assert.notEqual(replacementPairing.token, ownPairing.token);
  const replacementHeaders = { Authorization: 'Bearer ' + replacementPairing.token };
  assert.equal((await call('/api/cloud/snapshot', post(ownSnapshot, ownHeaders))).status, 401);
  assert.equal((await call('/api/cases/' + id + '/report' + ownQuery, { headers: accountHeaders })).status, 200);
  assert.equal((await call('/api/cloud/snapshot', post(ownSnapshot, replacementHeaders))).status, 200);
  sqlite.prepare('UPDATE cloud_accounts SET disabled_at = ? WHERE id = ?').run(new Date().toISOString(), 'account-one');
  assert.equal((await call('/api/cloud/status', { headers: accountHeaders })).status, 401);
  assert.equal((await call('/api/cloud/snapshot', post(ownSnapshot, replacementHeaders))).status, 401);
});
