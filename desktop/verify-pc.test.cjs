const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { tmpdir } = require('node:os');
const { compareSnapshots, composeVerdict, makeVerifyPc } = require('./verify-pc.cjs');

test('PC checks compare every category and distinguish missing evidence', () => {
  const ids = ['autoruns', 'services', 'tasks', 'listeners', 'firewall', 'users', 'admins', 'hosts', 'proxy', 'dns', 'exclusions'];
  const baseline = { values: Object.fromEntries(ids.map((id) => [id, ['a']])) };
  const current = { values: Object.fromEntries(ids.map((id) => [id, ['b']])) };
  assert.equal(compareSnapshots(current, baseline).length, 11);
  assert.ok(compareSnapshots(current, baseline).every((item) => item.status === 'review'));
  assert.ok(compareSnapshots(baseline, baseline).every((item) => item.status === 'fine'));
  assert.ok(compareSnapshots(current, null).every((item) => item.status === 'unknown'));
  assert.ok(compareSnapshots({ values: {} }, baseline).every((item) => item.status === 'unknown'));
});

test('PC verdict preserves source, posture, update and findings states', () => {
  const result = composeVerdict({ state: 'ready', kinds: [1] }, { state: 'ready', checks: [
    { id: 'firewall', title: 'Firewall', status: 'fail', reason: 'Review Windows policy.' },
    { id: 'tpm', title: 'TPM', status: 'unknown', reason: 'No data.' },
  ] }, { pending_updates: 0, recent_defender_detections: 2 }, [], { monitor: 'running', summary: { unreviewed: 0 } });
  assert.deepEqual(result.fine.map((item) => item.id), ['sysmon', 'updates', 'findings']);
  assert.deepEqual(result.review.map((item) => item.id), ['firewall', 'defender-events']);
  assert.deepEqual(result.unknown.map((item) => item.id), ['tpm']);
  assert.doesNotMatch(JSON.stringify(result), /\b(?:clean|safe|secure)\b/i);
  assert.equal(composeVerdict(null, null, null, [], { monitor: 'running' }).unknown.length, 5);
});

test('PC check baseline is explicit, local-only and preserved across restarts', async (t) => {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'north-verify-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const order = [];
  let token = 'a';
  const config = {
    directory,
    async readState() { order.push('state'); return {}; },
    async readSnapshot() {
      order.push('snapshot');
      return { categories: [{ id: 'hosts', items: [token.repeat(64)] }] };
    },
    async readFindings() { order.push('findings'); return null; },
  };
  const endpoint = 'north://app/api/local/verify-pc';
  const post = (suffix = '', origin = 'north://app') =>
    new Request(endpoint + suffix, { method: 'POST', headers: { origin } });
  const first = makeVerifyPc(config);
  assert.equal((await first(post('', 'https://example.invalid'))).status, 403);
  const initial = await (await first(post())).json();
  assert.deepEqual(order, ['state', 'snapshot', 'findings']);
  assert.equal(initial.baseline, null);
  assert.equal(initial.timeline[0].readable, 1);
  assert.equal((await first(post('?baseline=unknown'))).status, 404);
  const baseline = await (await first(post('?baseline=' + initial.timeline[0].id))).json();
  assert.equal(baseline.baseline, initial.timeline[0].at);
  token = 'b';
  const second = makeVerifyPc(config);
  const next = await (await second(post())).json();
  assert.equal(next.timeline.length, 2);
  assert.equal(next.timeline[0].compared_at, baseline.baseline);
  assert.equal(next.timeline[0].verdict.review[0].id, 'snapshot-hosts');
  assert.doesNotMatch(JSON.stringify(next), /(?:a{64}|b{64})/);
});

test('the Assistant uses the same three verdict counts shown in Overview', () => {
  const { answer } = require('../frontend/src/assistantEngine.ts');
  const verdict = composeVerdict({ state: 'ready', kinds: [1] }, null, { pending_updates: 3 }, [], null);
  const counts = ['fine', 'review', 'unknown'].map((section) => verdict[section].length);
  const report = { verification: { at: '2026-11-27T12:00:00Z', counts } };
  const expected = /1 checked and fine, 1 need a look, 3 could not be checked/;
  assert.match(answer('Is my PC okay?', report).text, expected);
  assert.match(answer('Verify my PC', report).text, expected);
});
