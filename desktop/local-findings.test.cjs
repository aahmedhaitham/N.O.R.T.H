const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { test } = require('node:test');
const { makeLocalFindings } = require('./local-findings.cjs');

test('desktop findings use only the private local database and launch one windowless monitor', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'north-findings-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const backend = path.join(root, 'backend');
  fs.mkdirSync(backend);
  fs.writeFileSync(path.join(backend, 'NORTH-Collector.exe'), '');
  const id = 'a'.repeat(24);
  const db = new DatabaseSync(path.join(root, 'local-findings.sqlite3'));
  db.exec(`
    CREATE TABLE local_detection_findings (id, status, last_seen, payload);
    CREATE TABLE local_windows_events (id, payload);
    CREATE TABLE events (id, payload);
  `);
  db.prepare('INSERT INTO local_detection_findings VALUES (?, ?, ?, ?)').run(
    id, 'new', '2026-01-15', JSON.stringify({ id, evidence_ids: [id] }));
  db.prepare('INSERT INTO local_windows_events VALUES (?, ?)').run(
    id, JSON.stringify({ source: 'neighbor', host: 'TEST', raw: { addresses: ['192.0.2.1'], internal: 'private' } }));
  db.close();

  const worker = new EventEmitter();
  worker.stdin = new EventEmitter();
  let ended = false;
  worker.stdin.end = () => { ended = true; };
  let launches = 0;
  const local = makeLocalFindings({ root, data: root, supported: true, launch(file, args, options) {
    launches++;
    assert.equal(file, path.join(backend, 'NORTH-Collector.exe'));
    assert.deepEqual(args, ['--local-monitor']);
    assert.equal(options.windowsHide, true);
    return worker;
  } });
  const call = (route, init) => local.handle(new Request('north://app/api/local/' + route, init));
  assert.equal((await call('findings').json()).monitor, 'stopped');
  assert.equal(call('findings/monitor', { method: 'POST' }).status, 403);
  const start = { method: 'POST', headers: { origin: 'north://app' } };
  assert.deepEqual(await call('findings/monitor', start).json(), { running: true });
  await call('findings/monitor', start).json();
  assert.equal(launches, 1);
  const feed = await call('findings').json();
  assert.equal(feed.monitor, 'running');
  assert.deepEqual(feed.findings, [{ id, evidence_ids: [id], status: 'new' }]);
  assert.deepEqual(await call('evidence/' + id).json(), { id, host: 'TEST', source: 'neighbor', addresses: ['192.0.2.1'] });
  assert.equal(call('evidence/invalid').status, 404);
  local.stop();
  assert.equal(ended, true);
});
