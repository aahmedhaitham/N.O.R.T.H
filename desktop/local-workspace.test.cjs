const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { makeLocalWorkspace } = require('./local-workspace.cjs');
const { deviceHistory } = require('./device-history.cjs');
const { listenerHistory } = require('./listener-history.cjs');

test('local workspace reads Windows data without cloud configuration', async () => {
  const makeEvent = (id, kind, fields) => ({ data: { win: {
    system: { eventID: kind, systemTime: `2026-11-25T10:00:0${id}Z`, eventRecordID: id },
    eventdata: { processGuid: 'example-process', ...fields },
  } } });
  const records = [{ address: '192.0.2.1', interface: 'Wi-Fi' }];
  const alerts = [
    makeEvent(3, 11, { targetFilename: 'inventory.ps1' }),
    makeEvent(1, 1, { image: 'powershell.exe' }),
    makeEvent(2, 3, { destinationIp: '192.0.2.1', image: 'PowerShell.exe' }),
  ];
  const invocations = [];
  const api = makeLocalWorkspace('tools', async (file, args) => {
    invocations.push(args[0] ?? path.basename(file));
    if (file.endsWith('Read-NorthAdapterTraffic.ps1')) return [{ name: 'Wi-Fi', received: '1200', sent: '500' }];
    return file.endsWith('Read-NorthSysmon.ps1') ? { alerts } : records;
  });
  const call = (endpoint, method = 'GET') => api(new Request('north://app' + endpoint, { method }));
  const snapshot = await (await call('/api/network')).json();
  assert.deepEqual(snapshot.neighbors.records, records);
  assert.equal(snapshot.sysmon.session_events, 3);
  assert.deepEqual(await api.sourceChecks(), { sysmon: { state: 'ready', problem: undefined, kinds: [11, 3, 1] } });
  assert.equal(snapshot.activity.buckets.at(-1).count, 3);
  assert.equal(snapshot.links[0].address, '192.0.2.1');
  assert.deepEqual(snapshot.app_connections, [{ process: 'powershell.exe', events: 1, destinations: 1 }]);
  const [incident] = await (await call('/api/cases')).json();
  assert.deepEqual(incident.evidence.map(({ kind }) => kind), [1, 3, 11]);
  const report = await call('/api/cases/' + incident.id + '/report');
  assert.match(await report.text(), /PowerShell process wrote a script file/);
  const filtered = await (await call('/api/events?kind=11&q=inventory')).json();
  assert.equal(filtered.events.length, 1);
  assert.deepEqual(invocations.sort(), ['-AsJson', '-Recent', 'Read-NorthAdapterTraffic.ps1']);
  assert.deepEqual(snapshot.adapter_traffic.adapters, [
    { name: 'Wi-Fi', received_bytes: 1200, sent_bytes: 500, receive_rate: null, send_rate: null },
  ]);
  assert.equal((await call('/api/cloud/status')).status, 404);
  assert.equal((await call('/api/cases', 'POST')).status, 405);
});

test('failed Sysmon access leaves the local network view available', async () => {
  const api = makeLocalWorkspace('tools', async (file) => {
    if (file.endsWith('Read-NorthSysmon.ps1')) throw Object.assign(new Error('Access denied'), { stderr: 'UnauthorizedAccessException' });
    return [];
  });
  const snapshot = await (await api(new Request('north://app/api/network'))).json();
  assert.equal(snapshot.neighbors.state, 'ready');
  assert.equal(snapshot.sysmon.state, 'unavailable');
  assert.equal(snapshot.sysmon.problem, 'access_denied');
  assert.deepEqual(await api.sourceChecks(), { sysmon: { state: 'unavailable', problem: 'access_denied', kinds: [] } });
  const page = await (await api(new Request('north://app/api/events'))).json();
  assert.equal(page.coverage, 'sysmon_unavailable');
});

test('TCP reader caches a bounded passive snapshot without adding it to the inventory payload', async () => {
  const row = { state: 'Listen', local_address: '::', local_port: 8443, remote_address: '::',
    remote_port: 0, pid: 42, process: 'test-process' };
  let reads = 0;
  const api = makeLocalWorkspace('tools', async (file, args) => {
    if (file.endsWith('Read-NorthTcp.ps1')) {
      reads++;
      assert.deepEqual(args, []);
      return { state: 'ready', limited: true, rows: [row, { ...row, local_port: 99999 }, { ...row, local_address: 'invalid' }] };
    }
    return file.endsWith('Read-NorthSysmon.ps1') ? { alerts: [] } : [];
  });
  const request = new Request('north://app/api/local/tcp');
  const result = await api(request);
  assert.equal(result.headers.get('Cache-Control'), 'no-store');
  const sample = await result.json();
  assert.deepEqual(sample.rows, [row]);
  assert.equal(sample.limited, true);
  assert.deepEqual(await (await api(request)).json(), sample);
  assert.equal(reads, 1);
  const network = await (await api(new Request('north://app/api/network'))).json();
  assert.equal(JSON.stringify(network).includes('test-process'), false);
  assert.equal((await api(new Request(request, { method: 'POST' }))).status, 405);
});

test('TCP permission failure is distinct from an empty snapshot', async () => {
  const api = makeLocalWorkspace('tools', async () => ({ state: 'access_denied', rows: [], limited: false }));
  const sample = await (await api(new Request('north://app/api/local/tcp'))).json();
  assert.equal(sample.state, 'access_denied');
  assert.deepEqual(sample.rows, []);
});

test('listening history ignores partial samples and persists new local endpoints', async (t) => {
  const folder = await fs.mkdtemp(path.join(tmpdir(), 'north-listeners-'));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, 'listeners.json');
  let observe = listenerHistory(file);
  const baseline = '2026-11-25T10:00:00.000Z';
  const next = '2026-11-25T10:05:00.000Z';
  const later = '2026-11-25T10:10:00.000Z';
  const listener = (local_port) => ({ state: 'Listen', local_address: '::', local_port });
  assert.equal((await observe([listener(777)], baseline, true)).baseline_at, null);
  const first = await observe([listener(8443)], baseline, false);
  assert.equal(first.baseline_at, baseline);
  assert.deepEqual(first.recent, []);
  observe = listenerHistory(file);
  assert.deepEqual((await observe([listener(443)], next, true)).recent, []);
  const update = await observe([listener(8443), listener(443)], next, false);
  assert.equal(update.recent.length, 1);
  assert.deepEqual(update.recent[0], {
    local_address: '::', local_port: 443, first_seen: next, last_seen: next, baseline: false,
  });
  const repeat = await observe([listener(443)], later, false);
  assert.equal(repeat.recent[0].first_seen, next);
  assert.equal(repeat.recent[0].last_seen, later);
});

test('local device review persists across desktop sessions', async (t) => {
  const folder = await fs.mkdtemp(path.join(tmpdir(), 'north-history-'));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, 'history.json');
  const device = (last) => ({ address: '192.0.2.' + last, mac: '02:12:34:56:78:0' + last, interface: 'Wi-Fi' });
  const first = deviceHistory(file);
  const at = '2026-11-25T12:00:00.000Z';
  assert.deepEqual(await first.observe([], at), { baseline_at: null, unreviewed: 0, items: [] });
  assert.equal((await first.observe([device(1)], at)).baseline_at, at);
  const second = deviceHistory(file);
  const later = '2026-11-25T12:05:00.000Z';
  const newDevice = await second.observe([device(1), device(2)], later);
  assert.equal(newDevice.unreviewed, 1);
  const id = newDevice.items[0].id;
  const api = makeLocalWorkspace('tools', async () => [], second);
  const response = await api(new Request('north://app/api/network/devices/' + id + '/review', { method: 'POST' }));
  assert.equal(response.status, 200);
  assert.equal((await deviceHistory(file).observe([device(2)], later)).unreviewed, 0);
});

test('local posture preserves unknown checks and rejects malformed snapshots', async () => {
  const request = new Request('north://app/api/local/posture');
  const checks = [{ id: 'secure-boot', title: 'Secure Boot enabled', status: 'unknown', reason: 'Access denied.' }];
  const ready = makeLocalWorkspace('tools', async (file) => {
    assert.equal(path.basename(file), 'Read-NorthPosture.ps1');
    return { checks };
  });
  const payload = await (await ready(request)).json();
  assert.equal(payload.state, 'ready');
  assert.deepEqual(payload.checks, [{ ...checks[0], weight: 2 }]);
  assert.deepEqual(payload.score, { earned: 0, possible: 0, unknown: 1 });

  const mixed = makeLocalWorkspace('tools', async () => ({ checks: [
    ...checks,
    { id: 'firewall-public', title: 'Firewall', status: 'fail', reason: 'Review.' },
    { id: 'uac', title: 'UAC', status: 'pass', reason: 'Observed.' },
  ] }));
  assert.deepEqual((await (await mixed(request)).json()).score, { earned: 2, possible: 5, unknown: 1 });

  const invalid = makeLocalWorkspace('tools', async () => ({ checks: [{ ...checks[0], status: 'guessed' }] }));
  assert.deepEqual(await (await invalid(request)).json(), {
    checks: [], state: 'unavailable', updated_at: null,
  });
});

test('posture history compares prior local results across instances', async (t) => {
  const { postureHistory } = require('./posture-history.cjs');
  const folder = await fs.mkdtemp(path.join(tmpdir(), 'north-posture-'));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, 'posture.json');
  const first = '2026-01-15T10:00:00Z';
  const second = '2026-01-15T10:05:00Z';
  const row = { id: 'firewall-public', title: 'Public firewall', status: 'pass' };
  assert.deepEqual(await postureHistory(file)([row], first), { compared_at: null, changes: [] });
  assert.deepEqual(await postureHistory(file)([{ ...row, status: 'unknown' }], second), {
    compared_at: first,
    changes: [{ id: row.id, title: row.title, before: 'pass', after: 'unknown' }],
  });
  assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), {
    at: second, states: { 'firewall-public': 'unknown' },
  });
});

test('posture details validates counts, maps known servicing dates and isolates reader failure', async () => {
  const request = new Request('north://app/api/local/posture/details');
  const workspace = makeLocalWorkspace('tools', async (file) => {
    assert.equal(path.basename(file), 'Read-NorthPostureDetails.ps1');
    return { pending_updates: 0, recent_defender_detections: 51, last_update_at: 'bad date',
      last_scan_at: '2026-11-27T12:00:00Z', windows_edition: 'Professional', windows_build: '26200' };
  });
  const data = await (await workspace(request)).json();
  assert.equal(data.pending_updates, 0);
  assert.equal(data.recent_defender_detections, null);
  assert.equal(data.last_update_at, null);
  assert.equal(data.last_scan_at, '2026-11-27T12:00:00.000Z');
  assert.equal(data.support_end, '2027-10-12');

  const partial = makeLocalWorkspace('tools', async (file) => {
    if (file.endsWith('Details.ps1')) throw new Error('Unavailable');
    return { checks: [] };
  });
  assert.equal((await (await partial(request)).json()).state, 'unavailable');
  assert.equal((await (await partial(new Request('north://app/api/local/posture'))).json()).state, 'ready');
});

test('Defender scan requires the local UI and native confirmation', async () => {
  let allow = false;
  let prompts = 0;
  let scans = 0;
  const workspace = makeLocalWorkspace('tools', async (file, args) => {
    assert.equal(path.basename(file), 'Start-NorthDefenderQuickScan.ps1');
    assert.deepEqual(args, []);
    scans++;
    return { accepted: true };
  }, undefined, undefined, undefined, async () => {
    prompts++;
    return allow;
  });
  const url = 'north://app/api/local/posture/quick-scan';
  assert.equal((await workspace(new Request(url))).status, 405);
  assert.equal((await workspace(new Request(url, { method: 'POST', headers: { origin: 'https://example.invalid' } }))).status, 403);
  assert.equal(prompts, 0);
  const request = () => new Request(url, { method: 'POST', headers: { origin: 'north://app' } });
  assert.deepEqual(await (await workspace(request())).json(), { state: 'cancelled' });
  assert.equal(scans, 0);
  allow = true;
  assert.deepEqual(await (await workspace(request())).json(), { state: 'accepted' });
  assert.equal(scans, 1);
});

test('logging repair previews exact values and saves undo and audit before applying', async (t) => {
  const { makeLoggingRepair } = require('./logging-repair.cjs');
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'north-repair-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let value = -1;
  let approve = false;
  const previews = [];
  const repair = makeLoggingRepair({
    directory, async confirm(...preview) { previews.push(preview); return approve; },
    async run(_script, id, action, expected, desired) {
      assert.equal(id, 'script-block');
      if (action === 'read') return { value, location: 'HKLM\\fixture' };
      assert.equal(expected, value);
      const journal = await fs.readFile(path.join(directory, 'posture-audit.jsonl'), 'utf8');
      assert.equal(JSON.parse(journal.trim().split('\n').at(-1)).state, 'requested');
      await fs.access(path.join(directory, 'posture-script-block-undo.json'));
      value = desired;
    },
  });
  const request = () => new Request('north://app/api/local/posture/repair/script-block/enable',
    { method: 'POST', headers: { origin: 'north://app' } });
  assert.equal((await repair(new Request('north://app/'), 'script-block', false)).status, 405);
  assert.equal((await repair(request(), 'arbitrary-id', false)).status, 404);
  assert.equal((await (await repair(request(), 'script-block', false)).json()).state, 'cancelled');
  assert.equal(value, -1);
  approve = true;
  assert.equal((await (await repair(request(), 'script-block', false)).json()).state, 'completed');
  assert.equal(value, 1);
  assert.equal((await (await repair(request(), 'script-block', true)).json()).state, 'completed');
  assert.equal(value, -1);
  assert.deepEqual(previews, [['HKLM\\fixture', -1, 1, false], ['HKLM\\fixture', -1, 1, false],
    ['HKLM\\fixture', 1, -1, true]]);
  const altered = path.join(directory, 'altered.ps1');
  await fs.writeFile(altered, 'invalid script');
  const verified = makeLoggingRepair({ script: altered, directory, confirm: () => assert.fail('unexpected prompt') });
  assert.equal((await verified(request(), 'script-block', false)).status, 503);
});

test('posture detects exclusion additions and removals across unreadable samples', async (t) => {
  const { postureHistory } = require('./posture-history.cjs');
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'north-exclusions-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'posture.json');
  const at = '2026-11-27T12:00:00Z';
  const first = 'ExclusionPath: synthetic-first';
  const second = 'ExclusionPath: synthetic-second';
  await postureHistory(file)([], at, [first]);
  await postureHistory(file)([], at, null);
  assert.deepEqual((await postureHistory(file)([], at, [second])).exclusion_changes, { added: 1, removed: 1 });
  assert.doesNotMatch(await fs.readFile(file, 'utf8'), /synthetic-/);
});

test('protected evidence keys are reused and a missing key for an existing chain fails closed', async (t) => {
  const { makeIntegrityKey } = require('./integrity-key.cjs');
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'north-key-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const protection = {
    isEncryptionAvailable: () => true,
    encryptString: (value) => Buffer.from('test-protected:' + value, 'utf8'),
    decryptString: (value) => value.toString('utf8').replace('test-protected:', ''),
  };
  const original = makeIntegrityKey(directory, protection, () => false)();
  assert.match(original, /^[a-f0-9]{64}$/);
  assert.equal(makeIntegrityKey(directory, protection, () => true)(), original);
  const file = path.join(directory, 'evidence-integrity.key');
  assert.notEqual(await fs.readFile(file, 'utf8'), original);
  await fs.writeFile(file, 'corrupted');
  assert.throws(makeIntegrityKey(directory, protection, () => true), /Invalid protected/);
  await fs.unlink(file);
  assert.throws(makeIntegrityKey(directory, protection, () => true), /missing its protected key/);
});
