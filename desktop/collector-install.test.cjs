const test = require('node:test');
const assert = require('node:assert/strict');
const { access, mkdir, mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { makeCollectorInstall } = require('./collector-install.cjs');

test('guided collector setup keeps the key off command lines and scopes local startup controls', async (t) => {
  const data = await mkdtemp(path.join(tmpdir(), 'north-collector-test-'));
  t.after(() => rm(data, { recursive: true, force: true }));
  const source = 'collector-' + 'a'.repeat(20);
  const token = 'b'.repeat(64);
  const trusted = 'https://workspace.example';
  let allowed = false;
  const actions = [];
  const api = makeCollectorInstall({
    root: path.join(__dirname, '..'), data, isWindows: true, confirm: async () => allowed,
    async execute(script, args, input) {
      assert.ok(!args.includes(token));
      actions.push(path.basename(script) + ':' + args.at(-1));
      if (args.includes('-PairFromStdin')) {
        assert.equal(input, token + '\n');
        const root = path.dirname(path.dirname(script));
        await access(path.join(root, 'backend', 'run_collector.py'));
        await assert.rejects(access(path.join(root, 'backend', 'north.sqlite3')));
        const settings = path.join(root, '.north-launcher');
        await mkdir(settings);
        await writeFile(path.join(settings, 'collector-connection.json'), '{}');
      }
    },
  });
  function invoke(action, origin = trusted, body) {
    return api(new Request('north://app/api/desktop/collector/' + action + '?source=' + source, {
      method: action === 'status' ? 'GET' : 'POST', body: body && JSON.stringify(body),
    }), origin);
  }
  assert.equal((await invoke('setup', trusted, { source, token: 'invalid' })).status, 422);
  assert.equal((await invoke('setup', trusted, { source, token })).status, 204);
  assert.deepEqual(actions, []);
  allowed = true;
  assert.equal((await invoke('setup', trusted, { source, token })).status, 200);
  assert.deepEqual(await (await invoke('status')).json(), { installed: true });
  assert.deepEqual(await (await invoke('status', 'https://other.example')).json(), { installed: false });
  assert.equal((await invoke('disable', 'https://other.example')).status, 404);
  assert.equal((await invoke('disable')).status, 200);
  assert.deepEqual(actions, [
    'Start-NorthCollector.ps1:-PairFromStdin',
    'Set-NorthCollectorStartup.ps1:Enable',
    'Set-NorthCollectorStartup.ps1:Disable',
  ]);
});

test('connecting this PC creates its pairing only after confirmation and keeps the key in the bridge', async (t) => {
  const data = await mkdtemp(path.join(tmpdir(), 'north-collector-connect-'));
  t.after(() => rm(data, { recursive: true, force: true }));
  const source = 'collector-' + 'a'.repeat(20);
  const token = 'c'.repeat(64);
  let confirmed = false;
  let apiCalls = 0;
  let failStartup = false;
  const api = makeCollectorInstall({
    root: path.join(__dirname, '..'), data, isWindows: true, confirm: async () => confirmed,
    async execute(script, args, input) {
      assert.ok(!args.includes(token));
      if (args.includes('-PairFromStdin')) assert.equal(input, token + '\n');
      if (failStartup && args.includes('Enable')) throw new Error('Mock scheduler failure');
    },
  });
  const invoke = () => api(new Request('north://app/api/desktop/collector/connect', {
    method: 'POST', body: JSON.stringify({ label: '  Lab PC  ' }),
  }), 'https://workspace.example', async (request) => {
    apiCalls++;
    assert.equal(new URL(request.url).pathname, '/api/cloud/pairings');
    assert.deepEqual(await request.json(), { label: 'Lab PC' });
    return Response.json({ source_id: source, token }, { status: 201 });
  });
  assert.equal((await invoke()).status, 204);
  assert.equal(apiCalls, 0);
  confirmed = true;
  const connected = await invoke();
  assert.equal(connected.status, 200);
  assert.deepEqual(await connected.json(), { started: true, source_id: source });
  failStartup = true;
  const failed = await invoke();
  assert.equal(failed.status, 503);
  const recovery = await failed.json();
  assert.equal(recovery.source_id, source);
  assert.ok(!JSON.stringify(recovery).includes(token));
});
