import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const executable = path.resolve(process.argv[2] ?? '');
assert.match(executable, /[\\/]NORTH\.exe$/i, 'Pass the installed NORTH.exe path.');
assert.ok(existsSync(executable), 'The Windows app is missing.');
const profile = mkdtempSync(path.join(tmpdir(), 'north-modes-'));
const app = spawn(executable, [
  `--user-data-dir=${profile}`, '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
  '--enable-logging=stderr',
], { cwd: path.dirname(executable), stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
let stderr = '';
app.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4000); });
let launchFailure;
const exited = new Promise((resolve) => {
  app.once('exit', (code, signal) => {
    launchFailure = new Error(`NORTH exited before the walkthrough finished (${code ?? signal}). ${stderr.trim()}`);
    resolve();
  });
  app.once('error', (error) => { launchFailure = error; resolve(); });
});

async function waitFor(label, check, timeout = 45_000) {
  const end = Date.now() + timeout;
  let lastError;
  while (Date.now() < end) {
    if (launchFailure) throw launchFailure;
    try {
      const result = await check();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await delay(250);
  }
  throw new Error(`Timed out waiting for ${label}`, { cause: lastError });
}

let socket;
try {
  const port = await waitFor('the isolated app debugger', () => {
    const activePort = path.join(profile, 'DevToolsActivePort');
    return existsSync(activePort) && readFileSync(activePort, 'utf8').split(/\r?\n/)[0];
  });
  const target = await waitFor('the local dashboard window', async () => {
    const response = await fetch(`http://127.0.0.1:${port}/json/list`);
    return (await response.json()).find((item) => item.type === 'page' && item.url === 'north://app/');
  });
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await once(socket, 'open', { signal: AbortSignal.timeout(10_000) });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    const reply = pending.get(message.id);
    if (!reply) return;
    pending.delete(message.id);
    if (message.error) reply.reject(new Error(message.error.message));
    else reply.resolve(message.result);
  });
  function call(method, params = {}) {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  await call('Page.enable');
  async function evaluate(expression) {
    const result = await call('Runtime.evaluate', { expression, returnByValue: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  }
  const bodyContains = (value) => evaluate(`document.body.innerText.includes(${JSON.stringify(value)})`);
  const see = (value) => waitFor(value, () => bodyContains(value));
  async function click(query, name) {
    const expression = `Array.from(document.querySelectorAll(${JSON.stringify(query)})).some(element => {
      if (element.textContent.trim() !== ${JSON.stringify(name)} && element.getAttribute('aria-label') !== ${JSON.stringify(name)}) return false;
      if (!element.getClientRects().length || element.disabled) return false;
      element.click();
      return true;
    })`;
    await waitFor(name, () => evaluate(expression));
  }
  async function switchMode(name) {
    await evaluate(`document.querySelector('button[aria-label="Workspace menu"]').dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))`);
    await click('[role=menuitem]', 'SettingsAlt Shift S');
    await see('Display mode');
    await click('label', name);
    await click('button', 'Back to workspace');
  }

  await see('Is my PC okay?');
  for (const heading of ['Who is on my network?', 'What did my PC connect to?', 'What should I do?']) {
    assert.equal(await bodyContains(heading), true);
  }
  await switchMode('AnalystDetailed rules, queries, and evidence.');
  await see('Needs attention');
  await call('Page.reload');
  await see('Needs attention');
  await switchMode('SimplePlain-language status and next steps.');
  await see('Is my PC okay?');

  function installFixtures() {
    const nativeFetch = window.fetch.bind(window);
    const device = 'a'.repeat(24);
    window.northWalkthroughFixture = { network: 0 };
    window.fetch = (input, options) => {
      const route = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
      const now = new Date().toISOString();
      if (route === '/api/cases') return Promise.resolve(Response.json([]));
      if (route === '/api/network') {
        window.northWalkthroughFixture.network++;
        return Promise.resolve(Response.json({
        assets: [], links: [], sysmon: { state: 'ready', updated_at: now },
        neighbors: { state: 'ready', updated_at: now, records: [
          { address: '192.0.2.10', mac: '02:00:00:00:00:10', interface: 'Fixture LAN', state: 'Reachable', name: 'Fixture phone' },
        ] },
        device_findings: { baseline_at: now, unreviewed: 1, items: [
          { id: device, first_seen: now, last_seen: now, reviewed_at: null, mac: '02:00:00:00:00:10',
            interface: 'Fixture LAN', addresses: ['192.0.2.10'] },
        ] },
        }));
      }
      if (route === '/api/local/findings') {
        const severe = sessionStorage.getItem('north-smoke-severe') === '1';
        const findings = severe ? [{ id: device, title: 'Synthetic review finding', severity: 'high', status: 'new',
          last_seen: now, plain_summary: 'A test observation was recorded.', what_to_do: 'Review the test evidence.',
          evidence_ids: [] }] : [];
        return Promise.resolve(Response.json({ findings, monitor: 'running',
          summary: { unreviewed: findings.length, severe: findings.length } }));
      }
      return nativeFetch(input, options);
    };
  }

  await call('Page.addScriptToEvaluateOnNewDocument', { source: `(${installFixtures.toString()})()` });
  await call('Page.reload');
  await waitFor('the fixture script to run in the reloaded window', () => evaluate('Boolean(window.northWalkthroughFixture)'));
  await waitFor('the dashboard to request fixture network data', () => evaluate('window.northWalkthroughFixture?.network > 0'));
  await see('Fixture phone');
  await see('Needs a look');
  await click('button', 'Yes');
  await see('NORTH sees no open issues');
  await call('Page.reload');
  await see('NORTH sees no open issues');
  await waitFor('the saved Yes answer', () => evaluate(
    'Array.from(document.querySelectorAll("button[aria-pressed=true]")).some(button => button.textContent === "Yes")'));
  await evaluate('sessionStorage.setItem("north-smoke-severe", "1")');
  await call('Page.reload');
  await see('Act now');
  await see('Synthetic review finding');
  console.log('NORTH Windows walkthrough passed: Simple default, Analyst switch, saved mode, device answer, and all three status levels.');
} finally {
  socket?.close();
  if (app.exitCode === null && !app.killed) app.kill();
  await Promise.race([exited, delay(3000, undefined, { ref: false })]);
}
