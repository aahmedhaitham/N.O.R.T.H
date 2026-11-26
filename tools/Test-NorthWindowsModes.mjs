import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const executable = path.resolve(process.argv[2] ?? '');
assert.match(executable, /[\\/]NORTH\.exe$/i, 'Pass the installed NORTH.exe path.');
assert.ok(existsSync(executable), 'The Windows app is missing.');
const profile = mkdtempSync(path.join(tmpdir(), 'north-modes-'));
const startedAt = performance.now();
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
    const result = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  }
  const bodyContains = (value) => evaluate(`document.body.innerText.includes(${JSON.stringify(value)})`);
  const see = (value) => waitFor(value, () => bodyContains(value));
  const require = createRequire(new URL('../desktop/package.json', import.meta.url));
  const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
  async function audit(label) {
    await call('Runtime.evaluate', { expression: axeSource });
    const failures = await evaluate(`axe.run(document, { runOnly: {
      type: 'rule', values: ['button-name', 'label', 'aria-valid-attr-value', 'landmark-one-main']
    }}).then(result => result.violations.map(({ id, nodes }) => ({ id, count: nodes.length })))`);
    assert.deepEqual(failures, [], label);
  }
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

  await see('Set up NORTH');
  const firstWindowMs = Math.round(performance.now() - startedAt);
  console.log(`NORTH startup to setup heading: ${firstWindowMs} ms (includes debugger connection).`);
  const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const rootWorkingSet = Number(execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    `(Get-Process -Id ${app.pid}).WorkingSet64`], { encoding: 'utf8', windowsHide: true, timeout: 5000 }));
  assert.ok(rootWorkingSet > 0);
  console.log(`NORTH main-process working set at launch: ${(rootWorkingSet / 1024 ** 2).toFixed(1)} MiB.`);
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  assert.equal(await evaluate('matchMedia("(prefers-reduced-motion: reduce)").matches'), true);
  await audit('first-run setup accessibility');
  await see('What NORTH can see');
  await click('button', 'Continue');
  await see('Choose your display mode');
  await click('button', 'Continue');
  await see('Your data and privacy');
  await click('button', 'Open dashboard');
  await see('Is my PC okay?');
  await call('Page.reload');
  await see('Is my PC okay?');
  assert.equal(await bodyContains('Set up NORTH'), false);
  await evaluate(`document.querySelector('button[aria-label="Workspace menu"]').dispatchEvent(
    new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))`);
  await click('[role=menuitem]', 'SettingsAlt Shift S');
  await click('button', 'Open setup guide');
  await see('Set up NORTH');
  await click('button', 'Skip setup');
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
        const findings = severe ? [{ id: device, title: 'Synthetic review finding <img data-north-smoke-marker>', severity: 'high', status: 'new',
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
  await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', ctrlKey: true, bubbles: true }))`);
  await see('Built in · works offline · answers from your NORTH data');
  await click('button', 'What needs attention?');
  await see('Unreviewed findings in the available snapshot.');
  await audit('Assistant accessibility');
  await see('<img data-north-smoke-marker>');
  assert.equal(await evaluate('document.querySelector("img[data-north-smoke-marker]") === null'), true);
  await click('button', 'Open evidence in Overview');
  await waitFor('the exact cited finding to expand', () => evaluate(
    'document.getElementById("assistant-findings-" + "a".repeat(24))?.open === true'));
  console.log('NORTH Windows walkthrough passed: display modes, all three status levels, and Assistant evidence navigation.');
} finally {
  socket?.close();
  if (app.exitCode === null && !app.killed) app.kill();
  await Promise.race([exited, delay(3000, undefined, { ref: false })]);
}
