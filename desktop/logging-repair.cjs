const { execFile } = require('node:child_process');
const { createHash, randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const exec = promisify(execFile);
const settings = new Set(['process-command-line', 'script-block', 'smbv1', 'firewall-domain', 'firewall-private', 'firewall-public', 'autorun-policy']);
const repairDigest = '244a0435a39923b1789d5038501976f814bc3f7a4b1b5e93b8345719a5958e5c';

function encoded(text) {
  return Buffer.from(text, 'utf16le').toString('base64');
}

async function runLoggingRepair(script, id, action, expected, desired) {
  const source = (await fs.readFile(script, 'utf8')).replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  if (createHash('sha256').update(source).digest('hex') !== repairDigest) throw new Error('Repair script verification failed');
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const invocation = `& { ${source}\n } -Id '${id}' -Action '${action}' -Expected ${expected} -Desired ${desired}`;
  const command = action === 'read' ? invocation : `
    $ErrorActionPreference = 'Stop'
    $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile -NonInteractive -EncodedCommand ${encoded(invocation)}'
    exit $child.ExitCode
  `;
  const { stdout } = await exec(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded(command)],
    { windowsHide: true, timeout: 180_000, maxBuffer: 16_384 });
  return action === 'read' ? JSON.parse(stdout) : undefined;
}

function makeLoggingRepair({ script, directory, confirm, run = runLoggingRepair }) {
  let busy = false;
  return async (request, id, undo) => {
    if (request.method !== 'POST') return new Response(null, { status: 405 });
    if (request.headers.get('origin') !== 'north://app') return new Response(null, { status: 403 });
    if (!settings.has(id)) return new Response(null, { status: 404 });
    if (busy) return new Response(null, { status: 409 });
    busy = true;
    try {
      const current = await run(script, id, 'read', -1, -1);
      const previous = path.join(directory, 'posture-' + id + '-undo.json');
      const saved = undo ? JSON.parse(await fs.readFile(previous, 'utf8')) : null;
      const valid = (value) => Number.isInteger(value) && value >= -1 && value <= (id === 'autorun-policy' ? 255 : 1);
      if (!valid(current.value) || (undo && (saved.id !== id || current.value !== saved.after ||
        !valid(saved.before)))) throw new Error('Unexpected setting state');
      const desired = undo ? saved.before : id === 'smbv1' ? 0 : id === 'autorun-policy' ? 255 : 1;
      if (current.value === desired) return Response.json({ state: 'unchanged' });
      if (!await confirm(current.location, current.value, desired, undo)) return Response.json({ state: 'cancelled' });
      await fs.mkdir(directory, { recursive: true });
      const action = { id, operation: undo ? 'undo' : 'repair', before: current.value, after: desired, request: randomUUID() };
      const audit = (state) => fs.appendFile(path.join(directory, 'posture-audit.jsonl'),
        JSON.stringify({ ...action, state, at: new Date().toISOString() }) + '\n', { mode: 0o600 });
      await audit('requested');
      if (!undo) {
        await fs.writeFile(previous + '.tmp', JSON.stringify(action), { mode: 0o600 });
        await fs.rename(previous + '.tmp', previous);
      }
      try {
        await run(script, id, 'apply', current.value, desired);
        const observed = await run(script, id, 'read', -1, -1);
        if (observed.value !== desired) throw new Error('Windows did not report the requested value');
      } catch (error) {
        await audit('unconfirmed');
        throw error;
      }
      await audit('completed');
      return Response.json({ state: 'completed' });
    } catch {
      return Response.json({ state: 'unconfirmed' }, { status: 503 });
    } finally {
      busy = false;
    }
  };
}
module.exports = { makeLoggingRepair };
