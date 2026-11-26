const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { access, copyFile, mkdir } = require('node:fs/promises');
const path = require('node:path');

const collectorFiles = [
  'backend/requirements.txt', 'backend/run_collector.py', 'backend/cloud_sync.py',
  'backend/neighbors.py', 'backend/sysmon.py', 'backend/north.py', 'backend/device_watch.py',
  'backend/network.py', 'backend/router_usage.py', 'backend/internet_health.py',
  'backend/adapter_traffic.py', 'backend/journal_monitor.py', 'tools/Start-NorthCollector.ps1',
  'tools/Set-NorthCollectorStartup.ps1', 'tools/Export-NorthNeighbors.ps1',
  'tools/Read-NorthSysmon.ps1', 'tools/SysmonFormat.ps1', 'tools/Read-NorthAdapterTraffic.ps1',
];
const sourcePattern = /^collector-[0-9a-f]{20}$/;
const keyPattern = /^[0-9a-f]{64}$/;

function runPowerShell(script, args, input = '') {
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  return new Promise((resolve, reject) => {
    const child = spawn(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args],
      { windowsHide: true, stdio: ['pipe', 'ignore', 'ignore'], timeout: 180000 });
    child.on('error', reject);
    child.on('exit', (code) => code === 0 ? resolve() : reject(new Error('Collector setup command failed.')));
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

function makeCollectorInstall({ root, data, confirm, execute = runPowerShell, isWindows = process.platform === 'win32' }) {
  let installing = false;
  return async (request, origin, cloud) => {
    if (!isWindows || !origin) return Response.json({ detail: 'Open a cloud workspace in NORTH for Windows.' }, { status: 501 });
    const url = new URL(request.url);
    const operation = /^\/api\/desktop\/collector\/(setup|connect|status|enable|disable)$/.exec(url.pathname)?.[1];
    const status = operation === 'status' && request.method === 'GET';
    if (!status && (request.method !== 'POST' || !['setup', 'connect', 'enable', 'disable'].includes(operation))) {
      return Response.json({ detail: 'Method not allowed.' }, { status: 405 });
    }
    if (operation !== 'setup' && operation !== 'connect') {
      const source = url.searchParams.get('source') ?? '';
      if (!sourcePattern.test(source)) return Response.json({ detail: 'Invalid collector source.' }, { status: 422 });
      const destination = collectorDirectory(data, origin, source);
      const installed = await access(path.join(destination, '.north-launcher', 'collector-connection.json')).then(() => true, () => false);
      if (status) return Response.json({ installed });
      if (!installed) return Response.json({ detail: 'This collector is not installed by NORTH on this PC.' }, { status: 404 });
      if (installing) return Response.json({ detail: 'Collector setup is already running.' }, { status: 409 });
      installing = true;
      try {
        if (operation === 'enable' && !await confirm()) return new Response(null, { status: 204 });
        await execute(path.join(destination, 'tools', 'Set-NorthCollectorStartup.ps1'),
          ['-Action', operation === 'enable' ? 'Enable' : 'Disable']);
        return Response.json({ enabled: operation === 'enable' });
      } catch {
        return Response.json({ detail: 'Windows could not update the background collector task.' }, { status: 503 });
      } finally {
        installing = false;
      }
    }
    if (installing) return Response.json({ detail: 'Collector setup is already running.' }, { status: 409 });
    installing = true;
    const connect = operation === 'connect';
    let newSource;
    try {
      let pairing;
      let label;
      try {
        const body = await request.text();
        if (body.length > 1024) throw new Error();
        const parsed = JSON.parse(body);
        if (connect) {
          label = typeof parsed?.label === 'string' ? parsed.label.trim() : '';
          if (!label || label.length > 80 || /[\u0000-\u001f\u007f]/.test(label)) throw new Error();
        } else {
          pairing = parsed;
          if (typeof pairing?.source !== 'string' || !sourcePattern.test(pairing.source) ||
              typeof pairing?.token !== 'string' || !keyPattern.test(pairing.token)) throw new Error();
        }
      } catch {
        return Response.json({ detail: connect ? 'Enter a collector name up to 80 characters.' :
          'A valid collector source and pairing key are required.' }, { status: 422 });
      }
      if (!await confirm() || request.signal.aborted) return new Response(null, { status: 204 });
      if (connect) {
        if (!cloud) return Response.json({ detail: 'Open a signed-in cloud workspace first.' }, { status: 401 });
        const response = await cloud(new Request('north://app/api/cloud/pairings', {
          method: 'POST', body: JSON.stringify({ label }),
        }));
        if (!response.ok) {
          return Response.json({ detail: response.status === 401 ? 'Sign in to the workspace again.' :
            'NORTH Cloud could not create the collector pairing.' }, { status: response.status });
        }
        const created = await response.json();
        if (typeof created?.source_id !== 'string' || !sourcePattern.test(created.source_id)) throw new Error();
        newSource = created.source_id;
        if (typeof created.token !== 'string' || !keyPattern.test(created.token)) throw new Error();
        pairing = { source: newSource, token: created.token };
      }
      const destination = collectorDirectory(data, origin, pairing.source);
      for (const file of collectorFiles) {
        const target = path.join(destination, file);
        await mkdir(path.dirname(target), { recursive: true });
        await copyFile(path.join(root, file), target);
      }
      const executable = 'backend/NORTH-Collector.exe';
      const bundled = await access(path.join(root, executable)).then(() => true, () => false);
      if (bundled) await copyFile(path.join(root, executable), path.join(destination, executable));
      await execute(path.join(destination, 'tools', 'Start-NorthCollector.ps1'),
        ['-Source', pairing.source, '-Workspace', origin, '-PairFromStdin'], pairing.token + '\n');
      await execute(path.join(destination, 'tools', 'Set-NorthCollectorStartup.ps1'), ['-Action', 'Enable']);
      return Response.json({ started: true, ...(newSource && { source_id: newSource }) },
        { status: 200, headers: { 'Cache-Control': 'no-store' } });
    } catch {
      return Response.json({ ...(newSource && { source_id: newSource }),
        detail: newSource ? 'NORTH created the pairing, but setup on this PC could not finish. Open that collector to recover or replace its key.' :
          'Collector setup could not finish. Check the Windows Task Scheduler and your collector prerequisites, then try again.',
      }, { status: 503 });
    } finally {
      installing = false;
    }
  };
}

function collectorDirectory(data, origin, source) {
  const scope = createHash('sha256').update(origin + '|' + source).digest('hex').slice(0, 24);
  return path.join(data, 'collectors', scope);
}

module.exports = { makeCollectorInstall };
