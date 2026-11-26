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
  return async (request, origin) => {
    if (!isWindows || !origin) return Response.json({ detail: 'Open a cloud workspace in NORTH for Windows.' }, { status: 501 });
    const url = new URL(request.url);
    const operation = /^\/api\/desktop\/collector\/(setup|status|enable|disable)$/.exec(url.pathname)?.[1];
    const status = operation === 'status' && request.method === 'GET';
    if (!status && (request.method !== 'POST' || !['setup', 'enable', 'disable'].includes(operation))) {
      return Response.json({ detail: 'Method not allowed.' }, { status: 405 });
    }
    if (operation !== 'setup') {
      const source = url.searchParams.get('source') ?? '';
      if (!/^collector-[0-9a-f]{20}$/.test(source)) return Response.json({ detail: 'Invalid collector source.' }, { status: 422 });
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
    try {
      let pairing;
      try {
        const body = await request.text();
        if (body.length > 512) throw new Error();
        pairing = JSON.parse(body);
        if (typeof pairing?.source !== 'string' || !/^collector-[0-9a-f]{20}$/.test(pairing.source) ||
            typeof pairing?.token !== 'string' || !/^[0-9a-f]{64}$/.test(pairing.token)) throw new Error();
      } catch {
        return Response.json({ detail: 'A valid collector source and pairing key are required.' }, { status: 422 });
      }
      if (!await confirm()) return new Response(null, { status: 204 });
      const destination = collectorDirectory(data, origin, pairing.source);
      for (const file of collectorFiles) {
        const target = path.join(destination, file);
        await mkdir(path.dirname(target), { recursive: true });
        await copyFile(path.join(root, file), target);
      }
      await execute(path.join(destination, 'tools', 'Start-NorthCollector.ps1'),
        ['-Source', pairing.source, '-Workspace', origin, '-PairFromStdin'], pairing.token + '\n');
      await execute(path.join(destination, 'tools', 'Set-NorthCollectorStartup.ps1'), ['-Action', 'Enable']);
      return Response.json({ started: true }, { status: 200, headers: { 'Cache-Control': 'no-store' } });
    } catch {
      return Response.json({ detail: 'Collector setup could not finish. Check that Python 3.11 or newer and the Windows Python launcher are installed, then try again.' }, { status: 503 });
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
