const { spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function makeLocalFindings({ root, data, launch = spawn, supported = process.platform === 'win32' }) {
  const dbPath = path.join(data, 'local-findings.sqlite3');
  const backend = path.join(root, 'backend');
  const packaged = path.join(backend, 'NORTH-Collector.exe');
  const python = path.join(backend, '.venv', 'Scripts', 'python.exe');
  let child;
  let failed = false;

  function stop() {
    const worker = child;
    child = undefined;
    worker?.stdin.end();
  }

  function start() {
    if (child) return true;
    const built = existsSync(packaged);
    if (!supported || (!built && !existsSync(python))) return false;
    const args = built ? ['--local-monitor'] : [path.join(backend, 'run_collector.py'), '--local-monitor'];
    try {
      const worker = launch(built ? packaged : python, args, {
        env: { ...process.env, NORTH_DB_PATH: dbPath, PYTHONNOUSERSITE: '1', PYTHONPATH: '' },
        cwd: backend, windowsHide: true, stdio: ['pipe', 'ignore', 'ignore'],
      });
      failed = false;
      child = worker;
      const ended = () => {
        if (child !== worker) return;
        child = undefined;
        failed = true;
      };
      worker.once('error', ended);
      worker.once('exit', ended);
      worker.stdin.on('error', ended);
      return true;
    } catch {
      failed = true;
      return false;
    }
  }

  function read(callback) {
    if (!existsSync(dbPath)) return null;
    const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 100 });
    try { return callback(db); } finally { db.close(); }
  }

  function handle(request) {
    const { pathname } = new URL(request.url);
    if (pathname === '/api/local/findings/monitor' && request.method === 'POST') {
      if (request.headers.get('origin') !== 'north://app') return new Response(null, { status: 403 });
      return Response.json({ running: start() });
    }
    if (request.method !== 'GET') return new Response(null, { status: 405 });
    try {
      if (pathname === '/api/local/findings') {
        const findings = read((db) => db.prepare(`
          SELECT status, payload FROM local_detection_findings
          ORDER BY CASE WHEN status = 'new' THEN 0 ELSE 1 END, last_seen DESC, id DESC LIMIT 100
        `).all().map(({ status, payload }) => ({ ...JSON.parse(payload), status })));
        return Response.json({ findings: findings ?? [], monitor: child ? 'running' : failed ? 'failed' : 'stopped' });
      }
      const id = /^\/api\/local\/evidence\/([a-f0-9]{24})$/.exec(pathname)?.[1];
      if (id) {
        const row = read((db) => db.prepare(`
          SELECT payload FROM local_windows_events WHERE id = ?
          UNION ALL SELECT payload FROM events WHERE id = ? LIMIT 1
        `).get(id, id));
        if (row) {
          const { timestamp, host, process, destination, target, source, kind, raw } = JSON.parse(row.payload);
          const addresses = source === 'neighbor' ? raw?.addresses : undefined;
          const listener = source === 'windows_tcp' ? { address: raw?.LocalAddress, port: raw?.LocalPort } : undefined;
          return Response.json({ id, timestamp, host, process: process || raw?.Image, destination, target, source, kind, addresses, listener });
        }
      }
    } catch {
      return Response.json({ detail: 'Local findings storage is temporarily unavailable.' }, { status: 503 });
    }
    return new Response(null, { status: 404 });
  }

  return { handle, stop };
}

module.exports = { makeLocalFindings };
