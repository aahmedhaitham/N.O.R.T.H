const { execFile, spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function makeLocalFindings({ root, data, launch = spawn, sourceChecks, packagedFirst = true, supported = process.platform === 'win32' }) {
  const dbPath = path.join(data, 'local-findings.sqlite3');
  const backend = path.join(root, 'backend');
  const packaged = path.join(backend, 'NORTH-Collector.exe');
  const python = path.join(backend, '.venv', 'Scripts', 'python.exe');
  let child;
  let failed = false;
  let listing;

  function runtime(argument) {
    if (!supported) return null;
    if (packagedFirst && existsSync(packaged)) return [packaged, [argument]];
    if (existsSync(python)) return [python, [path.join(backend, 'run_collector.py'), argument]];
    if (existsSync(packaged)) return [packaged, [argument]];
    return null;
  }

  const env = { ...process.env, NORTH_DB_PATH: dbPath, PYTHONNOUSERSITE: '1', PYTHONPATH: '' };

  async function ruleRequest(command) {
    const target = runtime('--rule-workspace');
    if (!target) throw new Error('Collector unavailable');
    const checks = command === '{}' && sourceChecks ? await sourceChecks() : {};
    return new Promise((resolve, reject) => {
      const [file, args] = target;
      const worker = execFile(file, args, {
        env: { ...env, NORTH_RULE_SOURCE_CHECKS: JSON.stringify(checks) },
        cwd: backend, windowsHide: true, timeout: 20_000, maxBuffer: 512_000,
      }, (error, stdout) => {
        if (error) return reject(error);
        try {
          const value = JSON.parse(stdout);
          if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid rule response');
          resolve(value);
        } catch (invalid) { reject(invalid); }
      });
      worker.stdin.on('error', reject);
      worker.stdin.end(command);
    });
  }

  function stop() {
    const worker = child;
    child = undefined;
    worker?.stdin.end();
  }

  function start() {
    if (child) return true;
    const target = runtime('--local-monitor');
    if (!target) return false;
    const [file, args] = target;
    try {
      const worker = launch(file, args, {
        env,
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

  function accessStore(callback, readOnly = true) {
    if (!existsSync(dbPath)) return null;
    const db = new DatabaseSync(dbPath, { readOnly, timeout: 100 });
    try { return callback(db); } finally { db.close(); }
  }

  async function handle(request) {
    const { pathname, searchParams } = new URL(request.url);
    if (pathname === '/api/local/rules') {
      try {
        let result;
        if (request.method === 'GET') {
          if (!listing) {
            const pending = ruleRequest('{}').finally(() => { if (listing === pending) listing = undefined; });
            listing = pending;
          }
          result = await listing;
        } else if (request.method === 'POST') {
          if (request.headers.get('origin') !== 'north://app') return new Response(null, { status: 403 });
          if (request.headers.get('content-type') !== 'application/json') return new Response(null, { status: 415 });
          const body = await request.text();
          if (Buffer.byteLength(body) > 200_000) return new Response(null, { status: 413 });
          result = await ruleRequest(body);
          listing = undefined;
        } else {
          return new Response(null, { status: 405 });
        }
        return Response.json(result, { status: result.detail ? 422 : 200 });
      } catch {
        return Response.json({ detail: 'The local rule engine is unavailable.' }, { status: 503 });
      }
    }
    if (pathname === '/api/local/findings/monitor' && request.method === 'POST') {
      if (request.headers.get('origin') !== 'north://app') return new Response(null, { status: 403 });
      return Response.json({ running: start() });
    }
    const reviewId = /^\/api\/local\/findings\/([a-f0-9]{24})\/review$/.exec(pathname)?.[1];
    if (reviewId && request.method === 'POST') {
      if (request.headers.get('origin') !== 'north://app') return new Response(null, { status: 403 });
      let status;
      try {
        if (request.headers.get('content-type') !== 'application/json') throw new Error();
        const body = await request.text();
        if (body.length > 64) throw new Error();
        ({ status } = JSON.parse(body));
        if (!['new', 'reviewed', 'benign'].includes(status)) throw new Error();
      } catch {
        return Response.json({ detail: 'Invalid finding status.' }, { status: 422 });
      }
      try {
        const updated = accessStore((db) => db.prepare(
          'UPDATE local_detection_findings SET status = ? WHERE id = ?',
        ).run(status, reviewId).changes, false);
        return updated ? Response.json({ status }) :
          Response.json({ detail: 'Finding not found.' }, { status: 404 });
      } catch {
        return Response.json({ detail: 'Local findings storage is temporarily unavailable.' }, { status: 503 });
      }
    }
    if (request.method !== 'GET') return new Response(null, { status: 405 });
    try {
      if (pathname === '/api/local/findings') {
        const offset = Number(searchParams.get('offset') ?? 0);
        if (!Number.isSafeInteger(offset) || offset < 0) return new Response(null, { status: 422 });
        const { findings, summary } = accessStore((db) => ({
          findings: db.prepare(`
            SELECT status, payload FROM local_detection_findings
            ORDER BY CASE WHEN status = 'new' THEN 0 ELSE 1 END, last_seen DESC, id DESC LIMIT 101 OFFSET ?
          `).all(offset).map(({ status, payload }) => ({ ...JSON.parse(payload), status })),
          summary: db.prepare(`
            SELECT count(*) AS unreviewed,
              count(CASE WHEN json_extract(payload, '$.severity') IN ('high', 'critical') THEN 1 END) AS severe
            FROM local_detection_findings WHERE status = 'new'
          `).get(),
        })) ?? { findings: [], summary: { unreviewed: 0, severe: 0 } };
        return Response.json({ findings: findings.slice(0, 100), has_more: findings.length > 100,
          summary, monitor: child ? 'running' : failed ? 'failed' : 'stopped' });
      }
      const id = /^\/api\/local\/evidence\/([a-f0-9]{24})$/.exec(pathname)?.[1];
      if (id) {
        const row = accessStore((db) => db.prepare(`
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

  function sourceHealth() {
    return accessStore((db) => db.prepare('SELECT source, state, checked_at FROM local_source_health')
      .all().filter((row) => {
        const age = Date.now() - Date.parse(row.checked_at);
        return age >= 0 && age <= 120_000;
      })) ?? [];
  }

  return { handle, stop, sourceHealth };
}

module.exports = { makeLocalFindings };
