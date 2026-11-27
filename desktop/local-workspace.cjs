const servicing = require('./windows-servicing.json');
const { execFile } = require('node:child_process');
const { createHash } = require('node:crypto');
const { hostname, networkInterfaces } = require('node:os');
const { isIP } = require('node:net');
const path = require('node:path');
const { promisify } = require('node:util');

const execute = promisify(execFile);
const host = hostname();

async function readScript(file, args) {
  if (process.platform !== 'win32') throw new Error('Windows telemetry is unavailable.');
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const { stdout } = await execute(powershell, [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file, ...args,
  ], { timeout: 12000, windowsHide: true, maxBuffer: 2_000_000 });
  return JSON.parse(stdout);
}

function cachedReader(read, fallback) {
  let cached;
  let expires = 0;
  return (refresh = false) => {
    if (!cached || Date.now() >= expires || (refresh && Date.now() >= expires - 12000)) {
      cached = read().then((data) => ({
        ...data, state: data.state ?? 'ready', updated_at: new Date().toISOString(),
      })).catch(() => ({ ...fallback, state: 'unavailable', updated_at: null }));
      expires = Date.now() + 15000;
    }
    return cached;
  };
}

function normalize(alert) {
  const { system, eventdata } = alert.data.win;
  const timestamp = new Date(system.systemTime).toISOString();
  const id = createHash('sha256').update(host + '|' + timestamp + '|' + system.eventRecordID).digest('hex').slice(0, 24);
  return { id, timestamp, kind: Number(system.eventID), host, process: eventdata.image,
    target: eventdata.targetFilename, destination: eventdata.destinationIp, raw: alert };
}

function scriptCases(events) {
  const guid = (event) => event.raw.data.win.eventdata.processGuid;
  const processes = new Map(events.filter((event) => event.kind === 1 && guid(event))
    .map((event) => [guid(event), event]));
  return events.filter((event) => event.kind === 11 && /\.ps1$/i.test(event.target)).flatMap((file) => {
    const process = processes.get(guid(file));
    if (!process || !/^(powershell|pwsh)\.exe$/i.test(process.process) || process.timestamp > file.timestamp) return [];
    const id = file.id;
    const network = events.filter((event) => event.kind === 3 && guid(event) === guid(file) &&
      event.timestamp >= process.timestamp && event.timestamp <= file.timestamp && event.destination);
    return [{
      id, host, asset_id: 'local-pc', title: 'PowerShell process wrote a script file',
      summary: 'Sysmon recorded a PowerShell process and a script file creation with the same process ID.',
      evidence: [process, ...network.reverse(), file],
      links: network.map((event) => ({ destination: event.destination, evidence_id: event.id })),
    }];
  });
}

function activity(events) {
  const types = new Map();
  const hour = 3600000;
  const countByHour = new Map();
  for (const event of events) {
    types.set(event.kind, (types.get(event.kind) ?? 0) + 1);
    const start = Math.floor(Date.parse(event.timestamp) / hour) * hour;
    countByHour.set(start, (countByHour.get(start) ?? 0) + 1);
  }
  const latest = Math.floor(Date.parse(events[0]?.timestamp) / hour) * hour;
  return {
    interval: events.length ? 'hour' : null,
    buckets: events.length ? Array.from({ length: 12 }, (_, index) => {
      const start = latest - (11 - index) * hour;
      return { start: new Date(start).toISOString(), count: countByHour.get(start) ?? 0 };
    }) : [],
    types: [...types].map(([kind, count]) => ({ kind, count })).sort((a, b) => b.count - a.count),
  };
}

function makeLocalWorkspace(scripts, read = readScript, history, observeListeners, observePosture) {
  const states = new Set(['Listen', 'Established', 'SynSent', 'SynReceived', 'CloseWait']);
  const postureWeights = {
    'firewall-domain': 3, 'firewall-private': 3, 'firewall-public': 3,
    'defender-realtime': 3, 'defender-signatures': 2, 'defender-tamper': 2, 'os-encryption': 3,
    smbv1: 3, rdp: 3, uac: 2, 'secure-boot': 2, 'guest-account': 2,
  };
  const posture = cachedReader(async () => {
    const snapshot = await read(path.join(scripts, 'Read-NorthPosture.ps1'), []);
    if (!Array.isArray(snapshot?.checks) || snapshot.checks.length > 32 || !snapshot.checks.every((check) =>
      check && /^[a-z0-9-]{1,48}$/.test(check.id) && ['pass', 'fail', 'unknown'].includes(check.status) &&
      typeof check.title === 'string' && check.title.length <= 128 &&
      typeof check.reason === 'string' && check.reason.length <= 256)) throw new Error('Invalid posture response');
    if (new Set(snapshot.checks.map(({ id }) => id)).size !== snapshot.checks.length) {
      throw new Error('Duplicate posture check');
    }
    const checks = snapshot.checks.map(({ id, title, reason, status }) => ({
      id, title, reason, status, weight: Object.hasOwn(postureWeights, id) ? postureWeights[id] : 1,
    }));
    const score = { earned: 0, possible: 0, unknown: 0 };
    for (const check of checks) {
      if (check.status === 'unknown') score.unknown++;
      else {
        score.possible += check.weight;
        if (check.status === 'pass') score.earned += check.weight;
      }
    }
    const drift = observePosture
      ? await observePosture(checks, new Date().toISOString()).catch(() => ({ unavailable: true }))
      : undefined;
    return { checks, score, drift };
  }, { checks: [] });
  const postureDetails = cachedReader(async () => {
    const details = await read(path.join(scripts, 'Read-NorthPostureDetails.ps1'), []);
    const count = (value, limit) => Number.isInteger(value) && value >= 0 && value <= limit ? value : null;
    const date = (value) => typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value))
      ? new Date(value).toISOString() : null;
    const end = ['Core', 'Professional'].includes(details?.windows_edition) && /^\d{5}$/.test(details?.windows_build)
      ? servicing.homeAndPro[details.windows_build] : null;
    return {
      support_end: end ?? null,
      support_reviewed: end ? servicing.reviewed : null,
      pending_updates: count(details?.pending_updates, 100_000),
      recent_defender_detections: count(details?.recent_defender_detections, 50),
      last_update_at: date(details?.last_update_at),
      last_scan_at: date(details?.last_scan_at),
    };
  }, {});
  const tcp = cachedReader(async () => {
    const sample = await read(path.join(scripts, 'Read-NorthTcp.ps1'), []);
    if (!sample || !Array.isArray(sample.rows) || sample.rows.length > 200 ||
        !['ready', 'access_denied', 'unavailable', 'read_failed'].includes(sample.state)) {
      throw new Error('Invalid TCP snapshot');
    }
    const rows = sample.state === 'ready' ? sample.rows.filter((row) => row && states.has(row.state) &&
      [row.local_address, row.remote_address].every((address) => typeof address === 'string' && isIP(address)) &&
      [row.local_port, row.remote_port].every((port) => Number.isInteger(port) && port >= 0 && port <= 65535) &&
      Number.isInteger(row.pid) && row.pid >= 0 && row.pid <= 4294967295 &&
      typeof row.process === 'string' && row.process.length <= 256).map((row) => ({
      state: row.state, local_address: row.local_address, local_port: row.local_port,
      remote_address: row.remote_address, remote_port: row.remote_port, pid: row.pid, process: row.process,
    })) : [];
    const limited = sample.limited === true;
    const incompleteListeners = (sample.listeners_limited ?? limited) ||
      sample.rows.filter((row) => row?.state === 'Listen').length !== rows.filter((row) => row.state === 'Listen').length;
    const listenerHistory = sample.state === 'ready' && observeListeners
      ? await observeListeners(rows, new Date().toISOString(), incompleteListeners)
        .catch(() => ({ unavailable: true }))
      : undefined;
    return { state: sample.state, limited, rows, listener_history: listenerHistory };
  }, { rows: [], limited: false });
  const neighbors = cachedReader(async () => ({
    records: await read(path.join(scripts, 'Export-NorthNeighbors.ps1'), ['-AsJson']),
  }), { records: [] });
  const sysmon = cachedReader(async () => {
    try {
      const data = await read(path.join(scripts, 'Read-NorthSysmon.ps1'), ['-Recent']);
      return { events: data.alerts.map(normalize).sort((a, b) => b.timestamp.localeCompare(a.timestamp)) };
    } catch (error) {
      const detail = String(error?.stderr ?? '');
      return { events: [], state: 'unavailable', problem: detail.includes('UnauthorizedAccessException') ?
        'access_denied' : detail.includes('NoMatchingLogsFound') ? 'channel_missing' : 'read_failed' };
    }
  }, { events: [] });
  let previousCounters = new Map();
  let previousSample = 0;
  let adapterHistory = new Map();
  const adapterTraffic = cachedReader(async () => {
    const rows = await read(path.join(scripts, 'Read-NorthAdapterTraffic.ps1'), []);
    const now = performance.now();
    const elapsed = (now - previousSample) / 1000;
    const counters = new Map();
    const nextHistory = new Map();
    const sampledAt = new Date().toISOString();
    const adapters = [];
    for (const { name, received, sent } of rows) {
      if (typeof name !== 'string' || !/^\d{1,20}$/.test(received) || !/^\d{1,20}$/.test(sent)) continue;
      const rx = BigInt(received);
      const tx = BigInt(sent);
      const previous = previousCounters.get(name);
      const validRate = previous && elapsed > 0 && rx >= previous.rx && tx >= previous.tx;
      counters.set(name, { rx, tx });
      const adapter = { name, received_bytes: Number(rx), sent_bytes: Number(tx),
        receive_rate: validRate ? Number(rx - previous.rx) / elapsed : null,
        send_rate: validRate ? Number(tx - previous.tx) / elapsed : null };
      let history = adapterHistory.get(name) ?? [];
      if (validRate) history = [...history.slice(-11), {
        sampled_at: sampledAt, receive_rate: adapter.receive_rate, send_rate: adapter.send_rate,
      }];
      if (history.length) adapter.recent_rates = history;
      nextHistory.set(name, history);
      adapters.push(adapter);
    }
    previousCounters = counters;
    previousSample = now;
    adapterHistory = nextHistory;
    return { adapters };
  }, { adapters: [] });

  const handle = async (request) => {
    const { pathname, searchParams } = new URL(request.url);
    const reviewId = /^\/api\/network\/devices\/([a-f0-9]{24})\/review$/.exec(pathname)?.[1];
    if (request.method === 'POST' && reviewId && history) {
      const reviewed = await history.review(reviewId, new Date().toISOString()).catch(() => null);
      if (reviewed === null) return Response.json({ detail: 'Could not update device history' }, { status: 500 });
      return reviewed ? Response.json({ reviewed }) : Response.json({ detail: 'Device not found' }, { status: 404 });
    }
    if (request.method !== 'GET') return Response.json({ detail: 'Method unavailable' }, { status: 405 });
    if (pathname === '/api/local/posture/details') return Response.json(await postureDetails(), { headers: { 'Cache-Control': 'no-store' } });
    if (pathname === '/api/local/posture') return Response.json(await posture(), { headers: { 'Cache-Control': 'no-store' } });
    if (pathname === '/api/local/tcp') return Response.json(await tcp(), { headers: { 'Cache-Control': 'no-store' } });
    if (pathname === '/api/cases') return Response.json(scriptCases((await sysmon()).events));
    const reportId = /^\/api\/cases\/([a-f0-9]{24})\/report$/.exec(pathname)?.[1];
    if (reportId) {
      const incident = scriptCases((await sysmon()).events).find((item) => item.id === reportId);
      if (!incident) return Response.json({ detail: 'Investigation unavailable' }, { status: 404 });
      const lines = incident.evidence.map((event) => `- ${event.timestamp} · Sysmon ${event.kind} · Evidence ${event.id}`);
      return new Response([`# ${incident.title}`, '', incident.summary, '', ...lines].join('\n'), { headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="north-${reportId}.md"`,
      } });
    }
    if (pathname === '/api/network') {
      const refresh = searchParams.get('refresh') === '1';
      const [localNeighbors, localSysmon, traffic] = await Promise.all([neighbors(refresh), sysmon(), adapterTraffic(refresh)]);
      const { events, ...status } = localSysmon;
      const deviceFindings = history && await history.observe(localNeighbors.records,
        localNeighbors.updated_at ?? new Date().toISOString()).catch(() => undefined);
      const cases = scriptCases(events);
      const connections = new Map();
      const apps = new Map();
      for (const event of events) {
        if (event.kind !== 3 || !event.destination) continue;
        if (event.process) {
          const process = event.process.toLowerCase();
          const app = apps.get(process) ?? { events: 0, destinations: new Set() };
          app.events += 1;
          app.destinations.add(event.destination);
          apps.set(process, app);
        }
        const link = connections.get(event.destination) ?? { asset_id: 'local-pc', address: event.destination,
          direction: 'outbound', source: 'Sysmon', events: 0, last_seen: event.timestamp, cases: [] };
        link.events += 1;
        connections.set(event.destination, link);
      }
      return Response.json({
        local_device: { host, addresses: Object.entries(networkInterfaces()).flatMap(([name, entries]) =>
          entries.filter((entry) => !entry.internal).map(({ address }) => ({ interface: name, address }))) },
        assets: events.length ? [{ id: 'local-pc', host, events: events.length, last_seen: events[0].timestamp,
          cases: cases.map(({ id, title }) => ({ id, title })) }] : [],
        links: [...connections.values()],
        app_connections: [...apps].map(([process, app]) => ({
          process, events: app.events, destinations: app.destinations.size,
        })).sort((a, b) => b.events - a.events || a.process.localeCompare(b.process)),
        adapter_traffic: traffic,
        neighbors: localNeighbors,
        device_findings: deviceFindings,
        sysmon: { ...status, recent: true, session_events: events.length },
        activity: activity(events),
      });
    }
    if (pathname === '/api/events') {
      const search = (searchParams.get('q') ?? '').toLowerCase().slice(0, 200);
      const kind = searchParams.get('kind');
      const before = searchParams.get('before');
      const requested = Number(searchParams.get('limit') ?? 25);
      const limit = Number.isSafeInteger(requested) ? Math.max(1, Math.min(100, requested)) : 25;
      const cursor = (event) => event.timestamp + '|' + event.id;
      const { events, state } = await sysmon();
      const matches = events.filter((event) =>
        (!search || JSON.stringify(event).toLowerCase().includes(search)) &&
        (!kind || String(event.kind) === kind) && (!before || cursor(event) < before),
      ).sort((a, b) => cursor(b).localeCompare(cursor(a)));
      const page = matches.slice(0, limit);
      return Response.json({ events: page, next: matches.length > page.length ? cursor(page.at(-1)) : null,
        coverage: state === 'unavailable' ? 'sysmon_unavailable' : undefined });
    }
    return Response.json({ detail: 'Not found' }, { status: 404 });
  };
  handle.sourceChecks = async () => {
    const current = await sysmon();
    return { sysmon: { state: current.state, problem: current.problem,
      kinds: [...new Set(current.events.map((event) => event.kind))] } };
  };
  return handle;
}

module.exports = { makeLocalWorkspace };
