const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

const categories = {
  autoruns: 'Startup entries', services: 'Services', tasks: 'Scheduled tasks',
  listeners: 'Listening TCP endpoints', firewall: 'Firewall rules', users: 'Local accounts',
  admins: 'Local administrators', hosts: 'Hosts file', proxy: 'Proxy settings',
  dns: 'DNS servers', exclusions: 'Defender exclusions',
};

function snapshotStore(directory) {
  const filename = path.join(directory, 'verify-pc.json');
  let pending = Promise.resolve();
  return (operation) => {
    const next = pending.then(async () => {
      let state;
      try { state = JSON.parse(await fs.readFile(filename, 'utf8')); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        state = { baseline: null, timeline: [] };
      }
      const result = operation(state);
      if (result.write) {
        await fs.mkdir(directory, { recursive: true });
        await fs.writeFile(filename + '.tmp', JSON.stringify(state), { mode: 0o600 });
        await fs.rename(filename + '.tmp', filename);
      }
      return result.value;
    });
    pending = next.catch(() => {});
    return next;
  };
}

function compareSnapshots(current, baseline) {
  return Object.entries(categories).map(([id, title]) => {
    const latest = current.values[id];
    const prior = baseline?.values[id];
    if (!latest) return { id, title, status: 'unknown', detail: 'Windows did not return a complete observation.' };
    if (!prior) return { id, title, status: 'unknown', detail: 'No readable known-good observation exists for this category.' };
    const previous = new Set(prior);
    const observed = new Set(latest);
    const added = latest.filter((item) => !previous.has(item)).length;
    const removed = prior.filter((item) => !observed.has(item)).length;
    return { id, title, status: added || removed ? 'review' : 'fine', detail: added || removed
      ? `${added} added or modified, ${removed} removed or replaced. Compare with recent approved Windows changes.`
      : 'Matches the known-good snapshot.' };
  });
}

function composeVerdict(source, posture, details, comparison, findings, monitor = []) {
  const rows = [];
  const add = (id, title, status, detail) => rows.push({ id, title, status, detail });
  if (source?.state === 'ready') {
    add('sysmon', 'Sysmon event source', source.kinds?.length ? 'fine' : 'unknown',
      source.kinds?.length ? 'NORTH read events from this source.' : 'The source read returned no events.');
  } else add('sysmon', 'Sysmon event source', 'unknown', 'NORTH could not read the event source.');
  for (const row of monitor) {
    if (!['security', 'system', 'powershell', 'defender', 'tcp'].includes(row.source)) continue;
    const observed = row.state === 'collecting';
    add('source-' + row.source, row.source + ' collector source', observed ? 'fine' : 'unknown',
      observed ? 'The local monitor reported collecting.' : 'Review source access and availability in Detections.');
  }
  if (posture?.state === 'ready' && posture.checks.length) {
    for (const item of posture.checks) add(item.id, item.id === "secure-boot" ? "UEFI boot signature checks enabled" : item.title,
      ({ pass: 'fine', fail: 'review', unknown: 'unknown' })[item.status], item.reason);
  } else add('posture', 'Windows settings', 'unknown', 'The posture reader returned no results.');
  add('updates', 'Cached pending updates', details?.pending_updates == null ? 'unknown' : details.pending_updates ? 'review' : 'fine',
    details?.pending_updates == null ? 'Windows Update cache was unavailable.' :
      `${details.pending_updates} pending updates in the local cache. Check Windows Update for current availability.`);
  add('defender-events', 'Recent Defender events',
    details?.recent_defender_detections == null ? 'unknown' : details.recent_defender_detections ? 'review' : 'fine',
    details?.recent_defender_detections == null ? 'Defender event history was unavailable.' :
      `${details.recent_defender_detections === 50 ? '50 or more' : details.recent_defender_detections} detections in the sampled week.`);
  rows.push(...comparison.map((row) => ({ ...row, id: 'snapshot-' + row.id })));
  add('findings', 'Unreviewed findings', (findings?.monitor !== 'running' || !Number.isInteger(findings.summary?.unreviewed)) ? 'unknown' :
    findings.summary?.unreviewed > 0 ? 'review' : 'fine',
    (findings?.monitor !== 'running' || !Number.isInteger(findings.summary?.unreviewed)) ? 'The local findings monitor is unavailable.' :
      `${findings.summary.unreviewed} findings awaiting review.`);
  return Object.fromEntries(['fine', 'review', 'unknown'].map((status) =>
    [status, rows.filter((row) => row.status === status)]));
}

function makeVerifyPc({ directory, readSnapshot, readState, readFindings }) {
  const store = snapshotStore(directory);
  let activeRun;
  const run = async () => {
    const { source, posture, details, monitor } = await readState();
    const captured = await readSnapshot().catch(() => null);
    const findings = await readFindings().catch(() => null);
    const values = {};
    for (const category of Array.isArray(captured?.categories) ? captured.categories.slice(0, 12) : []) {
      if (category && Object.hasOwn(categories, category.id) && Array.isArray(category.items) && category.items.length <= 512 &&
          category.items.every((item) => typeof item === 'string' && /^[a-f0-9]{64}$/.test(item))) {
        values[category.id] = [...new Set(category.items)];
      }
    }
    return store((state) => {
      const snap = { id: randomUUID(), at: new Date().toISOString(), values };
      const verdict = composeVerdict(source, posture, details, compareSnapshots(snap, state.baseline), findings, monitor);
      state.timeline = [{ ...snap, verdict, compared_at: state.baseline?.at ?? null }, ...state.timeline].slice(0, 20);
      return { write: true, value: present(state) };
    });
  };
  function present(state) {
    return { baseline: state.baseline?.at ?? null, timeline: state.timeline.map(({ id, at, verdict, compared_at, values }) =>
      ({ id, at, verdict, compared_at, readable: Object.keys(values).length })) };
  }
  return async (request) => {
    const url = new URL(request.url);
    try {
      if (request.method === 'GET') return Response.json(await store((state) => ({ value: present(state) })));
      if (request.method !== 'POST') return new Response(null, { status: 405 });
      if (request.headers.get('origin') !== 'north://app') return new Response(null, { status: 403 });
      const knownGood = url.searchParams.get('baseline');
      if (!knownGood) {
        if (!activeRun) activeRun = run().finally(() => { activeRun = undefined; });
        return Response.json(await activeRun);
      }
      return await store((state) => {
        const snapshot = state.timeline.find((item) => item.id === knownGood);
        if (!snapshot || !Object.keys(snapshot.values).length) return { value: new Response(null, { status: 404 }) };
        state.baseline = snapshot;
        return { write: true, value: Response.json(present(state)) };
      });
    } catch {
      return Response.json({ detail: 'NORTH could not complete this PC check.' }, { status: 503 });
    }
  };
}
module.exports = { compareSnapshots, composeVerdict, makeVerifyPc };
