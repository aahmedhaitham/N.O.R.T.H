const cookieName = '__Host-north_session';
const sessionSeconds = 8 * 60 * 60;
const maxBytes = 700_000;
const empty = { cases: [], events: [], network: { assets: [], links: [] }, reports: {} };
const headers = { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' };
const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers, ...extra } });
}

async function signature(secret, value) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function equal(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}

async function sessionValid(request, secret) {
  const token = request.headers.get('Cookie')?.match(/(?:^|;\s*)__Host-north_session=([^;]+)/)?.[1];
  const parts = token?.split('.');
  if (!parts || parts.length !== 3 || !/^\d{10}$/.test(parts[0]) || !/^[0-9a-f-]{36}$/.test(parts[1])) return false;
  const expires = Number(parts[0]);
  const now = Math.floor(Date.now() / 1000);
  if (expires <= now || expires > now + sessionSeconds) return false;
  return equal(parts[2], await signature(secret, parts[0] + '.' + parts[1]));
}

function cookie(value, lifetime) {
  return `${cookieName}=${value}; Path=/; Max-Age=${lifetime}; HttpOnly; Secure; SameSite=Strict`;
}

async function readBody(request, limit) {
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  const pieces = [];
  let length = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      throw new Error('Body too large');
    }
    pieces.push(value);
  }
  return JSON.parse(await new Blob(pieces).text());
}

function validSnapshot(body) {
  return body && Array.isArray(body.cases) && body.cases.length <= 100 &&
    Array.isArray(body.events) && body.events.length <= 150 &&
    body.events.every((event) => typeof event?.timestamp === 'string' && /^[0-9a-f]{24}$/.test(event.id)) &&
    Array.isArray(body.network?.assets) && Array.isArray(body.network?.links) &&
    body.reports && typeof body.reports === 'object' && !Array.isArray(body.reports);
}

function eventPage(events, params) {
  const q = (params.get('q') ?? '').trim().toLowerCase().slice(0, 200);
  const kind = params.get('kind');
  const before = params.get('before');
  const limit = Math.max(1, Math.min(100, Number.parseInt(params.get('limit') ?? '25', 10) || 25));
  const cursor = (event) => event.timestamp + '|' + event.id;
  const matches = events.filter((event) => (!kind || String(event.kind) === kind)
    && (!before || cursor(event) < before) && (!q || JSON.stringify(event).toLowerCase().includes(q)))
    .sort((a, b) => cursor(a) < cursor(b) ? 1 : cursor(a) > cursor(b) ? -1 : 0);
  return { events: matches.slice(0, limit), next: matches.length > limit ? cursor(matches[limit - 1]) : null };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!path.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (![env.NORTH_ACCESS_KEY, env.NORTH_INGEST_KEY, env.NORTH_SESSION_SECRET]
      .every((secret) => typeof secret === 'string' && secret.length >= 32)) {
      return json({ detail: 'Cloud service setup is incomplete.' }, 503);
    }

    if (request.method === 'POST' && path === '/api/cloud/snapshot') {
      if (!equal(request.headers.get('Authorization'), 'Bearer ' + env.NORTH_INGEST_KEY)) return json({ detail: 'Unauthorized' }, 401);
      try {
        const body = await readBody(request, maxBytes);
        if (!validSnapshot(body)) return json({ detail: 'Invalid collector snapshot' }, 422);
        const now = new Date().toISOString();
        await env.DB.prepare('INSERT INTO snapshots (id, payload, updated_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at')
          .bind(JSON.stringify(body), now).run();
        return json({ updated_at: now });
      } catch {
        return json({ detail: 'Could not store collector snapshot' }, 400);
      }
    }

    if (request.method === 'POST' && ['/api/cloud/login', '/api/cloud/logout'].includes(path)) {
      if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
      if (path.endsWith('/logout')) return json({ signed_in: false }, 200, { 'Set-Cookie': cookie('', 0) });
      try {
        const { key } = await readBody(request, 1024);
        if (typeof key !== 'string' || !equal(key, env.NORTH_ACCESS_KEY)) return json({ detail: 'Access key did not match.' }, 401);
        const value = Math.floor(Date.now() / 1000 + sessionSeconds) + '.' + crypto.randomUUID();
        return json({ signed_in: true }, 200, {
          'Set-Cookie': cookie(value + '.' + await signature(env.NORTH_SESSION_SECRET, value), sessionSeconds),
        });
      } catch {
        return json({ detail: 'Invalid sign-in request.' }, 400);
      }
    }

    if (!await sessionValid(request, env.NORTH_SESSION_SECRET)) return json({ detail: 'Sign in required' }, 401);
    if (request.method !== 'GET') return json({ detail: 'This cloud endpoint is read-only' }, 405);
    const stored = await env.DB.prepare('SELECT payload, updated_at FROM snapshots WHERE id=1').first();
    const data = stored ? JSON.parse(stored.payload) : empty;
    if (path === '/api/cloud/status') return json({ signed_in: true, synced_at: stored?.updated_at ?? null });
    if (path === '/api/cases') return json(data.cases);
    if (path === '/api/network') return json(data.network);
    if (path === '/api/events') return json(eventPage(data.events, url.searchParams));
    const id = /^\/api\/cases\/([0-9a-f]{24})\/report$/.exec(path)?.[1];
    if (id && typeof data.reports[id] === 'string') {
      return new Response(data.reports[id], { headers: {
        'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="north-${id}.md"`,
      } });
    }
    return json({ detail: 'Not found' }, 404);
  },
};
