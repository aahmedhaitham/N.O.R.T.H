const cookieName = '__Host-north_session';
const sessionSeconds = 8 * 60 * 60;
const maxBytes = 700_000;
const emptyNetwork = { assets: [], links: [] };
const idPattern = /^[0-9a-f]{24}$/;
const sourcePattern = /^[a-z0-9][a-z0-9-]{0,47}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$/;
const headers = { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' };
const encoder = new TextEncoder();
const googleCallback = '/api/cloud/auth/google/callback';
const oauthCookie = '__Host-north_oauth';
const randomHex = () => Array.from(crypto.getRandomValues(new Uint8Array(32)),
  (byte) => byte.toString(16).padStart(2, '0')).join('');
const utcTimestamp = (ms) => new Date(ms).toISOString().replace('Z', '000+00:00');

function retentionCutoff(env, now) {
  const days = String(env.NORTH_HOSTED_RETENTION_DAYS ?? '');
  if (!/^[1-9]\d{0,2}$/.test(days) || Number(days) > 365) return null;
  return utcTimestamp(now - Number(days) * 86400000);
}

function filterRetainedSnapshot(body, cutoff, now) {
  const earliest = Date.parse(cutoff);
  const latest = now + 300000;
  const retained = (timestamp) => {
    if (typeof timestamp !== 'string') return false;
    const time = Date.parse(timestamp);
    return time >= earliest && time <= latest;
  };
  body.events = body.events.filter((event) => retained(event.timestamp));
  body.cases = body.cases.filter((item) => item.evidence.length &&
    item.evidence.every((event) => retained(event?.timestamp)));
  body.reports = Object.fromEntries(body.cases.map((item) => [item.id, body.reports[item.id]]));
}

async function pruneHostedData(db, cutoff) {
  await db.batch([
    db.prepare(`DELETE FROM cloud_events WHERE rowid IN (
      SELECT e.rowid FROM cloud_events e JOIN cloud_source_owners o ON o.source_id = e.source_id
      WHERE e.timestamp < ? ORDER BY e.timestamp LIMIT 1000
    )`).bind(cutoff),
    db.prepare(`DELETE FROM cloud_cases WHERE rowid IN (
      SELECT c.rowid FROM cloud_cases c JOIN cloud_source_owners o ON o.source_id = c.source_id
      WHERE julianday(c.timestamp) < julianday(?) OR EXISTS (
        SELECT 1 FROM json_each(c.payload, '$.evidence') AS e
        WHERE julianday(json_extract(e.value, '$.timestamp')) < julianday(?)
      ) ORDER BY c.timestamp LIMIT 500
    )`).bind(cutoff, cutoff),
  ]);
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers, ...extra } });
}

async function useQuota(db, account, operation, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const start = now - now % windowSeconds;
  const used = await db.prepare(`
    INSERT INTO cloud_usage_limits (account_id, operation, window_start, used) VALUES (?, ?, ?, 1)
    ON CONFLICT(account_id, operation) DO UPDATE SET
      used = CASE WHEN window_start < excluded.window_start THEN 1 ELSE used + 1 END,
      window_start = excluded.window_start
    WHERE window_start < excluded.window_start OR (window_start = excluded.window_start AND used < ?)
    RETURNING used
  `).bind(account, operation, start, limit).first();
  return used ? 0 : start + windowSeconds - now;
}

async function signature(secret, value) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function fingerprint(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
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
  if (!parts || ![3, 4].includes(parts.length) || !/^\d{10}$/.test(parts[0]) || !/^[0-9a-f-]{36}$/.test(parts[1])) return null;
  const expires = Number(parts[0]);
  const now = Math.floor(Date.now() / 1000);
  if (expires <= now || expires > now + sessionSeconds) return null;
  const account = parts.length === 4 ? parts[2] : 'legacy';
  if (!/^[a-z0-9-]{1,64}$/.test(account)) return null;
  return equal(parts.at(-1), await signature(secret, parts.slice(0, -1).join('.'))) ? account : null;
}

function cookie(value, lifetime) {
  return `${cookieName}=${value}; Path=/; Max-Age=${lifetime}; HttpOnly; Secure; SameSite=Strict`;
}

async function sessionCookie(secret, account) {
  const value = Math.floor(Date.now() / 1000 + sessionSeconds) + '.' + crypto.randomUUID() +
    (account ? '.' + account : '');
  return cookie(value + '.' + await signature(secret, value), sessionSeconds);
}

const googleEnabled = (env) => Boolean(env.NORTH_GOOGLE_CLIENT_ID && env.NORTH_GOOGLE_CLIENT_SECRET);

async function desktopTicket(secret, ticket) {
  const parts = /^([a-f0-9]{32})\.([a-f0-9]{64})\.(\d{10})\.([a-f0-9]{64})$/.exec(ticket ?? '');
  if (!parts || Number(parts[3]) <= Date.now() / 1000 ||
    !equal(parts[4], await signature(secret, 'desktop:' + parts.slice(1, 4).join('.')))) return null;
  return { nonce: parts[1], challenge: parts[2], expires: Number(parts[3]) };
}

async function desktopAuth(request, url, env) {
  if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
  if (!googleEnabled(env)) return json({ detail: 'Browser sign-in is unavailable.' }, 404);
  let data;
  try { data = await readBody(request, 1024); }
  catch { return json({ detail: 'Invalid desktop request.' }, 400); }
  if (!data || typeof data !== 'object') return json({ detail: 'Invalid desktop request.' }, 400);
  if (url.pathname.endsWith('/start')) {
    if (typeof data.challenge !== 'string' || !/^[a-f0-9]{64}$/.test(data.challenge)) {
      return json({ detail: 'Invalid desktop challenge.' }, 422);
    }
    const nonce = randomHex().slice(0, 32);
    const expires = Math.floor(Date.now() / 1000) + 300;
    const value = `${nonce}.${data.challenge}.${expires}`;
    return json({ ticket: value + '.' + await signature(env.NORTH_SESSION_SECRET, 'desktop:' + value), expires });
  }
  if (typeof data.ticket !== 'string') return json({ detail: 'Desktop request has expired.' }, 410);
  const ticket = await desktopTicket(env.NORTH_SESSION_SECRET, data.ticket);
  if (!ticket) return json({ detail: 'Desktop request has expired.' }, 410);
  if (url.pathname.endsWith('/approve')) {
    const account = await sessionValid(request, env.NORTH_SESSION_SECRET);
    if (!account || account === 'legacy') return json({ detail: 'Sign in with your individual account first.' }, 401);
    const grant = await env.DB.prepare(`INSERT INTO cloud_desktop_grants (nonce, account_id, expires_at)
      SELECT ?, id, ? FROM cloud_accounts WHERE id = ? AND disabled_at IS NULL
      ON CONFLICT(nonce) DO NOTHING RETURNING nonce`).bind(ticket.nonce, ticket.expires, account).first();
    return grant ? json({ approved: true }) : json({ detail: 'This request is unavailable or already approved.' }, 409);
  }
  if (typeof data.verifier !== 'string' || !/^[a-f0-9]{64}$/.test(data.verifier) ||
    !equal(ticket.challenge, await fingerprint(data.verifier))) return json({ detail: 'Invalid desktop verifier.' }, 403);
  const grant = await env.DB.prepare(`UPDATE cloud_desktop_grants SET used = 1
    WHERE nonce = ? AND expires_at > ? AND used = 0 AND EXISTS (
      SELECT 1 FROM cloud_accounts a WHERE a.id = account_id AND a.disabled_at IS NULL
    ) RETURNING account_id`).bind(ticket.nonce, Math.floor(Date.now() / 1000)).first();
  if (!grant) return json({ approved: false }, 202);
  return json({ signed_in: true }, 200, { 'Set-Cookie': await sessionCookie(env.NORTH_SESSION_SECRET, grant.account_id) });
}

function authRedirect(location, cookies = []) {
  const response = new Response(null, { status: 303, headers: {
    Location: location, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
  } });
  for (const value of cookies) response.headers.append('Set-Cookie', value);
  return response;
}

async function googleAuth(request, url, env) {
  if (!googleEnabled(env) || url.protocol !== 'https:') return json({ detail: 'Google sign-in is unavailable.' }, 404);
  const setOAuth = (value, age) => `${oauthCookie}=${value}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;
  const redirectUri = url.origin + googleCallback;
  if (url.pathname !== googleCallback) {
    const state = randomHex();
    const verifier = randomHex();
    const expires = Math.floor(Date.now() / 1000) + 600;
    const value = `${state}.${verifier}.${expires}`;
    const token = value + '.' + await signature(env.NORTH_SESSION_SECRET, 'google:' + value);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(verifier)));
    const challenge = btoa(String.fromCharCode(...digest)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    const destination = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    destination.search = new URLSearchParams({
      client_id: env.NORTH_GOOGLE_CLIENT_ID, redirect_uri: redirectUri, response_type: 'code',
      scope: 'openid profile', state, code_challenge: challenge, code_challenge_method: 'S256',
    }).toString();
    return authRedirect(destination, [setOAuth(token, 600)]);
  }

  const expiredCookie = setOAuth('', 0);
  const reject = (reason) => authRedirect('/?sign_in_failed=' + reason, [expiredCookie]);
  const saved = request.headers.get('Cookie')?.match(/(?:^|;\s*)__Host-north_oauth=([^;]+)/)?.[1] ?? '';
  const parts = /^([a-f0-9]{64})\.([a-f0-9]{64})\.(\d{10})\.([a-f0-9]{64})$/.exec(saved);
  const code = url.searchParams.get('code');
  if (!parts || !equal(parts[1], url.searchParams.get('state')) ||
    Number(parts[3]) <= Date.now() / 1000 ||
    !equal(parts[4], await signature(env.NORTH_SESSION_SECRET, 'google:' + parts.slice(1, 4).join('.')))) {
    return reject('session');
  }
  if (url.searchParams.has('error') || !code || code.length > 4096) return reject('authorization');
  let stage = 'provider';
  try {
    const exchange = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
      body: new URLSearchParams({ code, client_id: env.NORTH_GOOGLE_CLIENT_ID,
        client_secret: env.NORTH_GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri,
        grant_type: 'authorization_code', code_verifier: parts[2] }),
    });
    if (!exchange.ok) {
      const failure = await exchange.json().catch(() => null);
      return reject(failure?.error === 'invalid_client' ? 'configuration' : 'exchange');
    }
    const { access_token: token } = await exchange.json();
    if (typeof token !== 'string' || !token || token.length > 4096) return reject('exchange');
    const profile = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: 'Bearer ' + token }, redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    if (!profile.ok) return reject('profile');
    const { sub } = await profile.json();
    if (typeof sub !== 'string' || !sub || sub.length > 255) return reject('profile');
    stage = 'workspace';
    const account = 'google-' + (await fingerprint('google:' + sub)).slice(0, 56);
    await env.DB.prepare(`INSERT INTO cloud_accounts (id, access_key_hash) VALUES (?, ?)
      ON CONFLICT(id) DO NOTHING`).bind(account, randomHex()).run();
    if (!await env.DB.prepare('SELECT id FROM cloud_accounts WHERE id = ? AND disabled_at IS NULL').bind(account).first()) {
      return reject('workspace');
    }
    return authRedirect('/', [expiredCookie, await sessionCookie(env.NORTH_SESSION_SECRET, account)]);
  } catch {
    return reject(stage);
  }
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
    body.events.every((event) => typeof event?.id === 'string' && idPattern.test(event.id)
      && typeof event.timestamp === 'string' && timestampPattern.test(event.timestamp) && Number.isInteger(event.kind)) &&
    Array.isArray(body.network?.assets) && Array.isArray(body.network?.links) &&
    body.reports && typeof body.reports === 'object' && !Array.isArray(body.reports) &&
    body.cases.every((item) => typeof item?.id === 'string' && idPattern.test(item.id)
      && Array.isArray(item.evidence) && typeof body.reports[item.id] === 'string');
}

async function eventPage(db, source, params) {
  const q = (params.get('q') ?? '').trim().toLowerCase().slice(0, 200);
  const kind = params.get('kind');
  const before = params.get('before');
  const limit = Math.max(1, Math.min(100, Number.parseInt(params.get('limit') ?? '25', 10) || 25));
  const terms = ['source_id = ?'];
  const values = [source];
  if (q) {
    terms.push("lower(payload) LIKE ? ESCAPE '!'");
    values.push('%' + q.replaceAll('!', '!!').replaceAll('%', '!%').replaceAll('_', '!_') + '%');
  }
  if (kind) {
    if (!/^\d{1,6}$/.test(kind)) return null;
    terms.push('kind = ?');
    values.push(Number(kind));
  }
  if (before) {
    const [timestamp, id, extra] = before.split('|');
    if (extra !== undefined || !timestampPattern.test(timestamp) || !idPattern.test(id ?? '')) return null;
    terms.push('(timestamp < ? OR (timestamp = ? AND id < ?))');
    values.push(timestamp, timestamp, id);
  }
  const { results } = await db.prepare(
    `SELECT payload FROM cloud_events WHERE ${terms.join(' AND ')} ORDER BY timestamp DESC, id DESC LIMIT ?`,
  ).bind(...values, limit + 1).all();
  const events = results.slice(0, limit).map((row) => JSON.parse(row.payload));
  const last = events.at(-1);
  return { events, next: results.length > limit ? last.timestamp + '|' + last.id : null };
}

async function saveSnapshot(db, body, now) {
  const source = body.source ?? { id: 'legacy', label: 'Earlier collector' };
  if (typeof source.id !== 'string' || !sourcePattern.test(source.id)
    || typeof source.label !== 'string' || !source.label.trim() || source.label.length > 80) return false;
  await db.batch([
    db.prepare(`INSERT INTO cloud_sources (id, label, network, updated_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET label=excluded.label, network=excluded.network, updated_at=excluded.updated_at`)
      .bind(source.id, source.label, JSON.stringify(body.network), now),
    db.prepare(`INSERT OR IGNORE INTO cloud_events (source_id, id, timestamp, kind, payload)
      SELECT ?, json_extract(value, '$.id'), json_extract(value, '$.timestamp'), json_extract(value, '$.kind'), value
      FROM json_each(?)`).bind(source.id, JSON.stringify(body.events)),
    db.prepare(`INSERT INTO cloud_cases (source_id, id, timestamp, payload, report)
      SELECT ?, json_extract(value, '$.id'), coalesce(json_extract(value, '$.evidence[#-1].timestamp'), ?),
             value, json_extract(?, '$.' || json_extract(value, '$.id'))
      FROM json_each(?) WHERE 1
      ON CONFLICT(source_id,id) DO UPDATE SET timestamp=excluded.timestamp, payload=excluded.payload, report=excluded.report`)
      .bind(source.id, now, JSON.stringify(body.reports), JSON.stringify(body.cases)),
  ]);
  return true;
}

async function relatedEvidence(db, source, caseId, account) {
  const stored = await db.prepare('SELECT payload FROM cloud_cases WHERE source_id = ? AND id = ?')
    .bind(source, caseId).first();
  if (!stored) return null;
  const evidence = JSON.parse(stored.payload).evidence;
  const addresses = [...new Set(evidence.flatMap((event) => [event?.source_ip, event?.destination])
    .filter((address) => typeof address === 'string' && address.length <= 45 &&
      (/^\d{1,3}(\.\d{1,3}){3}$/.test(address) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(address))))].slice(0, 20);
  const latest = evidence.reduce((time, event) => Math.max(time, Date.parse(event?.timestamp) || 0), 0);
  if (!addresses.length || !latest) return [];
  const window = 5 * 60 * 1000;
  const { results } = await db.prepare(`
    SELECT e.id, e.timestamp, e.kind, e.source_id, s.label AS collector,
      json_extract(e.payload, '$.host') AS host, refs.value AS address
    FROM cloud_events e JOIN cloud_sources s ON s.id = e.source_id
    LEFT JOIN cloud_source_owners o ON o.source_id = e.source_id
    JOIN json_each(?) refs ON refs.value IN (json_extract(e.payload, '$.source_ip'),
      json_extract(e.payload, '$.destination'))
    WHERE e.timestamp BETWEEN ? AND ? AND e.source_id <> ? AND coalesce(o.account_id, 'legacy') = ?
    ORDER BY e.timestamp DESC, e.source_id, e.id, refs.value LIMIT 50
  `).bind(JSON.stringify(addresses), utcTimestamp(latest - window), utcTimestamp(latest + window), source, account).all();
  return results;
}

const observations = new Map([
  [1, 'A process started.'],
  [3, 'A network connection was recorded.'],
  [5, 'A process exited.'],
  [11, 'A file was created.'],
  [1001, 'An SSH authentication attempt failed.'],
  [1002, 'A sudo command was recorded.'],
]);

async function caseDraft(env, source, caseId, account) {
  const stored = await env.DB.prepare('SELECT payload FROM cloud_cases WHERE source_id = ? AND id = ?')
    .bind(source, caseId).first();
  if (!stored) return json({ detail: 'Case not found' }, 404);
  const findings = JSON.parse(stored.payload).evidence
    .filter((event) => typeof event?.id === 'string' && idPattern.test(event.id) && observations.has(event.kind))
    .slice(0, 20);
  if (!findings.length) return json({ detail: 'This case has no supported observations.' }, 422);
  const field = (value) => typeof value === 'string' ? value.trim().slice(0, 160) : '';
  const claim = (event) => {
    const details = {
      1: event.process, 3: event.destination, 5: event.process, 11: event.target,
      1001: event.source_ip, 1002: event.target,
    };
    const detail = field(details[event.kind]);
    const host = field(event.host);
    return { text: [observations.get(event.kind), host && 'Host: ' + host, detail && 'Observed value: ' + detail]
      .filter(Boolean).join(' · '), evidence_ids: [event.id] };
  };
  const fallback = (reason) => json({ claims: findings.slice(0, 3).map(claim), provider: 'evidence', reason });
  if (!env.AI) return fallback();
  if (await useQuota(env.DB, account, 'ai-brief', 20, 3600)) return fallback('ai_limit');
  if (await useQuota(env.DB, ':service', 'ai-brief', 200, 3600)) return fallback('ai_capacity');
  try {
    const answer = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [{
        role: 'user',
        content: 'Prioritize up to three verified observations based on their likely value for incident triage. Return only JSON with a finding_ids array of distinct 1-based numbers. ' +
          JSON.stringify(findings.map((event, index) => ({ id: index + 1, observation: observations.get(event.kind) }))),
      }],
      max_tokens: 60, temperature: 0, response_format: { type: 'json_object' },
    });
    const result = typeof answer?.response === 'string' ? JSON.parse(answer.response) : answer?.response;
    const ids = result?.finding_ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 3 || new Set(ids).size !== ids.length ||
      !ids.every((id) => Number.isInteger(id) && id >= 1 && id <= findings.length)) {
      throw new Error('Invalid observation selection');
    }
    return json({ claims: ids.map((id) => claim(findings[id - 1])), provider: 'cloud-ai' });
  } catch {
    return fallback();
  }
}

export default {
  async scheduled(controller, env) {
    await env.DB.prepare(`DELETE FROM cloud_desktop_grants WHERE nonce IN (
      SELECT nonce FROM cloud_desktop_grants WHERE expires_at <= ? ORDER BY expires_at LIMIT 1000
    )`).bind(Math.floor(controller.scheduledTime / 1000)).run();
    const cutoff = retentionCutoff(env, controller.scheduledTime);
    if (cutoff) await pruneHostedData(env.DB, cutoff);
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!path.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (![env.NORTH_ACCESS_KEY, env.NORTH_INGEST_KEY, env.NORTH_SESSION_SECRET]
      .every((secret) => typeof secret === 'string' && secret.length >= 32)) {
      return json({ detail: 'Cloud service setup is incomplete.' }, 503);
    }
    if (request.method === 'GET' && path === '/api/cloud/auth/options') {
      return json({ google: googleEnabled(env) });
    }
    if (request.method === 'GET' && [googleCallback, '/api/cloud/auth/google'].includes(path)) {
      return googleAuth(request, url, env);
    }
    if (request.method === 'POST' && /^\/api\/cloud\/desktop\/(start|approve|exchange)$/.test(path)) {
      return desktopAuth(request, url, env);
    }

    if (request.method === 'POST' && path === '/api/cloud/snapshot') {
      const token = /^Bearer ([A-Za-z0-9+/=]{32,128})$/.exec(request.headers.get('Authorization') ?? '')?.[1];
      if (!token) return json({ detail: 'Unauthorized' }, 401);
      const legacyKey = equal(token, env.NORTH_INGEST_KEY);
      const paired = legacyKey ? null : await env.DB.prepare(
        `SELECT p.source_id, p.label, p.revoked_at, o.account_id FROM cloud_pairings p
         LEFT JOIN cloud_source_owners o ON o.source_id = p.source_id
         LEFT JOIN cloud_accounts a ON a.id = o.account_id
         WHERE p.token_hash = ? AND (o.account_id IS NULL OR (a.id IS NOT NULL AND a.disabled_at IS NULL))`,
      ).bind(await fingerprint(token)).first();
      if (!legacyKey && (!paired || paired.revoked_at)) {
        return json({ detail: 'Unauthorized' }, 401);
      }
      try {
        const body = await readBody(request, maxBytes);
        if (!validSnapshot(body)) return json({ detail: 'Invalid collector snapshot' }, 422);
        if (paired && body.source?.id !== paired.source_id) return json({ detail: 'Pairing belongs to another collector.' }, 403);
        if (legacyKey && /^collector-[0-9a-f]{20}$/.test(body.source?.id ?? '')) return json({ detail: 'A collector pairing is required.' }, 403);
        if (paired) body.source = { id: paired.source_id, label: paired.label };
        const retry = await useQuota(env.DB, paired?.account_id ?? 'legacy', 'snapshot', 600, 3600);
        if (retry) return json({ detail: 'The workspace has reached its hourly upload limit.' }, 429, {
          'Retry-After': String(retry),
        });
        const now = Date.now();
        const cutoff = paired?.account_id && retentionCutoff(env, now);
        if (cutoff) filterRetainedSnapshot(body, cutoff, now);
        if (!await saveSnapshot(env.DB, body, new Date(now).toISOString())) return json({ detail: 'Invalid collector identity' }, 422);
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
        if (typeof key !== 'string') return json({ detail: 'Access key did not match.' }, 401);
        const legacy = equal(key, env.NORTH_ACCESS_KEY);
        const account = legacy ? null : /^[a-f0-9]{64}$/.test(key) && await env.DB.prepare(
          'SELECT id FROM cloud_accounts WHERE access_key_hash = ? AND disabled_at IS NULL',
        ).bind(await fingerprint(key)).first();
        if (!legacy && !account) return json({ detail: 'Access key did not match.' }, 401);
        return json({ signed_in: true }, 200, {
          'Set-Cookie': await sessionCookie(env.NORTH_SESSION_SECRET, account?.id),
        });
      } catch {
        return json({ detail: 'Invalid sign-in request.' }, 400);
      }
    }

    const account = await sessionValid(request, env.NORTH_SESSION_SECRET);
    if (!account || (account !== 'legacy' && !await env.DB.prepare(
      'SELECT id FROM cloud_accounts WHERE id = ? AND disabled_at IS NULL',
    ).bind(account).first())) return json({ detail: 'Sign in required' }, 401);

    if (path === '/api/cloud/pairings') {
      if (request.method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT p.source_id, p.label, p.created_at, p.revoked_at, s.updated_at
           FROM cloud_pairings p LEFT JOIN cloud_sources s ON s.id = p.source_id
           LEFT JOIN cloud_source_owners o ON o.source_id = p.source_id
           WHERE coalesce(o.account_id, 'legacy') = ? ORDER BY p.created_at DESC LIMIT 100`,
        ).bind(account).all();
        return json({ pairings: results });
      }
      if (request.method === 'POST') {
        if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
        try {
          const body = await readBody(request, 2048);
          const label = typeof body.label === 'string' ? body.label.trim() : '';
          if (!label || label.length > 80) return json({ detail: 'Enter a name up to 80 characters.' }, 422);
          const sourceId = 'collector-' + crypto.randomUUID().replaceAll('-', '').slice(0, 20);
          const token = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, '0')).join('');
          const pairing = env.DB.prepare('INSERT INTO cloud_pairings (source_id, label, token_hash, created_at) VALUES (?, ?, ?, ?)')
            .bind(sourceId, label, await fingerprint(token), new Date().toISOString());
          if (account === 'legacy') await pairing.run();
          else await env.DB.batch([pairing, env.DB.prepare(
            'INSERT INTO cloud_source_owners (source_id, account_id) VALUES (?, ?)',
          ).bind(sourceId, account)]);
          return json({ source_id: sourceId, label, token }, 201);
        } catch {
          return json({ detail: 'Could not create the collector pairing.' }, 400);
        }
      }
    }
    const revoke = /^\/api\/cloud\/pairings\/(collector-[0-9a-f]{20})\/revoke$/.exec(path);
    if (request.method === 'POST' && revoke) {
      if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
      const result = await env.DB.prepare(
        `UPDATE cloud_pairings SET revoked_at = coalesce(revoked_at, ?) WHERE source_id = ?
         AND coalesce((SELECT account_id FROM cloud_source_owners WHERE source_id = cloud_pairings.source_id), 'legacy') = ?`,
      ).bind(new Date().toISOString(), revoke[1], account).run();
      return result.meta.changes ? json({ revoked: true }) : json({ detail: 'Collector not found.' }, 404);
    }
    const draftId = request.method === 'POST' && /^\/api\/cases\/([0-9a-f]{24})\/draft$/.exec(path)?.[1];
    if (draftId && request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
    if (request.method !== 'GET' && !draftId) return json({ detail: 'This cloud endpoint is read-only' }, 405);
    if (path === '/api/cloud/status') {
      const { results: sources } = await env.DB.prepare(
        `SELECT s.id, s.label, s.updated_at FROM cloud_sources s
         LEFT JOIN cloud_source_owners o ON o.source_id = s.id
         WHERE coalesce(o.account_id, 'legacy') = ? ORDER BY s.updated_at DESC, s.id LIMIT 100`,
      ).bind(account).all();
      return json({ signed_in: true, sources });
    }
    const sourceId = url.searchParams.get('source');
    if (sourceId && !sourcePattern.test(sourceId)) return json({ detail: 'Invalid collector identity' }, 422);
    const source = await env.DB.prepare(`SELECT s.id, s.network FROM cloud_sources s
      LEFT JOIN cloud_source_owners o ON o.source_id = s.id
      WHERE coalesce(o.account_id, 'legacy') = ? AND (? IS NULL OR s.id = ?)
      ORDER BY s.updated_at DESC, s.id LIMIT 1`).bind(account, sourceId, sourceId).first();
    if (sourceId && !source) return json({ detail: 'Collector not found' }, 404);
    if (draftId) return source ? caseDraft(env, source.id, draftId, account) : json({ detail: 'Case not found' }, 404);
    if (path === '/api/cases') {
      if (!source) return json([]);
      const { results } = await env.DB.prepare(
        'SELECT payload FROM cloud_cases WHERE source_id = ? ORDER BY timestamp DESC, id DESC LIMIT 100',
      ).bind(source.id).all();
      return json(results.map((row) => JSON.parse(row.payload)));
    }
    const relatedId = /^\/api\/cases\/([0-9a-f]{24})\/related$/.exec(path)?.[1];
    if (relatedId) {
      const matches = source ? await relatedEvidence(env.DB, source.id, relatedId, account) : null;
      return matches ? json({ matches }) : json({ detail: 'Case not found' }, 404);
    }
    if (path === '/api/network') return json(source ? JSON.parse(source.network) : emptyNetwork);
    if (path === '/api/events') {
      const page = source ? await eventPage(env.DB, source.id, url.searchParams) : { events: [], next: null };
      return page ? json(page) : json({ detail: 'Invalid event filter' }, 422);
    }
    const eventId = /^\/api\/events\/([0-9a-f]{24})$/.exec(path)?.[1];
    if (eventId) {
      const row = source && await env.DB.prepare('SELECT payload FROM cloud_events WHERE source_id = ? AND id = ?')
        .bind(source.id, eventId).first();
      return row ? json(JSON.parse(row.payload)) : json({ detail: 'Evidence not found' }, 404);
    }
    const id = /^\/api\/cases\/([0-9a-f]{24})\/report$/.exec(path)?.[1];
    const stored = id && source && await env.DB.prepare(
      'SELECT report FROM cloud_cases WHERE source_id = ? AND id = ?',
    ).bind(source.id, id).first();
    if (stored) {
      return new Response(stored.report, { headers: {
        'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="north-${id}.md"`,
      } });
    }
    return json({ detail: 'Not found' }, 404);
  },
};
