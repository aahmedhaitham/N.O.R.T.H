CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_sources (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    network TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_events (
    source_id TEXT NOT NULL REFERENCES cloud_sources(id),
    id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    kind INTEGER NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (source_id, id)
);
CREATE INDEX IF NOT EXISTS cloud_events_time ON cloud_events (source_id, timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS cloud_events_workspace_time ON cloud_events (timestamp DESC);

CREATE TABLE IF NOT EXISTS cloud_cases (
    source_id TEXT NOT NULL REFERENCES cloud_sources(id),
    id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL,
    report TEXT NOT NULL,
    PRIMARY KEY (source_id, id)
);
CREATE INDEX IF NOT EXISTS cloud_cases_time ON cloud_cases (source_id, timestamp DESC, id DESC);

CREATE TABLE IF NOT EXISTS cloud_case_reviews (
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'resolved')),
    notes TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source_id, case_id),
    FOREIGN KEY (source_id, case_id) REFERENCES cloud_cases(source_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cloud_pairings (
    source_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS cloud_accounts (
    id TEXT PRIMARY KEY CHECK (id <> 'legacy'),
    access_key_hash TEXT NOT NULL UNIQUE,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS cloud_source_owners (
    source_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES cloud_accounts(id)
);
CREATE INDEX IF NOT EXISTS cloud_source_owners_account ON cloud_source_owners (account_id);

CREATE TABLE IF NOT EXISTS cloud_usage_limits (
    account_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    used INTEGER NOT NULL,
    PRIMARY KEY (account_id, operation)
);
CREATE TABLE IF NOT EXISTS cloud_desktop_grants (
    nonce TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES cloud_accounts(id),
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS cloud_desktop_grants_expiry ON cloud_desktop_grants (expires_at);

CREATE TABLE IF NOT EXISTS cloud_revoked_sessions (
    session_id TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cloud_workspace_preferences (
    account_id TEXT PRIMARY KEY,
    ai_enabled INTEGER NOT NULL CHECK (ai_enabled IN (0, 1))
);
CREATE TABLE IF NOT EXISTS cloud_saved_searches (
    account_id TEXT NOT NULL,
    id TEXT NOT NULL,
    label TEXT NOT NULL,
    query TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, label)
);
CREATE INDEX IF NOT EXISTS cloud_revoked_sessions_expiry ON cloud_revoked_sessions (expires_at);

INSERT OR IGNORE INTO cloud_sources (id, label, network, updated_at)
SELECT 'legacy', 'Earlier collector', json_extract(payload, '$.network'), updated_at FROM snapshots;

INSERT OR IGNORE INTO cloud_events (source_id, id, timestamp, kind, payload)
SELECT 'legacy', json_extract(event.value, '$.id'), json_extract(event.value, '$.timestamp'),
       json_extract(event.value, '$.kind'), event.value
FROM snapshots, json_each(snapshots.payload, '$.events') AS event;

INSERT OR IGNORE INTO cloud_cases (source_id, id, timestamp, payload, report)
SELECT 'legacy', json_extract(item.value, '$.id'),
       coalesce(json_extract(item.value, '$.evidence[#-1].timestamp'), snapshots.updated_at),
       item.value, coalesce(json_extract(snapshots.payload, '$.reports.' || json_extract(item.value, '$.id')), '')
FROM snapshots, json_each(snapshots.payload, '$.cases') AS item;
