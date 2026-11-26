# Architecture

## Local Windows app

Electron hosts the bundled React and TypeScript interface. The isolated renderer uses the application's own origin to request read-only Windows observations. The main process routes requests to fixed readers. Checks reflect the event logs and adapter data the current account can read.

Optional local monitoring runs the bundled Python collector and writes evidence, findings, review status, and learned baselines to a private SQLite database. It normalizes events, queues new records, evaluates enabled rules, and links findings back to evidence IDs. The collector is tied to the desktop session when started from local mode.

- ATLAS groups nearby device observations and shows recorded connections. Device names and traffic rates depend on the evidence source.
- IRIS filters recorded events and exposes their evidence.
- ECHO presents investigations, playback, process relationships, and report export.
- NORTH Assistant uses bounded in-memory records from views that have already loaded. It opens citations through app navigation.

## Development backend and optional hosted workspace

FastAPI supports the loopback development setup. The Docker setup can use PostgreSQL for persistence. NORTH Cloud is a separate Cloudflare Worker and D1 deployment. A separately paired collector can send a workspace its configured snapshots. The desktop can access that workspace over HTTPS using the main-process session bridge.

A successful connection or an available log doesn't establish detection coverage. The coverage matrix uses recent source checks, observed event types, and enabled rules. The recorded coverage and benchmark methodology are documented separately.

[Development](DEVELOPMENT.md) · [Optional cloud](CLOUD.md) · [Privacy](../PRIVACY.md) · [Threat model](../THREAT_MODEL.md)
