# NORTH 12-week roadmap and progress tracker

NORTH stands for **Network Operations, Reconnaissance, Threat Hunting**. The portfolio demo follows one incident from a Windows event to an evidence-backed report. IRIS investigates and correlates alerts, ATLAS shows the affected infrastructure, and ECHO reconstructs the timeline. All three use the same event and evidence IDs.

## Phase 0 · 25 November 2026

- [x] Read-only Windows and development environment audit.
- [x] Establish the planning workspace and save this tracker.
- [x] Check Python 3.14 and Node 26 against published FastAPI, Pytest, and Vite requirements.
- [ ] Resolve the project's dependencies and run the backend smoke test and frontend build. Package resolution from this session was blocked.
- [ ] Verify WSL2 and Docker after setup is authorized, and measure memory and free disk before enabling concurrent services.
- [ ] Verify VMware guest boot and isolation before live lab work. Confirm Ollama model serving and measure inference latency and memory use.

The machine-specific environment audit is stored locally.

## Weekly milestones

These milestones preserve the original roadmap. The build proceeds by dependency and validation, with no weekly waiting period.

| Week | Status | Deliverable and acceptance check | Interview question | Evidence |
| --- | --- | --- | --- | --- |
| 1 | Planned | Create a React + TypeScript and FastAPI skeleton. Define the event contract and add a Pytest health-check test. Document the reproducible setup and tool versions. | Why separate the API from the UI? | |
| 2 | Planned | Add PostgreSQL migrations and a fixture importer. Re-import the same batch and verify stable event IDs and zero new duplicates. Record raw payload, source and UTC timestamps. | Where is idempotency enforced, and what happens on retry? | |
| 3 | Planned | Build an alert and evidence view with a WebSocket feed. Disconnect, reconnect and recover missed events through the API without duplicate rows. | Why do live notifications need a durable source of truth? | |
| 4 | Planned | Build IRIS rule-based correlation for one benign simulated scenario. Verify matching, near-miss and out-of-order fixtures with Pytest. | What causes false positives, and how would you measure them? | |
| 5 | Planned | Add Ollama investigation drafts with evidence IDs, explicit uncertainty and analyst review. Verify that invalid citations are rejected and the case stays usable when Ollama is offline. | How do you verify a model claim against source evidence? | |
| 6 | Planned | Build the ATLAS infrastructure digital twin with React Flow. Select an alert and see its affected assets and evidence-backed relationships. | How do you distinguish observed links from inferred ones? | |
| 7 | Planned | Build ECHO timeline and replay. Verify deterministic ordering for tied timestamps and preserve original source timestamps. | How do clock skew and late events affect a reconstruction? | |
| 8 | Planned | Import Sysmon and Wazuh telemetry from a benign action in an authorized isolated lab. Verify the same event contract and retain a sanitized replay fixture. If lab capacity blocks live capture, keep live integration open and use fixtures for the demo build. | What data does Sysmon provide, and what does Wazuh add? | |
| 9 | Planned | Join IRIS, ATLAS and ECHO around a shared case and export an investigation report. Trace each material finding to its stored evidence. | Which records are evidence and which are analyst conclusions? | |
| 10 | Planned | Run Pytest integration checks for malformed input, duplicates, reconnects and unavailable Ollama. Capture replay latency and peak memory on the laptop. | What failure modes remain, and what would you monitor? | |
| 11 | Planned | Verify the Docker demo from a clean checkout with a sanitized fixture. Write the architecture and operating guide and document the live lab separately. | Which services would you isolate or scale first, and why? | |
| 12 | Planned | Record a short walkthrough, finish the README and write a CV bullet grounded in measured outcomes. Practice a five-minute architecture explanation and a failure-mode walkthrough. | Which trade-off mattered most, and what would you change next? | |

## Demo and lab scope

Start with a repeatable fixture and a single case. Measure the core app, model and telemetry lab independently before running them together. The final walkthrough opens an alert, traces the affected asset, replays the timeline and exports a report with evidence references. Use only authorized isolated labs and benign or synthetic telemetry. Ollama drafts are advisory and require analyst review.

## Implementation and verification

| Area | Status | Evidence or remaining check |
| --- | --- | --- |
| Event storage and IRIS correlation | Core verified with SQLite | Tests cover replay, duplicates, near misses, malformed batches and linked evidence. |
| FastAPI and WebSockets | Browser and CI verified | The browser showed a connected live feed and downloaded the report. The hosted API suite passed. |
| ATLAS and ECHO console | Build and replay verified | The TypeScript check and Vite production build passed. The user confirmed the ECHO replay advanced through all three events. |
| Wazuh and Sysmon | Export importer verified with fixtures | Dry run and import coverage include JSON arrays, JSON Lines and indexer search hits. A real capture from an isolated Windows guest remains pending. |
| Ollama | Live fixture benchmark verified by user | Qwen2.5-Coder returned six valid drafts with a 0.61-second warm median. Two reported timed Qwen3 attempts were rejected. The README records the comparison. |
| Docker and PostgreSQL | Hosted check passed | GitHub Actions verified the gateway and PostgreSQL persistence after restarting with seeding disabled. [Passing run](https://github.com/aahmedhaitham/N.O.R.T.H/actions/runs/45588172311) |
| Portfolio | Core demo verified by user | Capture the walkthrough for the portfolio. Docker, live lab ingestion, and a real Ollama draft are tracked above. |
| Public hosting | Ready for deployment | The Render Blueprint runs the live console against a bundled synthetic case. The public URL and hosted smoke check are pending. |

## Progress log

| Date | Update | Next action |
| --- | --- | --- |
| 2026-11-25 | Read-only audit recorded. No installers, services or VM settings changed. | Check project runtime compatibility and agree on the first setup change before making it. |
| 2026-11-25 | Published requirements support the initial Python and Node choices. | Validate the resolved dependencies with the Week 1 scaffold. |
| 2026-11-25 | Implemented the console, ingest path, case analysis, topology, replay and report export. | Install project dependencies to run the API tests and browser walkthrough. |
| 2026-11-25 | Installed dependencies on the host, verified the frontend production build and four backend tests, and confirmed the demo commit reached GitHub. | Verify live HTTP, WebSockets and the browser walkthrough. |
| 2026-11-25 | User verified the live feed, three-event playback and Markdown report download in the browser. | Capture the portfolio walkthrough and verify optional integrations. |
