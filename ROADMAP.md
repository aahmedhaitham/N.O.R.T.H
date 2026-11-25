# NORTH 12-week roadmap and progress tracker

NORTH stands for **Network Operations, Reconnaissance, Threat Hunting**. The portfolio demo follows one incident from a Windows event to an evidence-backed report. IRIS investigates and correlates alerts, ATLAS shows the affected infrastructure, and ECHO reconstructs the timeline. All three use the same event and evidence IDs.

## Phase 0 · 25 November 2026

- [x] Read-only Windows and development environment audit.
- [x] Establish the planning workspace and save this tracker.
- [ ] Confirm pinned project dependency compatibility with the installed Python and Node versions.
- [ ] Verify WSL2 and Docker after setup is authorized, and measure memory and free disk before enabling concurrent services.
- [ ] Verify VMware guest boot and isolation before live lab work. Confirm Ollama model serving and measure inference latency and memory use.

The machine-specific environment audit is stored locally.

## Weekly milestones

Mark a week complete when its acceptance check passes and a commit, test result, or demo recording is linked in Evidence. The weeks are relative to the start of implementation.

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

## Progress log

| Date | Update | Next action |
| --- | --- | --- |
| 2026-11-25 | Read-only audit recorded. No installers, services or VM settings changed. | Check project runtime compatibility and agree on the first setup change before making it. |
