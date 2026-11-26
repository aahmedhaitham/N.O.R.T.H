# Authorized telemetry lab

## Add lab data or use local AI

### View your network

Open **Network** to see reporting devices and observed inbound and outbound connections. Select a linked investigation to review its evidence.

Open **Events** to search collected telemetry by host, process, address, or keyword. Filter by event type and expand a record to view its source fields and evidence ID. The newest page refreshes automatically. Older pages use a timestamp and event ID cursor so new activity does not move the page boundary.

On Windows, **Start NORTH.cmd** includes the automatic neighbor-cache collector. It reads the existing cache every 30 seconds and keeps the current snapshot in memory. On a native Linux installation, start FastAPI with `NORTH_NETWORK_AUTO=1 .venv/bin/python -m uvicorn main:app` and the `ip` utility available. Enable automatic collection only for a private NORTH instance. The public deployment disables it.

The first usable snapshot starts a saved device baseline. NORTH flags previously unseen MAC-and-interface combinations in subsequent snapshots. Open **Newly observed devices** to see the addresses and first/last observation times, then mark a finding reviewed. A changed or randomized MAC can show as new, and moving the collector to another network can reveal many new devices. The finding records a cache observation and does not determine whether a device is harmful or still online.

On Windows, the launcher also collects configured Sysmon process, connection and file-creation records about every 15 seconds after Sysmon is installed. NORTH saves the record cursor with the imported events and resumes after a restart. The launcher does not install or reconfigure Sysmon. Check **Windows event collection** in **Network** for status.

For another device source, choose **Import a device list**. You can load a saved neighbor cache or a router inventory converted to a JSON array with fields `address`, optional `name` and `mac`. The browser keeps imported records in memory and clears them when the page reloads.

- **Wazuh and Sysmon.** Preview a sanitized export from an authorized, isolated lab with `python backend/ingest.py path/to/alerts.json --check`. NORTH accepts a JSON array, JSON Lines, or indexer search hits containing `_source`. It selects Sysmon event IDs 1, 3, and 11 and reports how many cases the export can reconstruct. Omit `--check` to import into a running local backend. For Docker, add `--base-url http://127.0.0.1:8080`. Start with a fresh database and set `NORTH_SEED_DEMO=0` to evaluate lab events independently of the bundled case. Wazuh alerts can omit telemetry below the alert threshold, so consult the [Wazuh alert documentation](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html) if expected events are missing.
- **Linux OpenSSH.** If OpenSSH already writes to your Linux journal, export your own service's existing records with `journalctl -u ssh.service -u sshd.service --since today --no-pager -o json > ssh-journal.jsonl`. Preview with `python3 backend/ingest.py ssh-journal.jsonl --format journal --check`. Omit `--check` to import to your local NORTH instance. IRIS flags groups of three failures from the same source on the same host within five minutes, ATLAS maps the inbound address, and ECHO lists the original events. Keep real exports local.
- **Ollama.** With a local server running and `qwen2.5-coder:7b` available, click **Generate draft** in IRIS. Override the server or model with `OLLAMA_URL` or `OLLAMA_MODEL` as needed. NORTH derives observations and their citations from Sysmon event types. Ollama ranks those observations, and NORTH accepts only selections drawn from the current case. Analysts can open the cited raw events in ECHO. The rule-based report works independently.

The console binds to localhost in the documented setups. The browser and importer establish a loopback session automatically. This protects against requests from other websites and is intended for a single analyst on a trusted PC. See [SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](../THREAT_MODEL.md).

## Test and explain

For a live Windows capture without a Wazuh server, use [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with `tools/sysmon-demo.xml` on a machine where Sysmon is not already configured. Run `tools/Capture-NorthTelemetry.ps1` in PowerShell with access to the Sysmon log. It creates a comment-only file and exports its process and file-creation events to the Git-ignored `raw-logs` folder. Preview the resulting JSON with `python backend/ingest.py <capture.json> --check`, then omit `--check` to import it into a running local backend. This direct capture checks Sysmon and NORTH ingestion. Checking Wazuh forwarding requires a Wazuh deployment.

### Verify Wazuh forwarding

1. Use an authorized, isolated [Wazuh manager on a supported Linux host](https://documentation.wazuh.com/current/installation-guide/wazuh-server/index.html) and [enroll the Windows agent](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html). Keep the manager and agent traffic on the private lab network.
2. Add the block in `tools/wazuh-sysmon-localfile.xml` inside the agent's existing `ossec_config` and restart the agent. Use a fresh run of the capture script after enrollment. [Wazuh event-channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)
3. Find the marker from the fresh capture in the manager's JSON alerts or, with JSON archiving enabled for the test, its JSON archive. Keep only the matching process and file-creation records. Copy the resulting JSON Lines into the Git-ignored `raw-logs` folder and run the NORTH import with `--check`. Expect two supported events and one case. Then import and verify both records in ECHO. [Wazuh event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)

Run `.\.venv\Scripts\python.exe -m pytest tests` from `backend`, and `npm.cmd run build` from `frontend`. For a standard-library-only core check, run `python -m unittest discover -s tests -p test_core.py` from `backend`.

The repository's **Verify NORTH** GitHub Actions workflow runs the backend suite and frontend build. A separate job starts Docker Compose, checks the console and evidence through its HTTP and WebSocket gateway, then restarts with seeding disabled to check PostgreSQL persistence. To run the smoke check against your local Windows demo, use `.\.venv\Scripts\python.exe smoke_demo.py http://127.0.0.1:5173` from `backend` while both servers are running.

1. Ingestion normalizes times to UTC and inserts them transactionally. The database rejects duplicate evidence IDs.
2. IRIS links process creation and a script write by agent and process GUID within a two-minute window. This is a triage signal. Legitimate administration can produce it.
3. A WebSocket sends authoritative case snapshots, including after reconnect. This keeps the small demo simple. For sustained telemetry volumes, the next design step would be incrementally materialized cases and bounded event queries.
4. ATLAS displays observed destination relationships. ECHO sorts by UTC time and stable ID for deterministic playback. The export uses the same observations and evidence IDs.

An interview walkthrough can show all four steps with one case, then explain the trade-offs behind the detection rule, idempotent storage, WebSocket snapshots, and optional AI.

See the [12-week roadmap](../ROADMAP.md) for milestones, acceptance checks, and interview questions.
