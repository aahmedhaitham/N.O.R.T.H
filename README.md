# NORTH

**Network Operations, Reconnaissance, Threat Hunting**

NORTH is a local investigation console. Its bundled, synthetic Windows incident follows three Sysmon events from a process start to an evidence-backed report.

- **IRIS** correlates alerts and drafts evidence-linked investigations for analyst review.
- **ATLAS** maps affected assets and their observed relationships.
- **ECHO** reconstructs and replays the incident timeline.

## Run the demo on Windows

From the repository root, use two PowerShell terminals. The native setup uses SQLite and works without Docker or Ollama.

Terminal 1:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn main:app
```

Terminal 2:

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run dev
```

Open [the console](http://127.0.0.1:5173). Select the PowerShell case, inspect the ATLAS evidence link, replay the timeline in ECHO, and export the report. Open **Raw evidence** to see the original sanitized event.

With Docker and Compose available, run `docker compose up --build` at the repository root and open [the Docker console](http://127.0.0.1:8080). Compose uses PostgreSQL and keeps the database on a named volume.

## Add lab data or use local AI

- **Wazuh and Sysmon.** Import a sanitized JSON array or JSON Lines export from an authorized, isolated lab with `python backend/ingest.py path/to/alerts.json`. The importer expects Wazuh Windows event alerts for Sysmon IDs 1, 3, and 11. For Docker, add `--base-url http://127.0.0.1:8080`. Set `NORTH_SEED_DEMO=0` before booting with a fresh database to start without the bundled case.
- **Ollama.** With a local server running and `qwen2.5-coder:7b` available, click **Generate draft** in IRIS. Override the server or model with `OLLAMA_URL` or `OLLAMA_MODEL` as needed. NORTH derives observations and their citations from Sysmon event types. Ollama ranks those observations, and NORTH accepts only selections drawn from the current case. Analysts can open the cited raw events in ECHO. The rule-based report works independently.

The console binds to localhost in the documented setups. Its API has no user authentication and is intended for a single analyst in a local lab.

## Test and explain

Run `.\.venv\Scripts\python.exe -m pytest tests` from `backend`, and `npm.cmd run build` from `frontend`. For a standard-library-only core check, run `python -m unittest discover -s tests -p test_core.py` from `backend`.

1. Ingestion normalizes times to UTC and inserts them transactionally. The database rejects duplicate evidence IDs.
2. IRIS links process creation and a script write by agent and process GUID within a two-minute window. This is a triage signal. Legitimate administration can produce it.
3. A WebSocket sends authoritative case snapshots, including after reconnect. This keeps the small demo simple. For sustained telemetry volumes, the next design step would be incrementally materialized cases and bounded event queries.
4. ATLAS displays observed destination relationships. ECHO sorts by UTC time and stable ID for deterministic playback. The export uses the same observations and evidence IDs.

An interview walkthrough can show all four steps with one case, then explain the trade-offs behind the detection rule, idempotent storage, WebSocket snapshots, and optional AI.

See the [12-week roadmap](ROADMAP.md) for milestones, acceptance checks, and interview questions.
