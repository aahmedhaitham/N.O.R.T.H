# NORTH

**Network Operations, Reconnaissance, Threat Hunting**

NORTH is a local investigation console. Its bundled, synthetic Windows incident follows three Sysmon events from a process start to an evidence-backed report.

- **IRIS** correlates alerts and drafts evidence-linked investigations for analyst review.
- **ATLAS** maps affected assets and their observed relationships.
- **ECHO** reconstructs and replays the incident timeline.

## Run the demo on Windows

After installing the dependencies below once, double-click **Start NORTH.cmd** in the repository folder to start the backend and frontend. Double-click it again to restart both. If they were started manually, stop those tabs with **Ctrl+C** the first time. Open or refresh [the console](http://127.0.0.1:5173/). To stop servers started by the launcher, run `& '.\Start NORTH.cmd' -Stop` from PowerShell in the repository folder.

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

## Run on Kali or another Linux distribution

Use the Docker Compose command above, or run the same two services natively with Python 3.14 and Node 26. From `backend`, use `python3 -m venv .venv`, `.venv/bin/python -m pip install -r requirements-dev.txt`, then `.venv/bin/python -m uvicorn main:app`. In a second terminal from `frontend`, use `npm ci` and `npm run dev`.

To try a Linux case with the backend running, run `python ingest.py fixtures/linux-ssh-demo.jsonl --format journal` from `backend` on Windows, or use `python3` on Kali. The fixture contains three synthetic OpenSSH failures and requires no SSH service.

## Deploy the public portfolio demo

Create a [Render Blueprint](https://render.com/docs/infrastructure-as-code) connected to this repository. The included `render.yaml` deploys a single Docker web service. It serves the React console and the FastAPI routes from the same HTTPS origin, including the live WebSocket, timeline replay and report export. Visitors can investigate the bundled synthetic Windows and Kali cases without an account. Ingestion and live model calls are disabled on the public instance. The demo uses an ephemeral SQLite database seeded at startup. The PostgreSQL configuration remains available through Docker Compose.

After deployment, run the smoke check against the assigned URL with `python backend/smoke_demo.py https://YOUR-SERVICE.onrender.com --read-only` from a Python environment with the backend requirements installed.

For a static portfolio build, run `npm run build -- --mode portfolio` from `frontend`, then run `python backend/export_portfolio.py frontend/dist/demo` from the repository root using the backend environment. Upload the contents of `frontend/dist` to a static host such as [Cloudflare Pages](https://developers.cloudflare.com/pages/get-started/direct-upload/). This version replays the two bundled synthetic cases in the browser and provides their reports as downloads. It does not connect to the local NORTH database.

## Add lab data or use local AI

- **Wazuh and Sysmon.** Preview a sanitized export from an authorized, isolated lab with `python backend/ingest.py path/to/alerts.json --check`. NORTH accepts a JSON array, JSON Lines, or indexer search hits containing `_source`. It selects Sysmon event IDs 1, 3, and 11 and reports how many cases the export can reconstruct. Omit `--check` to import into a running local backend. For Docker, add `--base-url http://127.0.0.1:8080`. Start with a fresh database and set `NORTH_SEED_DEMO=0` to evaluate lab events independently of the bundled case. Wazuh alerts can omit telemetry below the alert threshold, so consult the [Wazuh alert documentation](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html) if expected events are missing.
- **Linux OpenSSH.** If OpenSSH already writes to your Linux journal, export your own service's existing records with `journalctl -u ssh.service -u sshd.service --since today --no-pager -o json > ssh-journal.jsonl`. Preview with `python3 backend/ingest.py ssh-journal.jsonl --format journal --check`. Omit `--check` to import to your local NORTH instance. IRIS flags groups of three failures from the same source on the same host within five minutes, ATLAS maps the inbound address, and ECHO lists the original events. Keep real exports local.
- **Ollama.** With a local server running and `qwen2.5-coder:7b` available, click **Generate draft** in IRIS. Override the server or model with `OLLAMA_URL` or `OLLAMA_MODEL` as needed. NORTH derives observations and their citations from Sysmon event types. Ollama ranks those observations, and NORTH accepts only selections drawn from the current case. Analysts can open the cited raw events in ECHO. The rule-based report works independently.

The console binds to localhost in the documented setups. Its API has no user authentication and is intended for a single analyst in a local lab.

### Local model benchmark

With Ollama running, execute `.\.venv\Scripts\python.exe compare_models.py` from `backend`. The script calls the NORTH draft endpoint in-process against the bundled case and a version with the network event removed.

On the development laptop, `qwen2.5-coder:7b` returned six valid drafts out of six, ranked file creation first in all six, and took a median of **0.61 seconds** after warm-up. The reported `huihui_ai/qwen3-abliterated:8b-v2` run was partial. Its warm-up and first two timed runs returned HTTP 502 because the endpoint could not verify the model selection. The two timed attempts took **6.20 seconds** and **6.57 seconds**. These observations support keeping Qwen2.5-Coder as the default for the current IRIS configuration.

## Test and explain

For a live Windows capture without a Wazuh server, use [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with `tools/sysmon-demo.xml` on a machine where Sysmon is not already configured. Run `tools/Capture-NorthTelemetry.ps1` in PowerShell with access to the Sysmon log. It creates a comment-only file and exports its process and file-creation events to the Git-ignored `raw-logs` folder. Preview the resulting JSON with `python backend/ingest.py <capture.json> --check`, then omit `--check` to import it into a running local backend. This direct capture checks Sysmon and NORTH ingestion. Checking Wazuh forwarding requires a Wazuh deployment.

Run `.\.venv\Scripts\python.exe -m pytest tests` from `backend`, and `npm.cmd run build` from `frontend`. For a standard-library-only core check, run `python -m unittest discover -s tests -p test_core.py` from `backend`.

The repository's **Verify NORTH** GitHub Actions workflow runs the backend suite and frontend build. A separate job starts Docker Compose, checks the console and evidence through its HTTP and WebSocket gateway, then restarts with seeding disabled to check PostgreSQL persistence. To run the smoke check against your local Windows demo, use `.\.venv\Scripts\python.exe smoke_demo.py http://127.0.0.1:5173` from `backend` while both servers are running.

1. Ingestion normalizes times to UTC and inserts them transactionally. The database rejects duplicate evidence IDs.
2. IRIS links process creation and a script write by agent and process GUID within a two-minute window. This is a triage signal. Legitimate administration can produce it.
3. A WebSocket sends authoritative case snapshots, including after reconnect. This keeps the small demo simple. For sustained telemetry volumes, the next design step would be incrementally materialized cases and bounded event queries.
4. ATLAS displays observed destination relationships. ECHO sorts by UTC time and stable ID for deterministic playback. The export uses the same observations and evidence IDs.

An interview walkthrough can show all four steps with one case, then explain the trade-offs behind the detection rule, idempotent storage, WebSocket snapshots, and optional AI.

See the [12-week roadmap](ROADMAP.md) for milestones, acceptance checks, and interview questions.
