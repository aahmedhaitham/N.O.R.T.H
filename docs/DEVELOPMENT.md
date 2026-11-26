# Development and synthetic demo

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

**Overview** is the home screen for activity charts, event counts, recent cases, and collector health. Use **ATLAS** for devices and observed connections, **IRIS** to search the event feed, and **ECHO** to replay investigations. A supported browser can install NORTH as a standalone app. Look for **Install NORTH** or your browser's install option. An installed local instance still connects to the NORTH servers on that device. Other devices need a reachable HTTPS deployment.

With Docker and Compose available, run `docker compose up --build` at the repository root and open [the Docker console](http://127.0.0.1:8080). Compose uses PostgreSQL and keeps the database on a named volume.

## Run on Kali or another Linux distribution

Use the Docker Compose command above, or run the same two services natively with Python 3.14 and Node 26. From `backend`, use `python3 -m venv .venv`, `.venv/bin/python -m pip install -r requirements-dev.txt`, then `.venv/bin/python -m uvicorn main:app`. In a second terminal from `frontend`, use `npm ci` and `npm run dev`.

To try a Linux case with the backend running, run `python ingest.py fixtures/linux-ssh-demo.jsonl --format journal` from `backend` on Windows, or use `python3` on Kali. The fixture contains three synthetic OpenSSH failures and requires no SSH service.

For a real Kali journal sample without starting SSH, run `sudo /usr/bin/true`, then `sudo journalctl _COMM=sudo --since '2 minutes ago' --no-pager -o json --grep 'COMMAND=/usr/bin/true$' > kali-journal.jsonl`. Transfer that local file to the Git-ignored `raw-logs` directory, preview with `python backend/ingest.py raw-logs/kali-journal.jsonl --format journal --check`, and omit `--check` to import. This produces an observed sudo command case from the actual journal.

## Deploy the public portfolio demo

Create a [Render Blueprint](https://render.com/docs/infrastructure-as-code) connected to this repository. The included `render.yaml` deploys a single Docker web service. It serves the React console and the FastAPI routes from the same HTTPS origin, including the live WebSocket, timeline replay and report export. Visitors can investigate the bundled synthetic Windows and Kali cases without an account. Ingestion and live model calls are disabled on the public instance. The demo uses an ephemeral SQLite database seeded at startup. The PostgreSQL configuration remains available through Docker Compose.

After deployment, run the smoke check against the assigned URL with `python backend/smoke_demo.py https://YOUR-SERVICE.onrender.com --read-only` from a Python environment with the backend requirements installed.

For a static portfolio build, run `npm run build -- --mode portfolio` from `frontend`, then run `python backend/export_portfolio.py frontend/dist/demo` from the repository root using the backend environment. Upload the contents of `frontend/dist` to a static host such as [Cloudflare Pages](https://developers.cloudflare.com/pages/get-started/direct-upload/). This version replays the two bundled synthetic cases in the browser and provides their reports as downloads. It does not connect to the local NORTH database.

See [Architecture](ARCHITECTURE.md) for the data flow and supported deployment modes.
