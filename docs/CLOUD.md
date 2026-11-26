# Optional cloud workspaces and collectors

## Run a private NORTH Cloud workspace

The Cloudflare Worker serves the browser app and uses D1 for private collector data. The console remains available when collectors are off and displays each collector's last sync time. A single operator can switch between multiple collector feeds. NORTH stores events and investigation reports by collector and adds events in batches of up to 100. A collector records a batch as delivered only after the cloud accepts it. The network view displays the latest snapshot for the selected collector.

From the repository root:

On Windows, after `npx wrangler login`, run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Deploy-NorthCloud.ps1` to create or reuse the database, build the app, and configure the secrets. Run it with `-ShowAccessKey` to display the sign-in key on the same Windows account. The encrypted keys stay under the ignored `.north-launcher` directory. This command does not send local telemetry. The manual equivalents and collector setup follow.

1. Authenticate with `npx wrangler login`, run `npx wrangler d1 create north-cloud`, and copy `cloud/wrangler.example.jsonc` to `cloud/wrangler.jsonc`. Set `database_id` to the ID returned by Wrangler.
2. Run `npx wrangler d1 execute north-cloud --config cloud/wrangler.jsonc --remote --file cloud/schema.sql`, then `npm --prefix frontend run build -- --mode cloud` and `npx wrangler deploy --config cloud/wrangler.jsonc`.
3. Generate three independent random secrets, each at least 32 characters. Run `npx wrangler secret put NORTH_ACCESS_KEY --config cloud/wrangler.jsonc` for the sign-in key, then repeat separately for `NORTH_INGEST_KEY` and `NORTH_SESSION_SECRET`. Keep those values private.
4. To opt in to uploading your actual local telemetry, set `NORTH_CLOUD_URL` and `NORTH_CLOUD_INGEST_KEY` in the terminal used to start NORTH. Set distinct `NORTH_CLOUD_SOURCE` identifiers for collectors that share a workspace, such as `main-pc` and `lab-vm`. Optionally set `NORTH_CLOUD_LABEL` to a friendly name. On Windows, start NORTH in that same terminal with `& '.\Start NORTH.cmd'`. The collector sends batches that include source event fields and network observations to the HTTPS workspace. Leave the cloud variables unset to keep telemetry local.

Use the sign-in key from a phone or computer at the deployed HTTPS URL. The cloud console can manage collector access. Ollama drafting runs with the local backend.

To connect an additional Windows device, open **Collectors**, give the device a name and select **Create pairing**. On the device, install Python 3.11 or later with the Windows launcher and run the displayed command from the NORTH folder. Enter the HTTPS workspace address and the key when prompted. The standalone collector installs its Python dependencies on first launch, stores its key for the current Windows user, and runs without the development servers. Double-click **Start NORTH Collector.cmd** for later sessions. Leave its window open while collecting. Sysmon event collection requires permission to read the existing Sysmon log. Revoke a pairing from **Collectors** to stop future uploads while keeping its existing history.

ECHO surfaces cross-collector observations sharing an address within five minutes of a case's latest event. IRIS can make a brief with citations to that case's events. Deploy with `-EnableCloudAI` to let Workers AI prioritize the brief using generic event descriptions. Hostnames, addresses, raw logs and evidence IDs stay out of the model input. The brief remains available from recorded evidence when the model is off or unavailable. [Workers AI bindings](https://developers.cloudflare.com/workers-ai/configuration/bindings/)

For per-device traffic, the standalone collector supports an OpenWrt router running `nlbwmon`. Use an SSH host alias that already works with key authentication and a verified host key, then run `& '.\Start NORTH Collector.cmd' -OpenWrtHost my-router` on the paired collector. ATLAS displays download and upload totals by device MAC from the router's current accounting period. These counters depend on the router's forwarding and accounting coverage. [OpenWrt traffic accounting documentation](https://github.com/jow-/nlbwmon)

To remember the cloud connection in the Windows launcher, run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Connect-NorthCloud.ps1 -Enable -Url https://YOUR-WORKSPACE.workers.dev`, then restart with **Start NORTH.cmd**. This opts the PC into sending its collected events, investigations, and network observations to that private workspace. To stop future syncs, run the same tool with `-Disable` and restart NORTH. Disconnecting the collector does not delete data already stored in Cloudflare.

### Windows desktop client

[NORTH privacy policy](../PRIVACY.md)

The Windows x64 client opens directly on **This computer**. It displays local network interfaces, nearby devices from the Windows neighbor cache, and up to 200 recent Sysmon events if the account can read that log. It can link a PowerShell process to a script file creation for an evidence timeline. Local data is read on demand and stays on the computer. A browser, Python, server address and key are unnecessary for local use.

Use **Workspace → Open cloud workspace** to open a saved or build-time workspace, or **Connect to a different workspace** to enter another HTTPS address. Cloud sign-in and collector pairing apply to that private workspace. The desktop cloud session lasts until the app closes or the cloud session expires.

To build the portable client from the repository root, run `npm.cmd --prefix frontend ci`, `npm.cmd --prefix desktop ci`, and `npm.cmd --prefix desktop run package:windows`. The portable file is `desktop/dist/NORTH-Desktop-Windows-x64.exe`. Set `NORTH_DESKTOP_DEFAULT_URL` at build time to provide an optional cloud workspace.

Run `npm.cmd --prefix desktop run package:installer` to build `desktop/dist/NORTH-Setup-Windows-x64.exe`. The manual **Build NORTH for Windows** GitHub workflow packages both Windows builds. Code signing requires a publisher certificate.
