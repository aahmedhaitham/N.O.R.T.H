# NORTH product progress

## Direction

The public product is cloud-first. Users open the hosted app or an installed client configured for the same service. AI runs in the hosted workspace. A machine or router can opt in to sending its observations with a separate collector.

## M0 repository audit

- The Electron client bundles React, TypeScript and React Flow. Its existing local Windows mode reads network and Sysmon data using PowerShell.
- The standalone Python collector stores events in SQLite and can sync to the Cloudflare Worker. The FastAPI deployment also supports PostgreSQL.
- The Worker and D1 already support remote collectors, events, investigations, network views and case briefs. The Worker can rank case findings with Workers AI and otherwise returns a deterministic brief.
- The current Worker is a single workspace. Its shared access key and source IDs do not provide an account model or isolation between customers. The workspace cannot serve as the public shared backend in this form.
- The signed public Windows installer is pending. The current GitHub release and existing workspace are independent of the hosted edition work.

## M1 hosted client startup

- Added a cloud-only build configuration. The desktop client opens a fixed HTTPS origin configured at build time and does not register the local network API or expose workspace switching in this mode.
- The existing Windows build configuration remains available. The adapter-counter work in progress is separate from the hosted startup change.
- The hosted production address and deployment are pending until account and workspace isolation are ready.
- Verified with `npm.cmd --prefix desktop test` (7 passed), `node --check desktop/main.cjs`, and `npm.cmd --prefix desktop run build:ui`. No hosted installer or production service was deployed.

## Implementation order

### Local-first product brief · Phase 3 visibility, findings and detections

- Overview's **Needs attention** lists local unreviewed findings with severity, status, ATT&CK techniques, and their evidence. Mark a finding reviewed or benign to move it into recent history, or reopen it. History and review state stay in the private database. The list shows unreviewed findings first and supports paging.
- **What NORTH can see** summarizes ATT&CK coverage. The local **Detections** page adds a filterable coverage matrix, source checks with remediation guidance, persistent rule toggles, previews against the latest 100 stored events, and bounded custom YAML imports. Imported rules start disabled. Previewing a rule does not create findings.
- **ECHO** shows observed process GUID relationships beside the evidence timeline. Selecting a process opens its source event. Missing or inconsistent parents are labeled, and large trees render in batches of 50 with a 500-process cap per case.
- Verified with 109 backend tests and 2 subtests, 17 desktop tests, 3 cloud tests, the desktop UI build, and a Windows source collector smoke check for listing rules and persisting a toggle. Coverage depends on collector access and observations. The installed Windows build and live privileged sources remain unverified.

### Local-first product brief · Phase 2 engine and rules

- NORTH ships 41 ATT&CK-tagged YAML rules with synthetic positive and negative fixtures for each rule. The catalog includes registry, process, authentication and DNS interval observations. Tags identify the technique a signal can help investigate.
- The optional Windows collector retains 96 passive TCP snapshots in local SQLite, exposes the latest 12 through the authenticated local API, and feeds first-seen listeners to the local baseline. The neighbor watcher stores evidence for newly observed LAN devices after its initial baseline.
- The outbound destination baseline flags an uncommon process-to-IP pair once when it returns after learning, provided that pair represented at most 5% of the recorded outbound observations during learning. The minimum evidence is 20 observations for the host. Existing installations whose learning window had already closed have no historical frequency sample. First-seen destinations have a separate finding.
- Backend suite passed 107 tests and 2 subtests. Desktop passed 15 tests and the bundled UI built. Three cloud tests, the standalone collector self-test, and both collector ZIP content checks passed.
- The Windows desktop app's **This computer → Overview → What changed** now shows local findings with expandable summaries and evidence. **Start monitoring** launches the bundled collector with a private SQLite database and no cloud session. The panel checks for new results every five seconds. Monitoring stops when the app exits and can be started again on the next launch.
- Verified 108 backend tests and 2 subtests, 16 desktop tests, the desktop UI build, and source collector startup and shutdown on Windows. The live TCP reader still reported access denied in this session. The installed build's full collection flow remains unverified.

- ATLAS now retains first and last observation times for local TCP listeners. The first complete, nonempty listener sample establishes the baseline. The view shows up to 12 recent new address/port pairs. Truncated samples do not update history. History stays in the desktop app data directory and is separate from the rules engine.
- `npm --prefix desktop test` passed 15 tests, including restart, repeated observations, and truncated samples. `npm --prefix desktop run build:ui` passed with the existing bundle-size warning. A successful live Windows sample and packaged app run remain unverified.

- Added desktop local-mode **ATLAS → Traffic → Live TCP on this PC**. It passively samples the Windows TCP table while visible, separates connections and listeners, and shows PID plus process name when timestamps support attribution. Snapshots are capped, kept in memory, and excluded from cloud synchronization. They are not yet retained as historical evidence or used for listening-port baselines.
- `npm --prefix desktop test` passed 14 tests and `npm --prefix desktop run build:ui` passed. A controlled mock of the PowerShell providers passed the listening/connection and PID-reuse checks. The live Windows provider returned access denied in this session, and the reader reported that state. Packaged UI and a successful live sample remain unverified.

- Added local SQLite baselines per host and signal for first-seen full process paths and outbound process-to-IP pairs. The default learning period is 24 hours. Set `NORTH_BASELINE_LEARNING_HOURS` to 1–720 before a host/signal first learns. Repeat and imported pre-baseline observations do not create findings. New observations are informational, cite evidence, and are not counted as ATT&CK rules.
- Extended optional local Sysmon collection to retain full-path process creation and outbound-connection fields. Baseline state, evidence and findings remain local. Added authenticated `GET /api/local/baselines` for learning and ready states.
- From backend, `python -m pytest -q -o faulthandler_timeout=15 tests` passed 71 tests and 2 subtests. The synthetic baseline test covered learning, restart, case normalization, per-host isolation, pre-baseline imports, inbound exclusion, and cloud exclusion. The PowerShell parser, source collector self-test and desktop UI build passed. Live permissions and packaged behavior were not verified.

- SQLite ingestion queues new records in the same transaction as the evidence write. The local FastAPI service and standalone collector consume the queue automatically. Findings and queue completion commit together, so a failed write leaves the records queued for retry. The worker preserves existing review status and does not queue startup demo fixtures.
- Automatic batches process up to 100 queued records and use up to 500 additional records as correlation context. Older stored records are available to manual scans and as context but are not automatically backfilled. The worker logs context caps and rule timeouts. Rich events, queue state and findings remain local.
- From backend, `python -m pytest -q -o faulthandler_timeout=15 tests` passed 70 tests and 2 subtests. Tests cover startup consumption, restart, prior context, duplicate ingestion, review preservation and transactional rollback. `python backend/run_collector.py --self-test` and `npm --prefix desktop run build:ui` passed from source.

- Local SQLite now stores evidence-linked findings. Re-evaluating the same evidence keeps the finding ID and review status. The authenticated loopback API evaluates, lists and reviews findings and can retrieve their exact evidence. The standalone collector can evaluate the local database with `--evaluate-findings`. Both paths are explicit scans of up to 100 recent events. The desktop UI does not surface them yet.
- `python -m pytest -q -o faulthandler_timeout=15 tests` passed 67 tests and 2 subtests, including review persistence and exclusion from cloud snapshots. From source, `python run_collector.py --evaluate-findings` returned two findings from six synthetic events. The collector self-test and desktop UI build passed. The packaged executable remains unverified.

- Added a local, named-selection Sigma subset with bounded YAML parsing, field aliases and modifiers, Boolean conditions, and explicitly reported regex timeouts. Five starter rules have positive and negative synthetic fixtures. The authenticated local API evaluates up to 100 recent events and returns their stored evidence IDs.
- PyYAML parses YAML without object constructors and with alias, nesting and size limits. The regex package supplies match timeouts. Added both modules and the bundled catalog to Docker and both collector ZIPs.
- In backend, `python -m pytest -q -o faulthandler_timeout=15 tests` passed 59 tests and 2 subtests. Desktop tests passed 12, desktop UI built with the existing size warning, both collector ZIPs included the rule files, and `python backend/run_collector.py --self-test` passed from source. Packaged runtime was not tested.
- Extracted reusable sequence-window and threshold grouping from the existing PowerShell and SSH cases. The original cases and evidence references remain compatible. Exact-boundary, just-outside-window and group-isolation tests passed. The full backend rerun passed 62 tests and 2 subtests.
- Added YAML-driven threshold and sequence rules for repeated SSH failures and PowerShell script creation. PowerShell includes related network events as context. The seven bundled rules all have positive and negative fixtures. The compatibility check matches both legacy cases' ordered evidence IDs.
- `python -m pytest -q -o faulthandler_timeout=15 tests` passed 66 tests and 2 subtests. `npm --prefix desktop run build:ui` passed with the existing bundle-size warning and the source collector self-test passed.

- Added opt-in Windows event collection for extended Sysmon, Security, System, PowerShell and Defender channels. Readers use fixed channel/event allowlists, bounded fields, per-channel cursors, and source-specific health messages. PowerShell script block metadata is collected without the script body.
- Rich records go into a separate SQLite table and are readable only through the authenticated local API. The regression test confirms that the new record ID and a synthetic command line never appear in a cloud snapshot. Collection is off by default, enabled by `NORTH_WINDOWS_LOCAL_EVENTS=1` in the Windows backend or standalone collector.
- `python -m pytest -q -o faulthandler_timeout=15 tests` passed 40 tests and 2 subtests after loopback access was available. `npm --prefix desktop test` passed 12, cloud/GeoIP passed 3, and `npm --prefix desktop run build:ui` passed with the existing bundle-size warning. The PowerShell reader parsed, the Windows and Linux ZIP checks passed, and `python backend/run_collector.py --self-test` passed from source.
- Live event-channel permissions and packaged Windows ingestion remain unverified. Live TCP sampling, desktop surfacing, and the Sigma rules and fixtures are still open.

- Added the local rule-engine event projection in `backend/event_contract.py`. It reads existing stored evidence and reuses its ID and UTC timestamp. It exposes bounded process, user, network, file, registry and DNS fields when the original event contains them. The projected `raw` field contains only channel and event type. Stored and uploaded evidence formats remain compatible.
- The existing Windows correlation now uses the projected process name. Both Docker build definitions and the Windows and Linux collector bundles include the projection.
- In backend, `.venv/Scripts/python.exe -m pytest -q tests` passed 38 tests and 2 subtests. `npm --prefix desktop run build:ui` passed with the existing bundle-size warning. Built both collector ZIPs and checked for `backend/event_contract.py` in each.
- Phase 2 remains open. Next is the bounded Sigma loader and tested catalog. Service installation event 7045 uses the System log. Custom rule regexes require bounded execution.

### Local-first product brief · Phases 0 and 1

- **Phase 0 audit.** The standalone collector uses SQLite and can sync a bounded snapshot. FastAPI reads normalized events and derives cases for HTTP and WebSockets. Electron local mode runs fixed PowerShell readers and applies its own recent-event correlation. Move shared rules into the bundled collector over a backward-compatible event contract. The repository does not contain an MIT license file.
- **Phase 1 local boundary.** Added one random signed, HttpOnly session cookie per loopback client, Host validation, exact-origin and Fetch Metadata checks, and denied cross-origin reads, writes, and WebSockets. Updated the UI, import tool and smoke runner. A local program can still initiate its own session, so this is a browser boundary rather than Windows user authentication.
- **Desktop boundary.** Zod validates the sole preload IPC input, alongside exact sender frame checks. The Electron CSP now starts from default deny. Inline styles are allowed for visualizations. The existing Windows tools run fixed scripts with `-File` and argument arrays.
- **History and hygiene.** `gitleaks git --log-opts=--all --redact=100 --no-banner .` scanned 123 commits and reported no leaks. Tracked telemetry candidates are `backend/fixtures/demo.json`, `backend/fixtures/linux-ssh-demo.jsonl`, and the inline records in backend, cloud, and desktop tests. Keep those synthetic. Added ignore patterns for captures, export files, and key material. Added SECURITY.md, THREAT_MODEL.md, and THIRD_PARTY_NOTICES.md.
- **Verification.** In backend, `.venv/Scripts/python.exe -m pytest -q tests` passed 36 tests and 2 subtests. `npm --prefix desktop test` passed 12. `node --test cloud/worker.test.mjs cloud/geoip.test.mjs` passed 3. Frontend `npm --prefix frontend run build` and desktop UI `npm --prefix desktop run build:ui` passed with the previously seen size warning. `python backend/smoke_demo.py http://127.0.0.1:8194` passed HTTP, WebSocket reconnect, report, and import retry checks against a disposable local database.
- A new installer launch and Docker run were not verified in this phase. Later phases start with the backward-compatible event contract, source coverage and rule engine. The offline assistant and Simple mode remain unimplemented.

### Interface Task 6 · Remote endpoint map

- Added a separate ATLAS Remote endpoints view using embedded Natural Earth country shapes and November 2026 DB-IP Lite data. Windows and the Cloud Worker resolve country codes offline. Browser trace lookups use the bundled database in the browser, and loaded traces stay local.
- Country arcs use a user-selected origin. Packet mapping uses the machine's interface addresses or a source IP selected for the trace. Private and documentation IPs are omitted. The empty state links to connection collection diagnostics.
- Verified the map and IRIS chart drill-down in a browser with synthetic telemetry. GeoIP tests cover public IPv4 and IPv6 and private/documentation exclusions. The Cloudflare staging dry run accepted the assets. Live staging and the packaged Windows UI remain to be verified.

### Interface Task 5 · Charts

- Added five charts in What changed using the existing Motion/CSS approach. The time brush, ranked rows, severity segments and legend, and heatmap open matching events from a sample of up to 100 records in IRIS.
- Frontend production build and 11 desktop tests passed.

### Interface Task 4 · Overview

- Rebuilt Overview as three panels. Open investigations and unreviewed device findings appear first, and source rows link to the relevant ATLAS diagnostics or collector setup.
- The cloud case list includes review status. Overview labels severity by recorded evidence, and the workspace timezone preference controls absolute timestamp detail.
- Frontend production build and both cloud tests passed.

### Interface Task 3 · Motion

- Added Motion transitions, animated counts and chart bars, static loading placeholders, visible pressed states, and a reduced-motion path. Page transitions take 140 ms.
- Frontend production build and 11 desktop tests passed.

### Interface Task 2 · Design tokens

- Centralized theme, spacing, type, borders, severity, and monospace tokens in `frontend/src/tokens.css`. The shell uses the shared type and border values, and Overview removes decorative borders from panels inside its existing dashboard container.
- Frontend production build and 11 desktop tests passed.

### Interface Task 1 · Top bar and menus

- Replaced the stacked app headers with a 44 px toolbar and a 56 px icon rail. The rail has tooltips, an investigation-count badge, and a sliding indicator that respects reduced motion.
- Added a searchable collector picker with platform icons, relative sync times, and a Show inactive filter. The centered Ctrl+K control opens the command palette. The avatar menu groups Settings, Collectors, Appearance, and Sign out.
- Replaced authored native selects with Radix controls and verified that ATLAS tabs fit at desktop and 375 px widths. Browser checks confirmed Ctrl+K navigation, keyboard event-type selection, and keyboard access to Appearance.
- Frontend and desktop UI builds passed. Tests passed for the desktop (11), cloud (2), and backend (35 plus 2 subtests). The build flags bundle size, and npm audit flags the existing Vite development dependency. The signed-in picker and redesigned live capture still need a packaged Windows run.

### Windows v1 release verification

- The user confirmed the staging deployment passed after refreshing Wrangler sign-in.
- For commit `e704bea`, GitHub passed Windows packaging, install, standalone collector and dashboard launch checks. The user paired a Windows collector from the installed app, and staging received its first snapshot three seconds after startup.
- The user verified live Wi-Fi capture in the installed build with 268 packets. The redesigned Packet traces view now detects adapters automatically and offers quick recordings with in-app progress and a live mode with Pause and Resume. The new capture controls were tested at the desktop API level with simulated inputs.
- The Ubuntu runner built the Linux collector download and verified its first authenticated snapshot to a temporary HTTPS receiver in the same run as the backend, frontend, PostgreSQL and public image checks.
- Trusted Windows signing and public publishing remain pending. The public releases repository currently exposes a prerelease, and the credentials needed for a new upload were unavailable to this session.

### ATLAS network monitoring roadmap

- Windows capture supports the Npcap loopback adapter and reports driver permission denials distinctly. Synthetic loopback and VLAN parser checks pass. Live capture verification is blocked by the current driver's administrator-only policy.
- Windows collector details detect a different bundled build and can update a managed collector in place. Updates stage code first and preserve the pairing, local database, and startup settings.
- The Windows app shows the local collector task’s status and last start in its details, and can restart it using the existing encrypted pairing.
- Windows desktop can create a pairing and connect the current PC as a single guided action. The key stays in the desktop bridge, and the app shows first-sync progress. Pairing other devices remains available.
- Windows installer builds compile a standalone collector, bundle it with the app, and smoke-test the runtime before packaging and after installation. Guided setup uses the bundled executable when present and falls back to the Python launcher in development builds.
- NORTH for Windows can guide collector pairing and manage background startup from the app. The installer bundles the collector scripts, uses an existing Python 3.11+ installation, and sends the key to the launcher through standard input.
- Overview lists the workspace collector fleet, including pending pairings, known platforms, last syncs, and direct collector switching.
- NORTH offers a Linux collector bundle. It reads existing neighbor observations and collects recent supported OpenSSH and sudo journal events accessible to the signed-in Linux user, with a Diagnostics status in ATLAS.
- The Windows collector bundle can opt into a per-user Windows sign-in task. Existing pairing stays in the collector folder, and users can check or disable automatic startup.
- ATLAS checks automatically while visible and shows the collector's actual cloud sync time. Overview, IRIS newest events, and ECHO refresh when their window regains focus. Collector sampling continues independently while the collector runs.
- Completed router intervals persist across collector restarts. The first successful reading after a restart or missed sample establishes a new baseline. Windows adapter views show up to 12 recent measured rates per adapter.
- The collector retains its last 72 internet checks across restarts, scoped to the collector and cloud origin. Diagnostics includes selectable history and a response-time chart.
- Device coverage filters the observed map and inventory. The filtered inventory can be exported to CSV with unmeasured fields left blank.
- Collector diagnostics check a dedicated HTTPS health endpoint without credentials and distinguish a cloud response, rejected requests, TLS failures, and timeouts. The dashboard marks old samples, and the staging deploy checks the health endpoint.
- The trace viewer reads Ethernet, raw IP, and both Linux cooked headers in PCAP and PCAPNG. It supports TCP/UDP port filtering and displays IPv6 addresses in compressed form.
- Signed-in workspaces can name observed devices by MAC per collector. Labels are saved in the workspace and are shared across sessions, with their source shown in the inspector.
- Router exports can label observed devices by an unambiguous MAC match. Imported names remain in the current window and can be cleared. Device coverage counts names, router-confirmed Wi-Fi, and router byte totals separately.
- Device inventory imports accept comma-, semicolon-, and tab-separated router exports in addition to JSON. Imports remain in the current window.
- The device inventory shows name provenance, observed IPs, MAC, interface, and router usage in one table. Usage is shown only when the configured router reports counters for the observed MAC.
- Router traffic lists active OpenWrt DHCP IPs next to MAC, Wi-Fi association, and byte totals. Collector-observed addresses are labeled when used as a fallback.
- Router integrations should report device inventory, Wi-Fi association, and measured counters as separate capabilities. Huawei documents DN8245V diagnostics through its operator platform; automatic local integration for the DN8245V-56 remains unverified.
- Windows adapter byte totals and sampled receive/send rates now appear in ATLAS Traffic for both paired collectors and the desktop local workspace. This measures interfaces and is shown separately from Sysmon process connections and router totals.
- Windows desktop ATLAS can list local capture adapters and start a short capture after native confirmation. Dumpcap streams the bounded trace directly to the inspector without saving or uploading it. Driver and installed-app verification are pending.
- The collector bundle includes a manually started, bounded Ethernet capture command for an existing Dumpcap installation. Capture files stay local. The trace viewer charts filtered traffic and can clear the loaded capture from the window.
- ATLAS separates Devices, Traffic, Diagnostics, and Packet traces into focused views. Router usage intervals have a per-device chart, and the app connections table links directly to an IRIS process search.
- Local packet analysis includes IP and protocol filters, visible TCP and UDP ports where available, and selectable address pairs ranked by original packet bytes. Internet health shows the latest gateway, DNS, and HTTPS results above recent history. Router traffic can be filtered to devices observed on Wi-Fi.
The first batch adds collector gateway, DNS, and HTTPS checks with 12 recent samples, Windows Sysmon app connection counts, OpenWrt DHCP names and positive Wi-Fi associations for devices with traffic counters, and 12 recent router byte-counter intervals. ATLAS can inspect classic Ethernet PCAP headers and enhanced Ethernet packet blocks in PCAPNG locally. In-app capture controls, live capture verification, per-app byte measurements, additional router integrations, and live deployment checks remain open.

- Add internet health checks from the enrolled collector, including gateway reachability, DNS resolution, HTTPS connectivity, latency, and check history.
- Improve device identity with source-labeled collector names and supported router client records. Display Wi-Fi association when the router or access point reports it.
- Expand router and gateway integrations for per-device byte totals and time-series usage. Keep router traffic and collector-local traffic distinct.
- Add per-app connections and usage for enrolled endpoints where the operating system reports process-level traffic. Router telemetry alone cannot associate another device's traffic with a process.
- Add opt-in packet capture and trace inspection on authorized interfaces, with visible capture scope, size limits, and local handling of packet payloads.

### UX backlog

- Collector details can replace a lost pairing key after confirmation. The source ID and history stay with the collector, and the old key stops authorizing uploads.
- Existing collector rows open inline details with the source ID and a copyable restart command. Synced, active collectors can be selected directly from their details.
- Overview attention items jump directly to the relevant ATLAS device review or collection status section.
- ATLAS ranks router traffic by device and shows download, upload, and combined totals. A collector-reported name appears when observations for that MAC agree.
- ATLAS can open a prefiltered IRIS search from a reporting host, observed connection, or device inspector IP address.
- ECHO filters its investigation list by title or host while keeping the open evidence in view.
- IRIS can move one page at a time through older or newer results while keeping applied filters. Failed page loads can be retried in place.
- ECHO citations and connection links jump to the referenced event, pause replay, and expand raw evidence. Direct evidence fragments open their case when it is available in the selected collector.
- The ATLAS inspector explains address scope and collector-reported names alongside the selected device. MAC address explanations distinguish locally assigned and group addresses.
- Collectors and Settings open inside the console, preserving the sidebar, appearance controls, and the previous page state when the collector remains the same.
- Collector management shows pairing status and last sync separately in a compact table. Temporary status failures keep the previous list visible and clear on recovery.
- Temporary cloud status errors keep the signed-in workspace open and show a retry message. A confirmed expired session still returns to sign-in.
- ECHO has a compact investigation list and a timeline-first evidence view. Connection graphs appear when the case contains connection records.
- IRIS uses a split event list and evidence inspector, with related-event actions beside the selected record.
- ATLAS uses a compact command bar and a shared map and device inspector. The portfolio preview includes labeled synthetic neighbor and router traffic records so the map can be explored immediately.
- Reworked Overview into a flat console with a larger telemetry plot, a side pane for event types and attention items, and a full-width investigation table.
- Kept the navigation and toolbars in place on wide layouts while the workspace scrolls independently. Consolidated Overview metrics into one compact strip, prioritized activity charts, and added a recent investigations table.
- Added system, light, and dark appearance settings, a centered NORTH title, a translucent sidebar, and a native desktop View menu for zoom and fullscreen.
- ECHO case cards show evidence counts. Timeline playback includes previous and next event controls and an accessible event position.
- IRIS previews observed values in collapsed event rows, displays the number of results on the current page, and lets users remove applied filters individually.
- ATLAS device details show separate router download and upload totals with relative bars and readable units. Missing or stale router data is labeled.
- Added a searchable page switcher with Ctrl+K or Command+K for Overview, ATLAS, IRIS, and ECHO.
- Polished workspace navigation, responsive Overview cards, and the ATLAS and IRIS page headings. Added reduced-motion-aware transitions, a simpler Google sign-in screen, and ECHO replay speed controls. Cloud and standard frontend builds pass. Visual review is queued for the combined staging pass.
- Refresh now restores the current page, collector, and ECHO case within the same tab or app window. Cloud sign-out clears these preferences. Live cloud verification is pending.
- Batch live staging checks after the next group of product changes.

### Investigation workflow

ECHO case reviews save status and analyst notes to the owning workspace. Concurrent edits receive a reload prompt instead of overwriting an updated review. IRIS offers pivots by host, process, and observed address, and stores named search filters in the workspace. Local cloud API tests exercise cross-account access and review conflicts. Live testing is deferred to the combined staging pass.

### Workspace settings

The hosted console shows the workspace's evidence retention period and usage limits, and lets the workspace owner turn cloud AI briefs off. Tests cover account isolation for the setting and evidence briefs without model calls when a workspace opts out. Deployment is pending.

### Workspace isolation checkpoint

- Added database ownership for individually provisioned accounts while keeping the existing workspace's unowned data and keys in a separate legacy scope. Account keys are stored as hashes and disabled accounts cannot sign in, read evidence or upload via paired collectors.
- Enforced ownership on cloud source listings and selection, collector pairing and revocation, and ECHO's cross-collector lookup. The source boundary also applies to events, network snapshots, case lists, reports and AI drafts.
- Verified with `node --test cloud/worker.test.mjs`. The test exercises the existing workspace and two provisioned accounts, including cross-account reads, report and AI access, collector keys and disabled-account behavior.
- Individual provisioning is an internal step. Normal account sign-up, authentication provider integration, quotas, and production deployment are pending.

### Remaining order

Browser sign-in now supports Google OAuth with PKCE, a signed state cookie, and a separate workspace for each Google subject. The service does not store profile fields or provider tokens. Live activation requires a Google web OAuth client with the exact HTTPS callback `/api/cloud/auth/google/callback` on the hosted origin, and Worker secrets `NORTH_GOOGLE_CLIENT_ID` and `NORTH_GOOGLE_CLIENT_SECRET`. The flow is covered by a mocked provider test. Public deployment, user-facing account controls and desktop handoff remain pending.

The Worker enforces 600 collector uploads and 20 cloud AI briefs per workspace per UTC hour. A limited collector gets a retry time and keeps undelivered records. IRIS shows an evidence-based brief when its AI limit is reached. Verified with `node --test cloud/worker.test.mjs`, `pytest tests/test_cloud_sync.py -q`, and the cloud frontend build.

Hosted event and case retention is available through the Worker variable `NORTH_HOSTED_RETENTION_DAYS` (1–365 days) and a scheduled trigger. The example Worker config schedules cleanup every 15 minutes. Deletion proceeds in batches, and ingest skips expired events and cases with expired evidence. The existing private workspace, collector settings, and latest network inventory snapshots are outside this cleanup. Local tests cover deletion, replay prevention, and new data after cleanup. The service also caps model calls at 200 per UTC hour across all workspaces. Live D1 verification, additional data lifecycle controls and other service-wide cost limits remain pending.

Desktop browser handoff now uses a short-lived approval request and a one-time exchange bound to a verifier held by Electron's main process. The user confirms the matching code in a signed-in browser. Worker tests verify unauthenticated approval fails, incorrect verifiers are rejected, and a grant cannot be exchanged twice. Desktop bridge tests verify the renderer does not receive the verifier or cloud session cookie. Live Google and Electron handoff testing still requires the hosted deployment.

Signing out revokes that cloud session on the server. Other sessions remain active. Worker tests cover replay rejection after sign-out, desktop approval denial with a revoked session, and cleanup after expiry. Live verification is pending the next staging deployment.

Collector onboarding offers a standalone Windows ZIP, a copyable command with the workspace address on the web, separate pairing-key entry, and first-sync status. The deploy script builds the archive from an explicit source allowlist. The owner confirmed a real Windows collector synced to staging and populated ATLAS after a manual refresh. Staging source discovery now checks every five seconds while waiting for the first collector, and the cloud and inventory views refresh when brought back into focus. Automatic refresh remains to be verified live.

The Windows deploy script accepts `-Staging` to deploy `north-cloud-staging` with a separate D1 database and encrypted keys. A simulated deployment verified resource names, database binding, AI binding, and credential isolation. Run `tools/Deploy-NorthCloud.ps1 -Staging -EnableCloudAI` first to obtain its callback URL. Create a Google OAuth **Web application** client for that exact callback. During Google testing, add only the accounts that should be able to sign in. Then run the same deployment command with `-ConfigureGoogle` and enter the credentials in the local prompts. The client secret is passed to Wrangler over stdin. The staging retention setting is 30 days.

The project owner confirmed live Google sign-in in the staging browser app and successful browser approval in the cloud-only Windows desktop build. The desktop ZIP was checked for archive integrity and the fixed staging origin. Local isolation tests passed with provisioned accounts. For the live two-account test, `tools/Test-NorthStagingIsolation.ps1` uploaded a synthetic event and case using the first Google account's collector pairing. The owner retrieved the event and exported a Markdown report with the matching evidence ID. A second signed-in Google account received `Collector not found` from both the event and report URLs. After switching to the cataloged Llama 3.3 70B FP8 Fast model, the owner confirmed IRIS displayed `Prioritized by cloud AI` and cited the same synthetic event. This verified one live cloud inference, rather than ranking quality across a multi-event case.

1. Design individual sign-in and enforce workspace membership on every API and collector operation. Verify isolation for event search, evidence, reports, exports, AI, and pairing before enabling public access.
2. Deploy a shared HTTPS service with account onboarding, cloud data ingestion, retention, audit logging and per-account quotas.
3. Move analysis, searchable event history, detection and AI to the hosted workspace. Validate citations and keep evidence-derived fallback summaries.
4. Implement the hosted ATLAS, IRIS and ECHO improvements, source setup and account settings. Keep real telemetry opt-in for each collector.
5. Run acceptance, accessibility, security and performance checks and publish the web service and installer.
