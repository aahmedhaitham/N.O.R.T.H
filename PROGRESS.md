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

### Local-first product brief · Phase 8 documentation and preview release

- Updated the README with desktop quick start, a preview-media slot, architecture diagram, and coverage and limits. Moved development, cloud, and authorized telemetry instructions into separate guides. Added architecture and Assistant contributor guides and updated privacy, security, threat model, and dependency notices.
- The Windows workflow now records commit, run, and per-file digests in `BUILD-INFO.json`, alongside `SHA256SUMS.txt`. It generates GitHub build attestations when supported by repository settings. The release notes label the artifacts as unsigned previews.
- Checked repository-relative documentation links, workflow YAML structure, and staged whitespace. A new installer run, its artifact hashes and any attestation, synthetic preview media, and Windows publisher signing remain unverified. No release was published.

### Local-first product brief · Phase 7 quality checks

- Added fixed-snapshot answer and citation checks for all 34 Assistant intents, Hypothesis tests for rule parsing, fast-check tests for the Assistant and import parsers, and collector argument validation cases. Verified 112 backend tests plus 2 subtests, 27 desktop tests, 3 cloud tests, and the desktop UI build.
- Added Windows syntax and type checks, a redacted history scan, CodeQL configuration for enabled repositories, and Dependabot. The installed walkthrough now runs selected axe checks, checks reduced-motion signaling, and measures startup and main-process working set. GitHub runner results for these additions remain pending.
- The reproducible synthetic benchmark measured 9,651.7 SQLite ingests/sec and a 793.08 ms median rare-match search on 500,000 events. See `docs/PERFORMANCE.md` for hardware, sample sizes, and the other measured results.
- Read-only tools export and render findings from an existing isolated recording. Their synthetic walkthrough passed. `docs/COVERAGE.md` keeps live coverage marked **not yet run**.

- Assistant tests route more than 150 distinct phrasings, including typos and unknown requests. Tests cover bounded non-mutating responses, exact evidence IDs, malformed input, and zero requests through fetch during answer generation.
- Rules now have an exact threshold-window boundary test and seeded malformed YAML tests. The installed Windows walkthrough now checks the Assistant keyboard shortcut and confirms synthetic markup renders as text.
- Verified 25 desktop tests, the two new backend rule tests, and the desktop UI build. The installed walkthrough, broader UI accessibility checks, performance benchmarks, and remaining quality work are open.

### Local-first product brief · Phase 6 first-run setup

- First-run setup checks existing source visibility, explains missing logs and denied access, offers Simple or Analyst mode, and explains local storage and cloud sync. Finish or skip without changing permissions, starting monitoring, or pairing a collector.
- Optional desktop monitoring uses the existing local collector after a separate confirmation. The cloud setup guide links to the existing Collectors page. Reopen the guide from Settings.
- The desktop UI build and 22 desktop tests passed. The installed Windows walkthrough now checks setup completion, persistence after reload, and reopening and skipping the guide. The updated walkthrough still needs a GitHub runner result.

### Local-first product brief · Phase 5 NORTH Assistant

- Added a docked panel available through **Assistant**, **Ctrl+J**, and the **Ctrl+K** command palette. It matches 34 question intents, offers autocomplete and follow-ups, and keeps a clearable history for the current workspace session.
- Answers use a bounded in-memory snapshot of data already loaded by NORTH. The assistant issues no requests and executes no commands. Findings, events, devices, connections, investigations, and rule coverage link back to their corresponding app records. Country answers require a loaded endpoint attribution and an exact destination IP match.
- Unknown questions offer three suggestions. Missing or inaccessible data is reported as such when source status is available. Changes such as device trust and configuration remain in their existing screens. The assistant itself offers no privileged repair or response actions.
- The desktop UI build, 20 desktop tests, and 3 cloud tests passed. Added an Assistant evidence-navigation step to the installed Windows walkthrough. That step still needs a GitHub runner result.

### Local-first product brief · Phase 4 Simple mode

- Simple is the default display mode. Workspace **Settings → Display mode** switches to Analyst and remembers the choice on that device. Both modes use the same observations, findings, and investigations.
- Simple Overview answers four questions about the computer, nearby devices, recorded connections, and next steps. Its status checks high-severity findings first, then other unreviewed findings and open cases, unrecognized devices, and current telemetry. Missing or stale data cannot show Good. Local finding counts cover every page.
- New-device answers persist in browser storage for the current desktop or collector. Device labels use observed names and app labels use executable names. The connection card lists observed destinations separately from app activity where the data does not establish a pair.
- The Simple dashboard and display settings use an English message catalog. Broader catalog migration and installed-app walkthrough remain open. Verified 109 backend tests, 2 subtests, 18 desktop tests, and the desktop UI build.

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

### Stabilization Phase A

- Recorded the six user-reported items in BUGS.md. Four major, one minor, and one cosmetic. The local Electron launch exited with 2147483651 before an interactive window, so the visual matrix and screenshots remain unverified.
- Baseline commands: npm.cmd --prefix desktop test (27 passed), npm.cmd --prefix desktop run build:ui (passed), backend pytest with faulthandler_timeout=15 (112 passed, 2 subtests), and the cloud Worker and GeoIP tests (3 passed).
- Continue with response handling, shared source evidence, permission guidance, and the Assistant. Validate visually in a fresh interactive Windows session.

### Stabilization Phase B

- Detections now treats empty, invalid, failed and timed-out replies as recoverable and offers retry. Development builds prefer the source rule engine over a stale bundled executable. The reported failure has not been reproduced in an interactive build.
- Desktop Detections uses the same passive Sysmon read as Overview. Unchecked sources have an explicit coverage category. Added fixtures for current, empty, denied, missing, failed, and unchecked states. Local TCP now has a retry and plain-language guidance. Simple mode points to denied Windows event access.
- Replaced the Assistant native dropdown with keyboard suggestions and moved the panel beside the workspace. Added compact answers, grouped evidence and one copy action per answer. The visual check remains pending.
- Commands: desktop test (28 passed), desktop UI build (passed), backend pytest (118 passed, 2 subtests), cloud Worker and GeoIP tests (3 passed). The Detections transport is covered independently. Other client API paths and release installation still need checks.

### Stabilization Phase C

- Added a docked width control that remembers its setting, styled file picker buttons, reset rule search when leaving the view, and grouped technique status by the published Enterprise ATT&CK tactic mapping. Coverage groups include text states and link to source guidance in affected rules.
- Added an SQLite trigram search index with exact literal filtering and an indexed-data regression test. The pre-change 500,000-event rerun measured 1327.37 ms median for the rare-match query. The indexed rerun measured 21.78 ms median. Ingest fell from 4,867.9 to 1,369.9 events/sec. See docs/PERFORMANCE.md for the comparison.
- Commands: desktop test (28 passed), desktop UI build (passed), backend pytest (119 passed, 2 subtests), cloud tests (3 passed). Synthetic screenshots, every-screen axe and keyboard verification, and the size/theme matrix remain blocked by the local Electron launch.

### Stabilization Phase D

- Added a two-file SHA-256 verifier that cross-checks the checksum list, BUILD-INFO.json, and optional commit pin. A synthetic artifact set passed and a modified installer was rejected.
- Documented a clean Windows VM pass for disconnected first launch, upgrade, and uninstall. The current release candidate installer and its artifact inventory were not available to verify here. No signing, publishing, visibility, or account changes were made.
- Commands: desktop test (28 passed), desktop UI build (passed), backend pytest (119 passed, 2 subtests), cloud tests (3 passed).

### Stabilization Phase E

- Added a passive Windows VM runbook and a CI coverage claims check. The checker accepted an isolated matching fixture and rejected missing or changed evidence. The tracked live coverage document remains empty and marked not yet run.
- The read-only NORTH reporting path is available for already recorded approved data. Live attack-tool execution and technique execution instructions are outside the delivered runbook.
- Commands: coverage checker against the repository and temporary fixtures (passed), desktop test (28 passed), desktop UI build (passed), backend pytest (119 passed, 2 subtests), and cloud tests (3 passed).

### Stabilization Phase F

- Added a documentation index, third-party attribution, and a publication checklist for the unsigned v0.3.0 preview candidate.
- A redacted Gitleaks 8.30.1 scan of 152 commits reported no leaks (exit 0). The final installer contents, clean-VM acceptance, and public release remain pending.
- Checked the documentation links, workflow YAML, and coverage claims. Final regression totals match Phase C.

### Published Windows preview

- Pushed candidate 115463a07777e9082f37dba0bd7857219c6af2f5. Verify NORTH (45903969587) and Build NORTH for Windows (45903969540) succeeded. The Windows run installed the package, checked the collector, and completed the Simple and Analyst walkthrough. Attestation was skipped.
- The GitHub artifact archive SHA-256 matched. Test-NorthPreviewArtifacts.ps1 verified both executable hashes and the candidate commit. Authenticode reported NotSigned. Extracted resource scans were clear after tracing three raw archive matches to unchanged Zod dependency test fixtures.
- Published the unsigned preview at https://github.com/aahmedhaitham/NORTH-Releases/releases/tag/v0.3.0-preview. GitHub asset digests matched the four uploaded files, and the release API returned all four without authentication.
- Clean-VM disconnected first launch, upgrade and uninstall remain unverified. Live detection coverage remains not yet run.

### Feature completion M1 — in progress

- Audited all 41 existing bundled rules and recorded qualitative benign-firing estimates in docs/RULE-QUALITY-AUDIT.md. The audit identifies 19 standalone process-start rules and four broad rules. No rules or ATT&CK coverage were removed in this slice.
- Enabled Sysmon file-create event 11 in the local Windows source and retained the target path. A synthetic collection test covers ingestion, normalization and PowerShell script-write source coverage.
- Added a Security 4688 rule for encoded PowerShell with three positive and three negative synthetic cases, each evaluated independently. The PowerShell ATT&CK mapping was verified at https://attack.mitre.org/techniques/T1059/001/.
- Verification: backend .venv/Scripts/python.exe -m pytest -q -o faulthandler_timeout=15 tests (122 passed, 2 subtests); npm.cmd --prefix desktop test (28 passed); node --test cloud/worker.test.mjs cloud/geoip.test.mjs (3 passed); npm.cmd --prefix desktop run build:ui (passed with a chunk-size warning).
- Remaining M1 work: contextual replacements for standalone process starts, narrowing broad rules, additional detections and fixtures, severity/confidence/rarity display, rule trace, and replay-based noise estimates. M2 through M9 remain open.

#### Needs manual verification

- With Sysmon file creation enabled, confirm a previously recorded event 11 appears in the Windows local collector and that the PowerShell script-write coverage reflects the observed event types.
- With previously recorded Security 4688 events containing command-line data, verify that the new rule and appropriate evidence appear in the desktop.

### Feature completion M1 — implemented and automated checks passed

- Reworked 19 process-start rules to require command-line or parent context. Preserved rule IDs and original ATT&CK IDs. Added distinct discovery correlation and the high-signal Windows rules documented in docs/RULE-QUALITY-AUDIT.md. The current catalog check reports 51 rules and no info-level process-start rules.
- Remote-thread rules require source and target evidence. The LSASS rule requires the memory-read access bit and an observed source. Both exclude the standard Windows Error Reporting executable paths. Service and scheduled-task creation remain broad, with synthetic examples of ordinary matching maintenance.
- Added positive and negative event fixtures and correlation scenarios, including ordinary launches, repeated utilities, wrong parents, missing fields, wrong sources and observations outside the time window. The Sysmon file-create test verifies source coverage against synthetic stored records.
- Finding details present severity, evidence confidence and baseline rarity. Detections can replay disabled rules against recent stored evidence, show a selectable event trace, and estimate alerts per day when the sample spans at least an hour. These are local observations from the replay sample.
- Commands and outcomes: backend .venv/Scripts/python.exe -m pytest -q -o faulthandler_timeout=15 tests (183 passed, 2 subtests); npm.cmd --prefix desktop test (28 passed); node --test cloud/worker.test.mjs cloud/geoip.test.mjs (3 passed); npm.cmd --prefix desktop run build:ui (passed with the bundle-size warning); PowerShell event reader parse (passed).
- Milestones M2–M9 remain open.

#### Needs manual verification

- Confirm real Security audit and Sysmon events are collected on Windows, including parent paths, access masks, group SIDs and file-create event 11. Compare source coverage with actual event types available on the PC.
- On a desktop build, verify finding confidence and rarity in Simple and Analyst mode, and verify that Detections displays the trace, event selection and noise estimate for a rule preview.
- Collect evidence from ordinary workloads before drawing conclusions about false-positive rates. The audit uses qualitative estimates and the tests use synthetic events.

### Feature completion M2 — passive health foundation

- Extended the existing Windows source watcher. It persists the most recent source check, collector activity and event timestamp locally. Sysmon reports a quiet state after an hour without a newer observed event. Quiet can reflect ordinary inactivity. Read failures, disabled channels and denied access have distinct explanations.
- Source-health transitions produce reviewable findings through the existing local findings store. Repeated identical states do not create repeated findings. Historical findings remain available after the source recovers.
- Verified with 184 backend tests and 2 subtests, 28 desktop tests, 3 cloud tests, and the desktop UI build. The source-health regression uses synthetic timestamps and exercises waiting, observed, quiet, denied and recovered states.
- M2 remains open. Sysmon service-state and policy drift collection, self-test runs and reports, and coverage verification from confirmed results remain unimplemented.

#### Needs manual verification

- Check that the local Windows source monitor displays a finding for an observed source failure and records recovery when that source becomes readable again. Validate the quiet threshold on a real workstation before interpreting its frequency.

### Feature completion M2 — recorded evidence check

- Detections previews a read-only check and requires explicit confirmation. It tests five bundled rules against up to 500 locally recorded Windows events, explains missing evidence, links real stored event IDs, saves the last 20 reports and supports Markdown export. Reopening Detections shows the latest saved report. The check writes no detection findings.
- The existing Windows watcher now observes the standard Sysmon service names. Stopped service state is reported separately from quiet event activity, and unknown service state does not imply missing Sysmon.
- Verified: backend pytest (191 passed, 2 subtests), desktop test (28 passed), cloud Worker and GeoIP tests (3 passed), desktop UI build (passed), and Windows source reader PowerShell syntax.
- Recorded matches establish rule behavior on the local sample. Active persistence simulations, live coverage promotion and general audit-policy drift remain open.

#### Needs manual verification

- In the desktop, confirm that preview, report reload, evidence links and Markdown export work with recorded Windows events. Confirm the Sysmon service-state display and finding behavior using existing Windows observations.

### M2 — audit-policy monitoring

- The passive Windows Security collector records audit-policy change event 4719 and links it to a local review finding. The change is evidence of policy activity and does not establish which logging capabilities remain available.
- Verified: 192 backend tests, 2 subtests, 28 desktop tests and 3 cloud tests passed. The UI built with the existing bundle-size warning.
- M2 remains partially complete. The live simulation and verified-coverage tier are open. Desktop and live Windows observations remain unverified.

### M2 — recorded pipeline coverage

- Detections has a Verified from recorded findings tier. A confirmed replay must link recent local events to the same finding previously saved by the detection pipeline. The rule must be enabled, the required sources currently observed, and the report less than a day old.
- Verified: 193 backend tests, 2 subtests, 28 desktop tests, 3 cloud tests and the desktop UI build. The regression distinguishes replay alone, a stored finding, stale coverage, an expired report and a disabled rule.
- Live Windows and desktop acceptance remain unverified. The original active persistence simulations are outside the delivered passive implementation.

### M3 — read-only Windows posture foundation

- Added a local-only Windows posture panel in Simple and Analyst views with 12 checks for firewall profiles, SMBv1, Remote Desktop, UAC, Secure Boot, TPM, Defender and logging settings. Windows values the collector cannot determine are reported as unknown.
- Verified: 193 backend tests, 2 subtests, 29 desktop tests, 3 cloud tests, PowerShell syntax, and the desktop UI build.
- A direct Windows PowerShell run returned an authorization error. The packaged Windows reader and desktop walkthrough remain unverified.
- M3 remains open. Remaining scope includes the full catalog, Defender and update details, posture scoring, drift history, and audited confirmed fixes and undo.

### M3 — weighted posture score and expanded checks

- Expanded the Windows posture reader from 12 to 18 observations with Defender signature and scan recency, BitLocker protection, built-in Guest, Sysmon service status and the Windows Update reboot marker.
- The local desktop API computes earned and available points using fixed weights. Unknown checks are excluded, duplicate IDs are rejected, and each failed check displays its point cost. The score summarizes checked settings.
- Verified: 193 backend tests, 2 subtests, 29 desktop tests, 3 cloud tests and the desktop UI build. A direct local Windows reader run returned 18 results (14 pass, 4 unknown). The packaged desktop walkthrough remains unverified.
- M3 remains open for the rest of the posture catalog, deeper Defender and Windows Update details, drift history, and confirmed fixes and undo.

### M3 — expanded catalog and posture drift

- Expanded to 25 read-only checks, including configured LSA protection, running Credential Guard, AutoRun and Script Host policies, and additional Defender checks. Defender exclusion checks summarize whether preferences returned exclusions without displaying their contents.
- The posture panel polls every five minutes while enabled on the visible dashboard. It compares the new statuses with the previous local snapshot, including across app sessions. A change to unknown can indicate a change in access.
- Verified: 193 backend tests, 2 subtests, 30 desktop tests, 3 cloud tests, and the desktop UI build. The Windows reader returned all 25 results (17 pass, 2 fail, 6 unknown).
- M3 remains open. Pending update and OS support details, richer Defender evidence, confirmed repair actions with audit logging and undo, and the packaged Windows walkthrough are pending.

### M3 — Windows Update and Defender details

- Added a separate read-only posture details request with cached pending updates, recent successful update history, last Defender scan, and a bounded detection count. Windows Update is queried offline. An unavailable details reader leaves the main 25 posture checks usable.
- Added sourced Windows 11 Home and Pro lifecycle dates for known builds. Other editions and builds remain unknown.
- Verified: 193 backend tests, 2 subtests, 31 desktop tests, 3 cloud tests and the desktop UI build. A local Windows run returned six structured fields. Individual Windows values and the packaged UI remain unverified.
- M3 remains open for confirmed repairs, audit logging and undo, the Defender quick-scan action, and exclusion-level drift. No Windows settings were changed during verification.

### M3 — confirmed Defender quick scan

- Added a local-only Defender quick-scan request with a native confirmation dialog. The handler refuses requests from other origins and avoids duplicate requests while confirmation or launch is pending. The UI reports request acceptance or uncertainty, and directs the user to Windows Security for scan results.
- Verified: 193 backend tests, 2 subtests, 32 desktop tests, 3 cloud tests, scan script syntax and desktop UI build. The desktop test uses a fake scan runner and proves cancellation leaves it untouched. A live scan and packaged desktop walkthrough were not run.
- M3 remains open for Windows settings repairs with exact previews, UAC, audit records and undo, plus individual Defender exclusion change tracking.

### M3 — confirmed posture repairs and exclusion changes

- Implemented seven allowlisted repairs: the two logging settings, SMBv1 server protocol, the three local firewall profiles, and computer AutoRun policy. The desktop previews the exact old and requested value, requires native confirmation and UAC, checks the packaged script hash, rechecks the old value after elevation, records the undo value before applying, audits requests and outcomes, and reads back the result. A managed firewall policy can still override the local policy value.
- Added local Defender exclusion details and counts for added and removed entries since the last readable list. The saved comparison uses keyed digests. Readable data is bounded and shown only in the local dashboard.
- Verified: 193 backend tests, 2 subtests, 34 desktop tests, 3 cloud tests, both PowerShell syntax checks, the pinned repair digest and the desktop UI build. The Windows reader returned 25 checks. All seven read-only repair previews were readable.
- M3 implementation is available locally. Real UAC apply and undo, the confirmed Defender scan, and packaged desktop acceptance remain unverified. The repair round trip used a fake backend, and Windows settings were not modified.

### M4 — Verify my PC and What Changed

- Added a local dashboard flow in Simple and Analyst modes. It reuses the Sysmon and Windows source checks, posture and Defender readers, and unreviewed findings. The Assistant shows the latest report's same three counts while the local dashboard is loaded.
- Added bounded snapshots for startup entries, services, scheduled tasks, listening endpoints, selected firewall rule properties, local users and admins, the hosts file, proxy and DNS settings, and Defender exclusions. The user can choose a known-good snapshot, inspect the last 20 reports and export Markdown. Diffs report added or modified and removed or replaced observations by category. The app links to the passive sensor evidence check.
- Verified: 193 backend tests, 2 subtests, 38 desktop tests, 3 cloud tests, Windows snapshot reader syntax and desktop UI build. A read-only Windows run returned 10 of 11 categories. Tests cover every category, local request scope, baseline persistence, unavailable findings, and Overview/Assistant count agreement.
- Packaged desktop acceptance remains open. Snapshot comparisons cover the selected properties and readable records. The report does not infer who caused a change.

### M5 — offline CloudTrail import foundation

- Added backend/cloudtrail.py for local command-line import of JSON and gzip CloudTrail exports into the private SQLite event store. It validates the full batch before inserting, deduplicates by event ID, and reports event count, time range, regions and event sources.
- The importer allowlists normalized fields and omits original request payloads, access-key fields and session tokens. It bounds file and decompressed size and record count. The normalized event contract exposes the CloudTrail event and identity metadata.
- Verified: 196 backend tests, 2 subtests, 38 desktop tests, 3 cloud tests and the desktop UI build. Tests cover JSON and gzip, malformed and oversized data, sensitive field omission, normalization, duplicates and the local storage boundary.
- M5 remains open for the desktop import flow, narrowly allowlisted request parameters, detection rules and fixtures, and coverage presentation.

### M5 — desktop CloudTrail import and offline findings

- Added the Windows desktop file picker in Detections. The application selects the file through a native dialog and imports into the local SQLite database. One transaction stores new records, import findings, and learned regions and addresses. The source list and date range cover stored imports only.
- Added 12 CloudTrail rules and first-seen region and source-address findings against previously imported evidence. Rules use conservative structured flags for recognized administrator policy, GuardDuty disablement, explicit public S3 grants and IPv4 world ingress. Effective access, other ACL or policy shapes, missing exports, and activity outside the imported time range remain unknown.
- Verified: 221 backend tests, 2 subtests, 38 desktop tests, 3 cloud tests, desktop UI build, and the source collector command against a temporary synthetic export and database. Each rule has checked positive and negative fixtures. The source collector smoke imported 3 events and created 3 findings.
- Packaged desktop acceptance remains open. The optional IAM graph was deferred. Live AWS APIs and credentials are outside this offline workflow.

### M6 — local evidence integrity foundation

- Added an opt-in HMAC chain covering new records in both local SQLite event tables, with a signed chain head and transactionally linked event writes. Verification identifies the first changed, missing or mislinked record. Existing events are outside the chain and verification reports its start time.
- Tests cover migration, duplicates, wrong or missing keys, modified payloads and timestamps, deleted events and chain entries, and a missing or altered chain head.
- Verified: 229 backend tests, 2 subtests, 38 desktop tests, 3 cloud tests and the desktop UI build.
- M6 remains open. Windows-protected key storage, the Settings and checkpoint flows, and ingest-cost measurement are pending. The desktop has not enabled the chain.

### M6 — protected desktop keys and Settings verification

- The Windows desktop uses Electron safeStorage for the local evidence key. The local worker receives the key for the database operation and removes it from the inherited environment before launching any helper. An existing chain with a missing key fails closed.
- Settings verifies the linked event history and optionally exports its authenticated checkpoint without raw evidence or the key. The report shows the chain start, count, or first broken link. Earlier evidence is outside the chain.
- Verified: 229 backend tests, 2 subtests, 39 desktop tests, 3 cloud tests and the UI build. The source collector verified a synthetic event and returned a key-free checkpoint. The DPAPI storage boundary uses an injected protection double in desktop tests.
- Five 10,000-event synthetic runs per mode measured median ingestion of 4,847.7 events/sec without integrity and 3,958.6 with it. See docs/PERFORMANCE.md for ranges.
- Packaged Windows verification and real safeStorage key persistence remain unverified. Full-host takeover and rollback require independent trust evidence.
