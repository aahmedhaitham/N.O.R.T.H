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

### UX backlog

- Preserve the current view and selected collector when the browser page is refreshed. The project owner reported that refresh returns to the dashboard.

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
