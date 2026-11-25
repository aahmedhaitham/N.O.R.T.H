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

### Workspace isolation checkpoint

- Added database ownership for individually provisioned accounts while keeping the existing workspace's unowned data and keys in a separate legacy scope. Account keys are stored as hashes and disabled accounts cannot sign in, read evidence or upload via paired collectors.
- Enforced ownership on cloud source listings and selection, collector pairing and revocation, and ECHO's cross-collector lookup. The source boundary also applies to events, network snapshots, case lists, reports and AI drafts.
- Verified with `node --test cloud/worker.test.mjs`. The test exercises the existing workspace and two provisioned accounts, including cross-account reads, report and AI access, collector keys and disabled-account behavior.
- Individual provisioning is an internal step. Normal account sign-up, authentication provider integration, quotas, and production deployment are pending.

### Remaining order

Browser sign-in now supports Google OAuth with PKCE, a signed state cookie, and a separate workspace for each Google subject. The service does not store profile fields or provider tokens. Live activation requires a Google web OAuth client with the exact HTTPS callback `/api/cloud/auth/google/callback` on the hosted origin, and Worker secrets `NORTH_GOOGLE_CLIENT_ID` and `NORTH_GOOGLE_CLIENT_SECRET`. The flow is covered by a mocked provider test. Public deployment, user-facing account controls and desktop handoff remain pending.

1. Design individual sign-in and enforce workspace membership on every API and collector operation. Verify isolation for event search, evidence, reports, exports, AI, and pairing before enabling public access.
2. Deploy a shared HTTPS service with account onboarding, cloud data ingestion, retention, audit logging and per-account quotas.
3. Move analysis, searchable event history, detection and AI to the hosted workspace. Validate citations and keep evidence-derived fallback summaries.
4. Implement the hosted ATLAS, IRIS and ECHO improvements, source setup and account settings. Keep real telemetry opt-in for each collector.
5. Run acceptance, accessibility, security and performance checks and publish the web service and installer.
