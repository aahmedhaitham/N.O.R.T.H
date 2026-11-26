# NORTH publication checklist

The intended next release is **v0.3.0-preview**, an unsigned Windows preview.
The maintainer controls visibility, publishing, history decisions, and signing.

## Review the source before changing access

- Review the redacted history scan below and repeat it after any changes.
- Inspect sample telemetry, demo files, and tests flagged below for actual names,
  addresses, process arguments and keys. Review historical changes, issues,
  workflow logs, release notes and attachments. A secret scan alone cannot
  establish that everything is synthetic.
- If any real credential was committed, revoke or rotate it in the provider
  before changing access. Decide privately how to clean any affected history
  and clones. Keep repository visibility private until the review is complete.
- Review repository licensing and third-party obligations before public access.
  Confirm that the source visibility decision applies to the source repo.
  The public NORTH-Releases repo can distribute a preview separately.

## Validate and publish the build

- Push the candidate, record its full commit, and open the Windows workflow.
  Verify the backend, desktop, cloud, secret-scan, and installed walkthrough
  checks. Run the clean VM checks in the preview guide.
- Download matching installer, portable executable, SHA256SUMS.txt and
  BUILD-INFO.json from the successful candidate run. Follow the exact
  [verification commands](docs/RELEASE-PREVIEW.md#download-and-verify).
- If the repository is eligible, enable the required Actions permissions and
  use NORTH_ATTESTATIONS_ENABLED=true for an eligible private repo, then rerun
  the build. Check the attestation result before distributing files.
- Record a screenshot or short GIF with synthetic data and no personal
  usernames, Wi-Fi labels, live events, or browser tabs. Add it in the README
  media slot. Leave live coverage marked unverified until supported.
- Choose the intended repository and confirm its description and topics.
  Suggested description: Local Windows console for network observations,
  event triage and evidence-linked investigations.
- Publish the preview notes and verified binaries, checksum file and metadata
  to NORTH-Releases. Use the preview label and preserve the older release.
  Verify access to the final public link while signed out.
- For a future signed release, verify publisher signing and repeat installation
  checks. Keep the v1 label reserved for that milestone.

## Redacted history scan and review inventory

Tool version: Gitleaks 8.30.1.
Command: gitleaks git --log-opts=--all --redact=100 --no-banner .
Result before this checklist was committed: 152 commits scanned, no leaks found,
exit 0. No credential values were printed.

Files and locations for manual review:

- backend/fixtures/ contains synthetic Sysmon, Linux journal, detection and
  correlation examples.
- desktop/assistant-golden.json and desktop/*.test.cjs include test identities,
  network labels, example addresses and event references.
- frontend/public/demo/ and cloud tests may include fixture names and addresses.
- cloud/wrangler.example.jsonc and deployment scripts should contain example
  values only. Ignored local configurations and key files stay outside the
  source and release files.
- Local audit notes, raw-logs, database copies, packet captures, diagnostics,
  old build outputs and signing material are candidate private data. Review
  both tracked history and the final extracted installer payload.
