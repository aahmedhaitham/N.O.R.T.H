# NORTH publication checklist

The public **v0.3.0-preview** is unsigned and predates the current milestones.
See [release preparation](docs/RELEASE-PREPARATION.md) for the next candidate.
The maintainer controls visibility, publishing, history decisions, and signing.

## Review release material

- Review the redacted history scan below and repeat it after any changes.
- Inspect sample telemetry, demo files, and tests flagged below for actual names,
  addresses, process arguments and keys. Review historical changes, issues,
  workflow logs, release notes and attachments. A secret scan alone cannot
  establish that everything is synthetic.
- If any real credential was committed, revoke or rotate it in the provider
  before sharing further. Decide privately how to clean any affected history
  and clones.
- Review repository licensing and third-party obligations before the next public build.
  NORTH-Releases distributes previews separately from the source repo.

## Validate and publish the build

- Push the candidate, record its full commit, and open the Windows workflow.
  Verify the backend, desktop, cloud, secret-scan, and installed walkthrough
  checks. Run the clean VM checks in the preview guide.
- Download matching installer, portable executable, SHA256SUMS.txt and
  BUILD-INFO.json from the successful candidate run. Follow the exact
  [verification commands](docs/RELEASE-PREVIEW.md#download-and-verify).
- The current public-source workflow already enables build attestations.
  Check the attestation result for the candidate before distributing files.
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
