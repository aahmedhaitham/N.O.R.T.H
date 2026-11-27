# Repository and release preparation

## Repository metadata draft

Description

> Windows-first security console for network observations, evidence-linked investigations, and local posture verification.

Topics

`windows`, `cybersecurity`, `dfir`, `endpoint-security`, `sysmon`,
`cloudtrail`, `electron`, `fastapi`, `detection-engineering`

## Open pull requests

GitHub returned the following 11 open Dependabot pull requests on 27 November
2026. This list reflects the titles and targets. Mergeability and compatibility
remain to be tested against the candidate commits.

| PR | Change | Review before merging |
| --- | --- | --- |
| [#11](https://github.com/aahmedhaitham/N.O.R.T.H/pull/11) | React Flow major version | Check canvas selection, layout, keyboard actions, and rendering of evidence-linked graphs. |
| [#10](https://github.com/aahmedhaitham/N.O.R.T.H/pull/10) | TypeScript major version | Review compiler and toolchain compatibility. Run the type check, the UI build, and desktop tests. |
| [#9](https://github.com/aahmedhaitham/N.O.R.T.H/pull/9) | Vite upgrade | Test development, cloud and packaged UI builds. Compare bundle output and installed startup. |
| [#8](https://github.com/aahmedhaitham/N.O.R.T.H/pull/8) | React DOM and types | Review with #7. Check runtime and types stay compatible, and rerun form and keyboard flows. |
| [#7](https://github.com/aahmedhaitham/N.O.R.T.H/pull/7) | React and types | Review with #8. Check focus, polling cleanup, and desktop interactions. |
| [#6](https://github.com/aahmedhaitham/N.O.R.T.H/pull/6) | Uvicorn update | Run API, loopback, Docker and WebSocket reconnect checks. |
| [#5](https://github.com/aahmedhaitham/N.O.R.T.H/pull/5) | WebSockets major version | Check backend compatibility, reconnect behavior, and Docker and collector sync tests. |
| [#4](https://github.com/aahmedhaitham/N.O.R.T.H/pull/4) | Checkout action major version | Review runner compatibility and confirm both Verify and Windows packaging can check out the intended commit. |
| [#3](https://github.com/aahmedhaitham/N.O.R.T.H/pull/3) | Node setup action major version | Verify configuration, lockfile caching, and the pinned Node version on each runner. |
| [#2](https://github.com/aahmedhaitham/N.O.R.T.H/pull/2) | Artifact upload action major version | Verify Windows artifact names, downloads, file digests, and attestation and signing integration before adopting. |
| [#1](https://github.com/aahmedhaitham/N.O.R.T.H/pull/1) | Python setup action major version | Verify the Python runtime and lockfile/cache behavior with the backend suite and Windows collector build. |

## Public build attestation

The Windows workflow already grants the build job `id-token: write` and
`attestations: write`, and runs its attestation step automatically for a
public source repository. Trigger **Build NORTH for Windows** for the intended
commit and confirm the attestation step succeeded. The older published
preview's build skipped that step.

Download the artifact for that run and verify both executable hashes using
`SHA256SUMS.txt` and `BUILD-INFO.json`. With GitHub CLI, run:

```powershell
gh attestation verify ./NORTH-Setup-Windows-x64.exe --repo aahmedhaitham/N.O.R.T.H
gh attestation verify ./NORTH-Desktop-Windows-x64.exe --repo aahmedhaitham/N.O.R.T.H
```

Check the provenance against the expected source commit and workflow. Windows
publisher signing is a separate step. [GitHub attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## Signing handoff

GitHub metadata returned no detected repository license. The maintainer must
choose an OSI-approved license before proceeding with SignPath Foundation and
verify whether the prior application was approved. After approval, configure
the trusted GitHub build, artifact configuration and signing policy, then put
the signing credential in the approved secret store. Submit the exact
candidate for a maintainer-approved signing request, verify the returned
Authenticode signatures and timestamps, regenerate distributed digests for
the signed binaries, and rerun clean-VM acceptance. Retain build provenance
for the exact artifacts it covers.

[SignPath Foundation terms](https://signpath.org/terms) ·
[SignPath GitHub integration](https://docs.signpath.io/trusted-build-systems/github)
