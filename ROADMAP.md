# NORTH roadmap

The public Windows preview includes M1–M9. The [status sheet](STATUS.md)
distinguishes automated checks, live checks, and release readiness.

| Milestone | Current status | Evidence and remaining acceptance |
| --- | --- | --- |
| Foundation | Implemented | Electron Windows app, FastAPI development mode, optional cloud workspace, ATLAS, IRIS, ECHO, and packaged collector. The unsigned preview remains publicly available. |
| M1 · Detection quality | Implemented | Contextual rules, scoring, evidence trace, and sampled noise estimates passed automated tests. Live false-positive rates are open. |
| M2 · Sensor evidence | Passive implementation available | Source monitoring and verification from stored findings work with recorded data. Active persistence simulation was excluded. Live acceptance remains open. |
| M3 · Windows posture | Implemented | Read-only checks, weighted score, local drift, Defender action, and repair previews. Live UAC apply, undo, and confirmed Defender scan remain open. |
| M4 · Verify my PC | Implemented | Combined report, known-good comparison, timeline, and export. The Windows reader was exercised. Packaged acceptance remains open. |
| M5 · CloudTrail | Implemented | Offline Windows import, local detections and import coverage. Packaged file picker remains unverified. Optional IAM graph deferred. |
| M6 · Evidence integrity | Implemented | Authenticated SQLite chain, Windows-protected desktop key, Settings verification and checkpoint export. Real packaged key persistence remains unverified. |
| M7 · Proof tooling | Offline tooling implemented | Replayed a public EVTX sample. Recorded-window reporting and coverage checks passed. Live detection coverage remains not yet run. |
| M8 · Assistant integration | Implemented | Shared local evidence with golden tests and a separately measured held-out routing evaluation. Packaged citations remain unverified. |
| M9 · Documentation and measurement | Prepared | Current status, documentation, measured benchmarks, and repository and signing notes. |

## Release gates

1. Review the candidate commits and open dependency pull requests.
2. Build and verify the Windows installer from the candidate commit and confirm
   package provenance. Repeat the clean Windows VM install, upgrade, and
   uninstall checks.
3. Complete the desktop acceptance pass for Simple and Analyst modes, keyboard
   navigation, accessibility, and synthetic screenshots.
4. Record live detection evidence separately. Leave coverage unmeasured until
   evidence passes the coverage checker.
5. Select an open-source license and confirm signing provider approval before
   distributing signed binaries.

[Progress log](PROGRESS.md) · [Documentation index](docs/README.md)
