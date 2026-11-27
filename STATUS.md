# NORTH status

[V] Implemented with recorded verification. [O] Open or unverified. [B]
Depends on external approval or a missing prerequisite. [X] Excluded or deferred.

## Delivered

- [V] Public source and unsigned Windows x64 preview containing M1–M9.
  The installer passed the Simple and Analyst smoke test.
- [V] README screenshot from the synthetic portfolio workspace.
- [V] Local desktop workspace with ATLAS, IRIS, ECHO, Detections, and Assistant.
- [V] Contextual detection rules, finding confidence and rarity, rule trace, and
  sampled replay noise estimates.
- [V] Passive sensor monitoring, recorded evidence check, and audit-policy
  change findings.
- [V] Windows posture checks, weighted score, Defender details, change
  comparison, and confirmation-backed repairs and undo. Synthetic tests and
  Windows read-only checks cover the implemented paths.
- [V] Verify my PC report, known-good snapshots, timeline, and Markdown export.
- [V] Offline CloudTrail import, normalized detections, and sample coverage.
- [V] Local evidence chain, checkpoint export, and benchmark comparisons.
- [V] Offline EVTX replay and recorded-window reporting. A public sample was
  replayed locally.
- [V] Assistant evidence integration and measured held-out routing.
- [V] Current roadmap, architecture, notices, release checklist and benchmarks.

## Open or deferred

- [O] Extended packaged walkthrough, live UAC repairs and undo, confirmed Defender
  quick scan, and Windows integrity key persistence.
- [O] Clean Windows VM offline launch, upgrade and uninstall for the next
  candidate. Full keyboard, accessibility, theme and size review remains open.

- [O] Live detection coverage. Offline replay and synthetic tests demonstrate
  observed test behavior only.
- [B] Signed Windows release. License choice and SignPath approval and
  configuration still need confirmation.
- [X] Active persistence simulations and execution automation. The delivered
  validation tools consume recorded evidence.
- [X] Optional offline IAM graph deferred.
- [X] Cross-platform desktop installers and universal router measurements are
  outside the verified Windows release scope.

[Public source](https://github.com/aahmedhaitham/N.O.R.T.H) ·
[Windows preview](https://github.com/aahmedhaitham/NORTH-Releases/releases/tag/v0.4.0-preview) ·
[Progress log](PROGRESS.md) · [Roadmap](ROADMAP.md)
