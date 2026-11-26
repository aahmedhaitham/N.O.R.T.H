# Detection coverage

The bundled rule catalog is tested with synthetic positive and negative fixtures. Those checks establish behavior on the recorded fixtures. Live validation is **not yet run**.

| Technique | Recorded test | Rule | Finding observed | False-positive notes |
|---|---|---|---|---|

For an offline review, use findings from a separately approved exercise or an existing synthetic recording. Record the time bounds, NORTH commit, sources available during the run, exact evidence IDs, and any negative control. A missing finding is meaningful only if the required source was available and the evidence was actually collected.

The read-only report and renderer can summarize an existing database copy. Run from the repository root and replace the example UTC time bounds with the recorded window.

```powershell
& ./backend/.venv/Scripts/python.exe tools/Report-NorthRecordedFindings.py ./recorded-findings.sqlite3 --since 2026-01-15T10:00:00Z --until 2026-01-15T11:00:00Z | Set-Content -Encoding utf8 recorded-findings.json
& ./backend/.venv/Scripts/python.exe tools/Render-NorthRecordedCoverage.py ./recorded-findings.json
```

The renderer lists observed findings only. An empty output window remains unverified. Keep captured data and results private unless reviewed for publication.
