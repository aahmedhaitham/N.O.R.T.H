# Detection coverage

The bundled rule catalog is tested with synthetic positive and negative fixtures. Those checks establish behavior on the recorded fixtures. Live validation is **not yet run**.

<!-- north-coverage:start -->
<!-- north-coverage:end -->

For an offline review, use findings from a separately approved exercise or an existing synthetic recording. Record the time bounds, NORTH commit, sources available during the run, exact evidence IDs, and any negative control. A missing finding is meaningful only if the required source was available and the evidence was actually collected.

The read-only report and renderer can summarize an existing database copy. Run from the repository root and replace the example UTC time bounds with the recorded window.

```powershell
& ./backend/.venv/Scripts/python.exe tools/Report-NorthRecordedFindings.py ./recorded-findings.sqlite3 --since 2026-01-15T10:00:00Z --until 2026-01-15T11:00:00Z | Set-Content -Encoding utf8 recorded-findings.json
& ./backend/.venv/Scripts/python.exe tools/Render-NorthRecordedCoverage.py ./recorded-findings.json
```

The renderer lists observed findings only. An empty output window remains unverified. Keep captured data and results private unless reviewed for publication.

## Offline Windows dataset replay

Use the development Python environment on Windows. The replay tool opens an
existing EVTX file through the Windows event reader, evaluates supported
records and reports matched rule IDs by technique. It limits file and record
counts and labels output offline-replay. Unsupported channels and event types
are counted as skipped. The runner does not import the file into NORTH or
execute any commands found in the stored logs.

The dataset downloader accepts a full commit ID and a relative EVTX path
within the [reviewed public dataset repository](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).
It checks the pinned GPL-3.0 license text, file signature and size, then saves a
provenance manifest with the source and SHA-256. Dataset files belong outside
Git. The default download folder is ignored locally.

```powershell
& ./backend/.venv/Scripts/python.exe tools/Get-NorthEvtxDataset.py 'FULL-COMMIT-ID' 'RELATIVE-PATH.evtx'
& ./backend/.venv/Scripts/python.exe tools/Replay-NorthEvtx.py '.north-launcher/datasets/FILENAME.evtx'
```

To review already recorded exercise windows, copy
`tools/atomic/run-log.example.csv` to a private file and fill it using the
[VM runbook](VM_RUNBOOK.md#recorded-exercise-windows). Match those windows
against a database copy using the read-only reporter.

```powershell
& ./backend/.venv/Scripts/python.exe tools/atomic/Report-NorthRunWindows.py ./recorded-findings.sqlite3 ./run-log.csv
```

The report includes outcomes and evidence links for expected rules, plus
unverified windows. The existing renderer and checker accept its findings
schema. Only reviewed live evidence should reach the coverage table.
