# NORTH performance baseline

Measured on this Windows 11 workstation with an AMD Ryzen 5 7235HS, 8 logical processors, and 11.7 GiB visible RAM. The runs used synthetic data, Python 3.14.10, and Node 26.7.0.

| Metric | Measured result |
|---|---:|
| SQLite ingest, 500,000 generated events in 1,000-event batches, queue disabled | 9,651.7 events/sec |
| IRIS store search, one rare match among 500,000 events, 7 searches | 793.08 ms median |
| Evaluation of 41 bundled rules against 500 normalized events, 10 passes | 21,429.6 events/sec |
| Assistant intent matching, 555 timed questions | 1.502 ms median, 2.521 ms p95 |
| Peak RSS of the Node matcher benchmark | 76.7 MiB |

The search measurement calls the IRIS data-store query directly. Desktop startup and main-process working set are measured by the installer walkthrough and have no result for the current commit.

Run from the repository root:

```powershell
& ./backend/.venv/Scripts/python.exe backend/benchmark_north.py
node tools/Benchmark-NorthAssistant.mjs
```

## Stabilization search comparison

Measured with the same synthetic 500,000-event workload on this workstation. The benchmark exercises the store directly.

| Metric | Before index | With index |
|---|---:|---:|
| Rare-match search, seven runs, median | 1,327.37 ms | 21.78 ms |
| SQLite ingest | 4,867.9 events/sec | 1,369.9 events/sec |
| Rule evaluation | 8,397.9 events/sec | 10,075.5 events/sec |

The ingest measurement includes maintaining the search index. These are single benchmark runs with possible workstation load variation. The table above records an earlier baseline.

## M6 evidence chain cost

Five runs per mode, alternating order, used 10,000 synthetic events per run with the SQLite search index enabled. Run `python benchmark_north.py --events 10000` and repeat with `--integrity`. Other local validation was running during part of the sample.

| Integrity mode | Median events/sec | Observed range |
| --- | ---: | ---: |
| Off | 4,847.7 | 2,774.7–5,116.4 |
| On | 3,958.6 | 2,574.8–4,231.4 |
