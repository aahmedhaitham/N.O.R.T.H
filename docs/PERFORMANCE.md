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
