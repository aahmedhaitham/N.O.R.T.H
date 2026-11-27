# NORTH performance benchmark

Measured on AMD Ryzen 5 7235HS, 8 logical processors,
11.7 GiB visible RAM, win32 10.0.26300, Python 3.14.10,
and Node v26.7.0. The [raw results](performance-results.json) include every run.

## Local SQLite and detections

Each mode used 5 fresh databases with 20,000 synthetic events,
1,000-event ingestion batches, and the detection queue disabled for the ingest
measurement. The runner rotates mode order. Search is a rare-match query against
the event store, with seven measurements per run. Rule evaluation applies
63 bundled rules to a 500-event sample.

Values are median (observed minimum–maximum). Search values summarize each
run's median search latency.

| Mode | Ingest, events/sec | Rare search, ms | Rule evaluation, events/sec |
| --- | ---: | ---: | ---: |
| Unindexed | 21,923.5 (17,575.9–23,175.7) | 38.35 (36.42–46.77) | 14,366.2 (4,446.0–15,786.3) |
| Search index | 2,595.6 (2,115.9–2,649.1) | 4.76 (4.12–5.64) | 9,948.4 (6,957.7–10,115.5) |
| Search index and evidence chain | 1,832.9 (1,623.6–2,062.7) | 4.74 (3.43–5.21) | 8,921.4 (8,138.9–10,662.5) |

The index made this query about 8.1× faster, with an 88% lower
median ingestion rate. The integrity chain reduced median indexed ingestion by
a further 29%. Rule evaluation runs on projected events in memory.
Its between-mode variation is a measure of run variability. These workloads
do not measure production throughput or UI response time.

## Assistant routing performance

Each of 5 runs measured 690 timed intent matches after warm-up.

| Metric | Median across runs (range) |
| --- | ---: |
| Per-run median latency, ms | 1.919 (1.709–2.228) |
| Per-run p95 latency, ms | 3.626 (2.941–5.350) |
| Process peak RSS, MiB | 73.2 (69.4–73.4) |

See [held-out routing results](assistant-routing-results.json) for the separate
accuracy evaluation. Packaged startup and desktop working set for this
candidate remain unmeasured.

## Reproduce

Run from the repository root:

```powershell
& ./backend/.venv/Scripts/python.exe tools/Benchmark-North.py --events 20000
```
