"""Run the same NORTH synthetic benchmarks five times with fresh stores."""
import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODES = {
    "unindexed": ["--no-search-index"],
    "indexed": [],
    "indexed_with_integrity": ["--integrity"],
}


def invoke(args):
    return json.loads(subprocess.check_output(args, cwd=ROOT, text=True, encoding="utf-8", timeout=600))


def summarize(runs, fields):
    return {field: {"median": statistics.median(values), "min": min(values), "max": max(values)}
            for field in fields if (values := [run[field] for run in runs])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=20_000)
    args = parser.parse_args()
    backend = {mode: [] for mode in MODES}
    assistant = []
    for run in range(5):
        order = list(MODES)
        for mode in order[run % len(order):] + order[:run % len(order)]:
            backend[mode].append(invoke([sys.executable, "backend/benchmark_north.py", "--events", str(args.events), *MODES[mode]]))
        assistant.append(invoke(["node", "tools/Benchmark-NorthAssistant.mjs"]))
    db_fields = ("ingest_events_per_second", "rare_iris_search_median_ms", "evaluation_events_per_second")
    print(json.dumps({
        "runs_per_mode": 5,
        "backend": {mode: {"summary": summarize(runs, db_fields), "runs": runs} for mode, runs in backend.items()},
        "assistant": {"summary": summarize(assistant, ("medianMs", "p95Ms", "benchmarkProcessPeakRssMiB")), "runs": assistant},
    }, indent=2))


if __name__ == "__main__":
    main()
