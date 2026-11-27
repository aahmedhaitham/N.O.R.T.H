"""Reproducible NORTH SQLite benchmark using generated observations only."""

import argparse
import json
import platform
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from detection_rules import bundled_rules, evaluate_rules
from event_contract import event_contract
from north import Store


def synthetic_event(index):
    timestamp = datetime(2026, 1, 15, tzinfo=timezone.utc) + timedelta(milliseconds=index)
    return {
        "agent": {"id": "synthetic", "name": "NORTH-BENCH"},
        "data": {"win": {"system": {"eventRecordID": str(index), "systemTime": timestamp.isoformat(), "eventID": 1},
                         "eventdata": {"image": r"C:\Example\rare-benchmark.exe" if index == 1 else r"C:\Example\inventory.exe"}}},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=500_000, metavar="1..500000")
    parser.add_argument("--integrity", action="store_true", help="Enable the SQLite evidence chain for synthetic events")
    args = parser.parse_args()
    rows = args.events
    if not 1 <= rows <= 500_000:
        parser.error("--events must be between 1 and 500000")
    with TemporaryDirectory(prefix="north-benchmark-") as temporary:
        store = Store(path=Path(temporary) / "benchmark.sqlite3", integrity_key=b"x" * 32 if args.integrity else None)
        store.initialize()
        start = perf_counter()
        for first in range(1, rows + 1, 1000):
            store.ingest([synthetic_event(index) for index in range(first, min(rows + 1, first + 1000))], enqueue=False)
        ingest = perf_counter() - start
        search = []
        for _ in range(7):
            start = perf_counter()
            result = store.event_page(search="rare-benchmark.exe")
            search.append((perf_counter() - start) * 1000)
            assert len(result["events"]) == 1
        sample = [event_contract(event) for event in store.event_page(limit=500)["events"]]
        rules = bundled_rules()
        start = perf_counter()
        for _ in range(10):
            evaluate_rules(rules, sample)
        rule_seconds = perf_counter() - start
        print(json.dumps({
            "platform": platform.platform(), "python": platform.python_version(), "events": rows, "integrity": args.integrity,
            "ingest_events_per_second": round(rows / ingest, 1),
            "rare_iris_search_median_ms": round(statistics.median(search), 2),
            "rules": len(rules), "evaluation_events_per_second": round(len(sample) * 10 / rule_seconds, 1),
        }, indent=2))


if __name__ == "__main__":
    main()
