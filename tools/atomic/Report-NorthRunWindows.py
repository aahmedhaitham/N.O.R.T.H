"""Match manually recorded UTC exercise windows to existing local NORTH evidence."""
import argparse
import csv
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

OUTCOMES = {"completed", "source_missing", "possible_rule_gap", "blocked_by_platform", "not_applicable"}
COLUMNS = ["technique", "start_utc", "end_utc", "outcome", "notes"]


def utc(value):
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError("Every window timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def read_windows(file, mapping):
    if file.stat().st_size > 256_000:
        raise ValueError("The run log exceeds 256 KB.")
    with file.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != COLUMNS:
            raise ValueError("Use the supplied run-log columns.")
        windows = []
        for row in reader:
            if len(windows) >= 100:
                raise ValueError("Use at most 100 recorded windows per report.")
            if None in row or any(value is None for value in row.values()):
                raise ValueError("Every run log row must have five fields.")
            technique = row["technique"].strip().upper()
            start, end = utc(row["start_utc"]), utc(row["end_utc"])
            outcome = row["outcome"].strip()
            if technique not in mapping or start >= end or outcome not in OUTCOMES or len(row["notes"]) > 512:
                raise ValueError("A run row has an unknown technique or outcome, invalid time range, or long notes.")
            windows.append((technique, start, end, outcome, row["notes"]))
    if not windows:
        raise ValueError("The run log has no recorded windows.")
    return windows


def report_runs(db, windows, mapping, *, recorded_live=False):
    reports, findings = [], {}
    limited = False
    for technique, start, end, outcome, notes in windows:
        rows = db.execute("""
            SELECT payload FROM local_detection_findings WHERE last_seen >= ? AND last_seen < ?
            ORDER BY last_seen, id LIMIT 201
        """, (start, end)).fetchall()
        limited |= len(rows) > 200
        observed = []
        for (payload,) in rows[:200] if outcome == "completed" else []:
            item = json.loads(payload)
            if item.get("rule_id") not in mapping[technique]["expected_rules"]:
                continue
            tag = "attack." + technique.lower()
            ids = item.get("evidence_ids")
            if tag not in (item.get("attack") or []) or not ids or len(ids) > 512:
                continue
            if any(not db.execute("""
                SELECT 1 FROM local_windows_events WHERE id=? AND timestamp>=? AND timestamp<?
                UNION ALL SELECT 1 FROM events WHERE id=? AND timestamp>=? AND timestamp<? LIMIT 1
            """, (identity, start, end, identity, start, end)).fetchone() for identity in ids):
                continue
            reduced = {key: item.get(key) for key in ("id", "rule_id", "last_seen", "evidence_ids", "falsepositives")}
            reduced["attack"] = [tag]
            findings[item["id"], technique] = reduced
            observed.append(item["id"])
        reports.append({"technique": technique, "start_utc": start, "end_utc": end,
                        "outcome": outcome, "notes": notes, "findings": observed,
                        "result": "observed" if observed else "unverified" if outcome == "completed" else outcome})
    return {"validation_kind": "recorded-live" if recorded_live else "recorded-review",
            "since": min(row[1] for row in windows), "until_exclusive": max(row[2] for row in windows),
            "limited": limited, "findings": list(findings.values()), "windows": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("run_log", type=Path)
    parser.add_argument("--recorded-live", action="store_true",
                        help="Mark as reviewed live evidence only after checking the original run and evidence.")
    args = parser.parse_args()
    try:
        mapping = json.loads(Path(__file__).with_name("technique-map.json").read_text(encoding="utf-8"))
        windows = read_windows(args.run_log, mapping)
        with closing(sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            report = report_runs(db, windows, mapping, recorded_live=args.recorded_live)
        encoded = json.dumps(report, ensure_ascii=True, indent=2)
        if len(encoded.encode()) > 4_000_000:
            raise ValueError("The resulting report exceeds 4 MB.")
    except (ValueError, OSError, sqlite3.Error, csv.Error, KeyError, TypeError) as error:
        parser.exit(2, "NORTH could not review the recorded windows: " + str(error) + "\n")
    print(encoded)


if __name__ == "__main__":
    main()
