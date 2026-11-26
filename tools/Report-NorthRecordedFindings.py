"""Summarize detection evidence for an already recorded, isolated test window."""

import argparse
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def utc(value):
    instant = datetime.fromisoformat(value)
    if instant.utcoffset() is None:
        raise ValueError("Use a timestamp with a UTC offset")
    return instant.astimezone(timezone.utc).isoformat(timespec="microseconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="Copy of the NORTH local findings database")
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()
    try:
        since, until = utc(args.since), utc(args.until)
        if not args.database.is_file() or since >= until or not 1 <= args.limit <= 1000:
            raise ValueError("Use an existing database, increasing timestamps, and a limit from 1 to 1,000")
    except ValueError as error:
        parser.error(str(error))

    with closing(sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        rows = db.execute(
            "SELECT payload FROM local_detection_findings WHERE last_seen >= ? AND last_seen < ? "
            "ORDER BY last_seen, id LIMIT ?", (since, until, args.limit + 1),
        ).fetchall()
    findings = []
    for (payload,) in rows[:args.limit]:
        item = json.loads(payload)
        findings.append({key: item.get(key) for key in
                         ("id", "rule_id", "attack", "last_seen", "evidence_ids", "falsepositives")})
    print(json.dumps({"since": since, "until_exclusive": until, "limited": len(rows) > args.limit,
                      "findings": findings}, indent=2))


if __name__ == "__main__":
    main()
