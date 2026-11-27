"""Replay saved Windows EVTX observations through NORTH without running the recorded activity."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from detection_rules import bundled_rules, evaluate_rules
from event_contract import event_contract
from windows_sources import SOURCE_EVENTS, normalize_record


CHANNELS = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "system": "system",
    "microsoft-windows-powershell/operational": "powershell",
    "microsoft-windows-windows defender/operational": "defender",
}


def replay_rows(rows):
    evidence = {}
    skipped = 0
    for index, row in enumerate(rows, start=1):
        if index > 10_000:
            raise ValueError("Replay accepts at most 10,000 records per exported log.")
        if not isinstance(row, dict):
            raise ValueError("The replay reader returned an invalid record.")
        source = CHANNELS.get(str(row.get("channel")).casefold())
        if source is None or row.get("event_id") not in SOURCE_EVENTS[source]:
            skipped += 1
            continue
        event = normalize_record(source, row)
        event["asset_id"] = hashlib.sha256(event["host"].casefold().encode()).hexdigest()[:24]
        evidence[event["id"]] = event_contract(event)
    result = evaluate_rules(bundled_rules(), list(evidence.values()))
    techniques = {}
    for match in result["matches"]:
        for technique in match["attack"]:
            techniques.setdefault(technique, []).append(match["rule_id"])
    return {"validation_kind": "offline-replay", "events": len(evidence), "skipped": skipped,
            "techniques": dict(sorted(techniques.items())), "timed_out_rule_ids": result["timed_out_rule_ids"]}


def read_rows(file):
    if sys.platform != "win32":
        raise ValueError("EVTX replay requires the Windows event reader.")
    if not file.is_file() or file.suffix.lower() != ".evtx" or file.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Choose a local EVTX file no larger than 128 MiB.")
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    with tempfile.TemporaryFile() as output:
        command = [str(powershell), "-NoProfile", "-NonInteractive", "-File",
                   str(Path(__file__).with_name("Read-NorthEvtx.ps1")), "-LogPath", str(file.resolve())]
        subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL, check=True, timeout=90)
        output.seek(0)
        while line := output.readline(1_000_001):
            if len(line) > 1_000_000:
                raise ValueError("A Windows event exceeds the replay size limit.")
            yield json.loads(line.decode("utf-8-sig"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        result = replay_rows(read_rows(args.file))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        parser.exit(2, "NORTH could not replay this EVTX export. Check Windows access, format, and size.\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
