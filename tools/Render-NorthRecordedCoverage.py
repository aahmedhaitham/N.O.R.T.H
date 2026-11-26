"""Render an observational Markdown table from a saved NORTH findings report."""

import argparse
import json
from pathlib import Path


def cell(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("\n", " ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    if args.report.stat().st_size > 4_000_000:
        parser.error("Report exceeds 4 MB")
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    print("# Recorded NORTH detections\n")
    print(f"Window {cell(report['since'])} through {cell(report['until_exclusive'])} (exclusive).\n")
    if report["limited"]:
        print("The report reached its row limit.\n")
    findings = report["findings"]
    if not findings:
        print("No findings were recorded in this window. Detection coverage is unverified.")
        return
    print("| Technique | Rule | Finding observed | Evidence IDs | False-positive notes |")
    print("|---|---|---|---|---|")
    for item in findings:
        tags = ", ".join(item["attack"] or [])
        evidence = ", ".join(item["evidence_ids"] or [])
        notes = "; ".join(item["falsepositives"] or [])
        print(f"| {cell(tags)} | {cell(item['rule_id'])} | Yes | {cell(evidence)} | {cell(notes)} |")


if __name__ == "__main__":
    main()
