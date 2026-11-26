"""Require the published detection table to match its recorded results."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

START = "<!-- north-coverage:start -->"
END = "<!-- north-coverage:end -->"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--document", type=Path, default=Path("docs/COVERAGE.md"))
    parser.add_argument("--results", type=Path, default=Path("docs/coverage-results.json"))
    args = parser.parse_args()
    text = args.document.read_text(encoding="utf-8-sig")
    if text.count(START) != 1 or text.count(END) != 1 or text.index(START) > text.index(END):
        parser.error("The document must contain one coverage block")
    before, remainder = text.split(START)
    table, after = remainder.split(END)
    if any(line.lstrip().startswith("|") for line in (before + after).splitlines()):
        parser.error("Coverage table rows must be inside the checked block")
    if not args.results.is_file():
        if table.strip() or "not yet run" not in before:
            parser.error("No results file exists. Keep the block empty and mark coverage not yet run")
        print("Coverage is marked not yet run. No results are claimed.")
        return
    if args.results.stat().st_size > 4_000_000:
        parser.error("Results exceed 4 MB")
    report = json.loads(args.results.read_text(encoding="utf-8-sig"))
    if report.get("validation_kind") != "recorded-live" or not report.get("findings") or report.get("limited"):
        parser.error("Coverage requires a complete, reviewed live report with findings")
    rendered = subprocess.check_output(
        [sys.executable, str(Path(__file__).with_name("Render-NorthRecordedCoverage.py")), str(args.results)],
        encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    expected = "\n".join(line for line in rendered.splitlines() if line.startswith("|"))
    if table.strip() != expected or "not yet run" in before:
        parser.error("Coverage does not match the recorded report")
    print("Coverage table matches the recorded report.")


if __name__ == "__main__":
    main()
