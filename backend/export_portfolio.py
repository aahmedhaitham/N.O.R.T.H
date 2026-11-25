"""Export only the bundled cases and reports for static portfolio hosting."""

import argparse
import json
from pathlib import Path

from main import demo_alerts
from north import build_cases, normalize, report


def export(directory: Path):
    cases = build_cases([normalize(alert) for alert in demo_alerts(include_linux=True)])
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
    for case in cases:
        (directory / f"{case['id']}.md").write_text(report(case), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    export(parser.parse_args().directory)
