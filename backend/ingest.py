"""Import sanitized Sysmon alerts from a Wazuh JSON array or JSON Lines export."""

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    try:
        content = args.export.read_text(encoding="utf-8-sig").strip()
        alerts = (
            json.loads(content) if content.startswith("[")
            else [json.loads(line) for line in content.splitlines() if line.strip()]
        )
        if not 1 <= len(alerts) <= 1000:
            parser.error("Each export must contain 1 to 1000 supported alerts")
        request = Request(
            args.base_url.rstrip("/") + "/api/ingest",
            data=json.dumps({"alerts": alerts}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=30) as response:
            inserted = json.load(response)["inserted"]
    except HTTPError as exc:
        parser.exit(1, f"Import failed (HTTP {exc.code}): {exc.read().decode(errors='replace')}\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Import failed: {exc}\n")
    print(f"Imported {inserted} new alerts out of {len(alerts)}.")


if __name__ == "__main__":
    main()
