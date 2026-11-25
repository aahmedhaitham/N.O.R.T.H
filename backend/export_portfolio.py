"""Export only the bundled cases and reports for static portfolio hosting."""

import argparse
import json
from pathlib import Path

from main import demo_alerts
from device_watch import demo_findings
from network import app_connections, snapshot
from north import build_cases, normalize, report


def export(directory: Path):
    events = [normalize(alert) for alert in demo_alerts(include_linux=True)]
    cases = build_cases(events)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
    (directory / "events.json").write_text(json.dumps(events), encoding="utf-8")
    findings = demo_findings()
    sample_time = findings["baseline_at"]
    records = [
        {"address": "192.0.2.42", "mac": "02:00:00:00:00:42", "network": "Demo LAN",
         "state": "Reachable", "name": "Demo workstation"},
        {"address": "192.0.2.1", "mac": "02:00:00:00:00:01", "network": "Demo LAN",
         "state": "Reachable", "name": "Demo gateway"},
        {"address": "198.51.100.24", "mac": "02:00:00:00:00:24", "network": "Demo Wi-Fi",
         "state": "Stale", "name": "Demo wireless device"},
    ]
    (directory / "network.json").write_text(
        json.dumps({
            **snapshot(events), "device_findings": findings,
            "neighbors": {"state": "ready", "updated_at": sample_time, "records": records},
            "internet_health": [
                {"checked_at": sample_time, "gateway": "responded", "dns_ms": 19, "https_ms": 72, "http_status": 200},
                {"checked_at": findings["items"][0]["first_seen"], "gateway": "responded",
                 "dns_ms": 26, "https_ms": 83, "http_status": 200},
            ],
            "app_connections": app_connections(events, "WIN-LAB-01"),
            "adapter_traffic": {"state": "ready", "updated_at": sample_time, "adapters": [
                {"name": "Demo LAN", "received_bytes": 81_000_000, "sent_bytes": 22_000_000,
                 "receive_rate": 120_000, "send_rate": 18_000, "recent_rates": [
                     {"sampled_at": "2026-01-15T09:59:30+00:00", "receive_rate": 40_000, "send_rate": 14_000},
                     {"sampled_at": sample_time, "receive_rate": 120_000, "send_rate": 18_000},
                 ]},
            ]},
            "router_usage": {"state": "ready", "updated_at": sample_time, "devices": [
                {"mac": records[0]["mac"], "download_bytes": 128_000_000, "upload_bytes": 24_000_000,
                 "recent_usage": [
                     {"from": sample_time, "to": "2026-01-15T10:01:00+00:00",
                      "download_bytes": 4_000_000, "upload_bytes": 900_000},
                     {"from": "2026-01-15T10:01:00+00:00", "to": "2026-01-15T10:02:00+00:00",
                      "download_bytes": 9_000_000, "upload_bytes": 1_500_000},
                 ]},
                {"mac": records[2]["mac"], "download_bytes": 32_000_000, "upload_bytes": 8_000_000,
                 "wifi_associated": True},
            ]},
        }), encoding="utf-8",
    )
    for case in cases:
        (directory / f"{case['id']}.md").write_text(report(case), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    export(parser.parse_args().directory)
