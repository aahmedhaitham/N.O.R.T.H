"""Verify a running NORTH demo through its HTTP and WebSocket gateway."""

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from websockets.sync.client import connect


def read_json(url, data=None):
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def verify(base):
    origin = urlsplit(base)
    websocket_url = urlunsplit((
        "wss" if origin.scheme == "https" else "ws", origin.netloc, "/api/live", "", "",
    ))
    with urlopen(base, timeout=10) as response:
        assert b"NORTH" in response.read(), "Frontend index did not contain the NORTH title"
    assert read_json(base + "/api/health") == {"status": "ok"}
    case, = read_json(base + "/api/cases")
    assert [item["kind"] for item in case["evidence"]] == [1, 3, 11]
    assert case["links"][0]["evidence_id"] == case["evidence"][1]["id"]

    for _ in range(2):
        with connect(websocket_url, origin=base, open_timeout=10, close_timeout=5) as socket:
            assert json.loads(socket.recv(timeout=10)) == [case]

    with urlopen(base + f"/api/cases/{case['id']}/report", timeout=10) as response:
        report = response.read().decode()
        assert "attachment" in response.headers["Content-Disposition"]
        assert all(item["id"] in report for item in case["evidence"])

    fixture = Path(__file__).with_name("fixtures") / "demo.json"
    alerts = json.loads(fixture.read_text(encoding="utf-8"))
    assert read_json(base + "/api/ingest", json.dumps({"alerts": alerts}).encode()) == {
        "inserted": 0,
    }
    print("NORTH demo verified: index, health, evidence, WebSocket reconnect, report, and deduplication.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="URL of the running NORTH console")
    verify(parser.parse_args().base_url.rstrip("/"))
