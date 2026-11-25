import json
from urllib.error import URLError

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
from north import Store


def test_seed_websocket_report_and_offline_draft(tmp_path, monkeypatch):
    monkeypatch.setenv("NORTH_SEED_DEMO", "1")

    def unavailable(*args, **kwargs):
        raise URLError("offline")

    monkeypatch.setattr(main, "urlopen", unavailable)
    with TestClient(main.make_app(Store(path=tmp_path / "test.sqlite3"))) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        case, = client.get("/api/cases").json()
        for _ in range(2):
            with client.websocket_connect("/api/live") as socket:
                assert socket.receive_json() == [case]
        url = "/api/cases/" + case["id"]
        assert client.post(url + "/draft").status_code == 503
        report = client.get(url + "/report")
        assert report.status_code == 200
        assert all(item["id"] in report.text for item in case["evidence"])
        assert client.post("/api/ingest", json={"alerts": [{}]}).status_code == 422


def test_draft_requires_case_evidence():
    payload = {"response": json.dumps({"claims": [{"text": "Observed activity", "evidence_ids": ["a"]}]})}
    assert main.validated_draft(payload, {"a"})["claims"][0]["evidence_ids"] == ["a"]
    with pytest.raises(HTTPException) as error:
        main.validated_draft(payload, {"b"})
    assert error.value.status_code == 502
