import importlib.util
import io
import json
from pathlib import Path

import pytest

from detection_rules import bundled_rules, consume_detection_queue
from north import Store
from windows_sources import normalize_record

TOOLS = Path(__file__).resolve().parents[2] / "tools"


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def service():
    return {"channel": "System", "host": "WIN-SYNTHETIC", "event_id": 7045, "record_id": 1,
            "timestamp": "2026-01-15T10:00:00Z", "fields": {"ServiceName": "synthetic"}}


def test_replay_reports_mapped_events_only_and_never_claims_live_coverage():
    replay = load(TOOLS / "Replay-NorthEvtx.py")
    result = replay.replay_rows([service(), {**service(), "channel": "unrecognized"}])
    assert result["validation_kind"] == "offline-replay"
    assert result["events"] == result["skipped"] == 1
    assert result["techniques"] == {"attack.t1543.003": ["windows-service-installed"]}
    assert "synthetic" not in json.dumps(result)


def test_window_report_checks_expected_rule_and_stored_evidence(tmp_path):
    tool = load(TOOLS / "atomic" / "Report-NorthRunWindows.py")
    mapping = json.loads((TOOLS / "atomic" / "technique-map.json").read_text(encoding="utf-8"))
    csv = tmp_path / "recorded.csv"
    csv.write_text("technique,start_utc,end_utc,outcome,notes\n"
                   "T1543.003,2026-01-15T09:59:00Z,2026-01-15T10:01:00Z,completed,synthetic fixture\n",
                   encoding="utf-8")
    windows = tool.read_windows(csv, mapping)
    store = Store(path=tmp_path / "recorded.sqlite")
    store.initialize()
    evidence = normalize_record("system", service())
    store.ingest_local_windows([evidence])
    assert consume_detection_queue(store, bundled_rules()) == 1
    with store.connect() as db:
        report = tool.report_runs(db, windows, mapping)
        assert report["validation_kind"] == "recorded-review"
        assert report["windows"][0]["result"] == "observed"
        assert report["findings"][0]["evidence_ids"] == [evidence["id"]]
        db.execute("DELETE FROM local_windows_events")
        report = tool.report_runs(db, windows, mapping)
        assert report["windows"][0]["result"] == "unverified"
        assert report["findings"] == []


def test_dataset_refuses_unverified_license_and_records_pinned_provenance(tmp_path, monkeypatch):
    tool = load(TOOLS / "Get-NorthEvtxDataset.py")
    monkeypatch.setattr(tool, "fetch", lambda url: io.BytesIO(b"unknown license"))
    with pytest.raises(ValueError, match="license"):
        tool.download("a" * 40, "sample.evtx", tmp_path)
    assert not list(tmp_path.iterdir())
    data = b"ElfFile\x00synthetic"
    monkeypatch.setattr(tool, "fetch", lambda url: io.BytesIO(
        b"GNU GENERAL PUBLIC LICENSE Version 3" if url.endswith("LICENSE.GPL") else data))
    report = tool.download("a" * 40, "sample.evtx", tmp_path)
    assert report["license"] == "GPL-3.0"
    assert report["bytes"] == len(data)
    assert json.loads((tmp_path / "sample.evtx.provenance.json").read_text()) == report
    assert (tmp_path / "sample.evtx").read_bytes() == data
