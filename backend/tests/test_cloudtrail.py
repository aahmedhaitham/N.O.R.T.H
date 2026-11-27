import gzip
import json

import pytest

from cloudtrail import ImportError, import_export, read_export
from event_contract import event_contract
from north import Store


def fixture():
    return {"Records": [{
        "eventID": "12345678-0000-4000-8000-123456789abc",
        "eventTime": "2026-01-15T10:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/fixture",
                         "accessKeyId": "synthetic-key-marker", "sessionToken": "synthetic-token-marker"},
        "sourceIPAddress": "192.0.2.10", "awsRegion": "us-east-1", "errorCode": "AccessDenied",
        "requestParameters": {"SessionToken": "synthetic-request-marker"},
    }]}


@pytest.mark.parametrize("compressed", [False, True])
def test_offline_cloudtrail_import_is_local_and_deduplicated(tmp_path, compressed):
    source = tmp_path / "fixture"
    content = json.dumps(fixture()).encode()
    source.write_bytes(gzip.compress(content) if compressed else content)
    store = Store(path=tmp_path / "events.sqlite3")
    store.initialize()
    report = import_export(store, source)
    assert report["inserted"] == 1
    assert import_export(store, source)["inserted"] == 0
    assert report["regions"] == ["us-east-1"]
    stored, = store.local_windows_events()
    assert store.events() == []
    event = event_contract(stored)
    assert event["source"] == "cloudtrail"
    assert event["cloudtrail"] == {
        "event_source": "signin.amazonaws.com", "event_name": "ConsoleLogin",
        "identity_type": "IAMUser", "identity_arn": "arn:aws:iam::111122223333:user/fixture",
        "region": "us-east-1", "error_code": "AccessDenied",
    }
    assert event["network"]["src"]["ip"] == "192.0.2.10"
    assert "synthetic-" not in json.dumps(stored)


def test_cloudtrail_rejects_invalid_and_oversized_exports(tmp_path, monkeypatch):
    source = tmp_path / "fixture"
    for content in (b'{', b'{}', b'{"Records":[null]}', b'\x1f\x8b'):
        source.write_bytes(content)
        with pytest.raises(ImportError, match="CloudTrail"):
            read_export(source)
    monkeypatch.setattr("cloudtrail.MAX_FILE", 128)
    source.write_bytes(b"x" * 129)
    with pytest.raises(ImportError, match="file limit"):
        read_export(source)
    monkeypatch.setattr("cloudtrail.MAX_JSON", 128)
    source.write_bytes(gzip.compress(b"x" * 129))
    with pytest.raises(ImportError, match="expanded"):
        read_export(source)
