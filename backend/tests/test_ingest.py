import json
from copy import deepcopy
from pathlib import Path

import pytest

from ingest import prepare
from north import Store, build_cases


def fixture():
    source = Path(__file__).parents[1] / "fixtures" / "demo.json"
    return json.loads(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize("format", ["array", "lines", "search"])
def test_wazuh_export_formats_build_the_same_case(format, tmp_path):
    demo = fixture()
    unrelated = {"agent": {"id": "001"}, "data": {"win": {"system": {
        "eventID": "1", "channel": "System",
    }}}}
    records = [unrelated, *reversed(demo)]
    if format == "lines":
        document = "\n".join(json.dumps(item) for item in records)
    elif format == "search":
        document = json.dumps({"hits": {"hits": [{"_source": item} for item in records]}})
    else:
        document = json.dumps(records)

    alerts, events, skipped = prepare(document)
    assert (len(events), skipped) == (3, 1)
    store = Store(path=tmp_path / "preview.sqlite3")
    store.initialize()
    assert store.ingest(alerts) == 3
    assert store.ingest(alerts) == 0
    case, = build_cases(store.events())
    assert [event["kind"] for event in case["evidence"]] == [1, 3, 11]


def test_invalid_supported_event_is_reported_before_import():
    records = deepcopy(fixture())
    del records[1]["agent"]["id"]
    with pytest.raises(ValueError, match="record 2"):
        prepare(json.dumps(records))
