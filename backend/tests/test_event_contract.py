from event_contract import event_contract
from main import demo_alerts
from north import normalize


def test_contract_projects_existing_fixture_without_changing_evidence():
    legacy = normalize(demo_alerts()[0])
    contract = event_contract(legacy)
    assert contract["id"] == legacy["id"]
    assert contract["ts"] == legacy["timestamp"]
    assert contract["source"] == "sysmon"
    assert contract["source_event_id"] == "1"
    assert contract["category"] == "process"
    assert contract["process"]["name"] == "powershell.exe"
    assert contract["process"]["guid"] == legacy["process_guid"]
    assert contract["raw"] == {"event_type": 1, "channel": ""}
    assert "data" in legacy["raw"]


def test_contract_bounds_fields_and_does_not_infer_missing_direction():
    alert = demo_alerts()[1]
    fields = alert["data"]["win"]["eventdata"]
    fields.update(destinationPort="443", sourcePort="99999", commandLine="x" * 6000, user="LAB\\analyst")
    contract = event_contract(normalize(alert))
    assert contract["network"]["direction"] == ""
    assert contract["network"]["dst"]["port"] == 443
    assert contract["network"]["src"]["port"] is None
    assert 0 < len(contract["process"]["cmdline"]) < 6000
    assert contract["user"]["name"] == "analyst"
    assert contract["user"]["domain"] == "LAB"
