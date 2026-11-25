from main import demo_alerts
from network import snapshot
from north import normalize


def test_inventory_separates_connections_and_links_investigations():
    events = [normalize(alert) for alert in demo_alerts(include_linux=True)]
    inventory = snapshot(events[::-1])
    assert inventory == snapshot(events)
    assets = {asset["host"]: asset for asset in inventory["assets"]}
    assert assets["WIN-LAB-01"]["events"] == assets["KALI-DEMO"]["events"] == 3
    outbound, inbound = inventory["links"]
    assert outbound["direction"] == "outbound"
    assert inbound["direction"] == "inbound"
    assert outbound["events"] == 1 and inbound["events"] == 3
    assert outbound["cases"] == assets["WIN-LAB-01"]["cases"]
    assert inbound["cases"] == assets["KALI-DEMO"]["cases"]


def test_inventory_keeps_connections_with_no_correlated_incident():
    event = normalize(demo_alerts()[1])
    inventory = snapshot([event])
    assert inventory["links"][0]["address"] == event["destination"]
    assert inventory["links"][0]["cases"] == []
