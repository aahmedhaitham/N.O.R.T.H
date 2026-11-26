"""Derive the local rule-engine contract without changing stored evidence."""

from pathlib import PureWindowsPath


_CLASSIFICATIONS = {
    1: ("process", "start"),
    3: ("network", "connect"),
    7: ("process", "image_load"),
    8: ("process", "remote_thread"),
    10: ("process", "access"),
    11: ("file", "create"),
    13: ("registry", "set_value"),
    22: ("dns", "query"),
    1001: ("authentication", "failure"),
    1002: ("privilege", "sudo"),
}


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _text(value, length=4096):
    return value[:length] if isinstance(value, str) else ""


def _integer(value, limit):
    if type(value) is int:
        return value if 0 <= value <= limit else None
    if isinstance(value, str) and len(value) <= 10 and value.isascii() and value.isdecimal():
        number = int(value)
        return number if number <= limit else None
    return None


def event_contract(event):
    """Project an existing normalized event onto typed, bounded local fields."""
    raw = _mapping(event.get("raw"))
    windows = _mapping(_mapping(raw.get("data")).get("win"))
    system = _mapping(windows.get("system"))
    fields = _mapping(windows.get("eventdata"))
    kind = event["kind"]
    category, action = _CLASSIFICATIONS.get(kind, ("other", "observe"))
    journal = kind in (1001, 1002)
    process_path = _text(fields.get("image", event.get("process")))
    parent_path = _text(fields.get("parentImage"))
    username = _text(fields.get("user"), 512)
    domain, separator, name = username.partition("\\")
    initiated = _text(fields.get("initiated"), 12).casefold()
    direction = "inbound" if kind == 1001 else ""
    if kind == 3:
        direction = {"true": "outbound", "false": "inbound"}.get(initiated, "")
    record_id = system.get("eventRecordID")
    if type(record_id) is int:
        record_id = str(record_id)
    return {
        "id": event["id"],
        "ts": event["timestamp"],
        "source": "journalctl" if journal else "sysmon",
        "source_event_id": _text(record_id, 256),
        "category": category,
        "action": action,
        "host": _text(event.get("host"), 512),
        "process": {
            "guid": _text(event.get("process_guid"), 128),
            "pid": _integer(fields.get("processId"), 4294967295),
            "name": PureWindowsPath(process_path).name,
            "path": process_path,
            "cmdline": _text(fields.get("commandLine")),
            "parent_guid": _text(event.get("parent_guid"), 128),
            "parent_name": PureWindowsPath(parent_path).name,
            "parent_cmdline": _text(fields.get("parentCommandLine")),
            "user": username,
        },
        "user": {
            "name": name if separator else username,
            "domain": domain if separator else "",
            "sid": _text(fields.get("userSid"), 256),
        },
        "network": {
            "direction": direction,
            "protocol": _text(fields.get("protocol"), 32).lower(),
            "src": {"ip": _text(fields.get("sourceIp", event.get("source_ip")), 64),
                    "port": _integer(fields.get("sourcePort"), 65535)},
            "dst": {"ip": _text(event.get("destination"), 64),
                    "port": _integer(fields.get("destinationPort"), 65535)},
        },
        "file": {"path": _text(event.get("target")) if kind == 11 else ""},
        "registry": {"target": _text(fields.get("targetObject"))},
        "dns": {"query": _text(fields.get("queryName"), 253)},
        "raw": {"event_type": kind, "channel": _text(system.get("channel"), 128)},
    }
