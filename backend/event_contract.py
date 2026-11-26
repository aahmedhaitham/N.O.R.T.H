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
    4104: ("script", "observe"),
    4624: ("authentication", "success"),
    4625: ("authentication", "failure"),
    4688: ("process", "start"),
    4698: ("task", "create"),
    7045: ("service", "install"),
    1116: ("antimalware", "detect"),
    1117: ("antimalware", "remediate"),
    1118: ("antimalware", "remediation_failed"),
    1119: ("antimalware", "remediation_failed"),
    5001: ("antimalware", "disable"),
    5007: ("antimalware", "configuration_change"),
    2001: ("network", "listen"),
    2002: ("network", "neighbor_first_seen"),
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


def _process_id(value):
    if isinstance(value, str) and value.casefold().startswith("0x") and 2 < len(value) <= 10:
        try:
            return _integer(int(value, 16), 4294967295)
        except ValueError:
            return None
    return _integer(value, 4294967295)


def event_contract(event):
    """Project an existing normalized event onto typed, bounded local fields."""
    raw = _mapping(event.get("raw"))
    windows = _mapping(_mapping(raw.get("data")).get("win"))
    system = _mapping(windows.get("system"))
    fields = _mapping(windows.get("eventdata"))
    local_source = event.get("source")
    if local_source:
        fields = {key[:1].lower() + key[1:]: value for key, value in raw.items()}
    kind = event["kind"]
    category, action = _CLASSIFICATIONS.get(kind, ("other", "observe"))
    journal = kind in (1001, 1002)
    process_path = _text(fields.get("image") or fields.get("newProcessName") or fields.get("imagePath") or event.get("process"))
    parent_path = _text(fields.get("parentImage"))
    username = _text(fields.get("user"), 512)
    domain, separator, name = username.partition("\\")
    initiated = _text(fields.get("initiated"), 12).casefold()
    direction = "inbound" if kind == 1001 else ""
    if kind == 3:
        direction = {"true": "outbound", "false": "inbound"}.get(initiated, "")
    record_id = event.get("source_event_id", system.get("eventRecordID"))
    if type(record_id) is int:
        record_id = str(record_id)
    return {
        "id": event["id"],
        "ts": event["timestamp"],
        "source": local_source or ("journalctl" if journal else "sysmon"),
        "source_event_id": _text(record_id, 256),
        "category": category,
        "action": action,
        "host": _text(event.get("host"), 512),
        "asset_id": _text(event.get("asset_id"), 512),
        "process": {
            "guid": _text(event.get("process_guid") or fields.get("processGuid"), 128),
            "pid": _process_id(fields.get("processId") or fields.get("newProcessId")),
            "name": PureWindowsPath(process_path).name,
            "path": process_path,
            "cmdline": _text(fields.get("commandLine")),
            "parent_guid": _text(event.get("parent_guid") or fields.get("parentProcessGuid"), 128),
            "parent_name": PureWindowsPath(parent_path).name,
            "parent_path": parent_path,
            "parent_cmdline": _text(fields.get("parentCommandLine")),
            "target_path": _text(fields.get("targetImage")),
            "loaded_image": _text(fields.get("imageLoaded")),
            "user": username,
        },
        "user": {
            "name": _text(fields.get("targetUserName"), 512) or (name if separator else username),
            "domain": _text(fields.get("targetDomainName"), 512) or (domain if separator else ""),
            "sid": _text(fields.get("targetUserSid") or fields.get("userSid"), 256),
        },
        "network": {
            "direction": direction,
            "protocol": _text(fields.get("protocol"), 32).lower(),
            "src": {"ip": _text(fields.get("sourceIp") or fields.get("ipAddress") or event.get("source_ip"), 64),
                    "port": _integer(fields.get("sourcePort") or fields.get("ipPort"), 65535)},
            "dst": {"ip": _text(fields.get("destinationIp") or event.get("destination"), 64),
                    "port": _integer(fields.get("destinationPort"), 65535)},
            **({"local": {"ip": _text(fields.get("localAddress"), 64),
                           "port": _integer(fields.get("localPort"), 65535)}} if kind == 2001 else {}),
        },
        "file": {"path": _text(event.get("target") or fields.get("targetFilename")) if kind == 11 else ""},
        "registry": {"target": _text(fields.get("targetObject"))},
        "dns": {"query": _text(fields.get("queryName"), 253)},
        **({"neighbor": {"interface": _text(fields.get("interface"), 256),
                         "mac": _text(fields.get("mac"), 32),
                         "addresses": [_text(address, 64) for address in fields.get("addresses", [])[:12]]}}
           if kind == 2002 else {}),
        "raw": {"event_type": kind, "channel": _text(system.get("channel"), 128),
                **({"logon_type": _text(fields.get("logonType"), 12)} if fields.get("logonType") else {})},
    }
