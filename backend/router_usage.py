"""Read device byte totals from an explicitly configured OpenWrt router."""

import asyncio
import csv
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from io import StringIO
from ipaddress import IPv4Address
from time import time

from starlette.concurrency import run_in_threadpool


def parse_totals(output):
    rows = csv.DictReader(StringIO(output))
    if not {"mac", "rx_bytes", "tx_bytes"} <= set(rows.fieldnames or []):
        raise ValueError("Unsupported nlbw output")
    totals = []
    for row in rows:
        mac = row["mac"].lower()
        if not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac) or mac == "00:00:00:00:00:00":
            continue
        counts = [row[field] for field in ("rx_bytes", "tx_bytes")]
        if not all(value and re.fullmatch(r"[0-9]{1,16}", value) and int(value) <= 2**53 - 1 for value in counts):
            raise ValueError("Invalid router byte counter")
        rx, tx = map(int, counts)
        totals.append({"mac": mac, "download_bytes": rx, "upload_bytes": tx})
    return sorted(totals, key=lambda item: -(item["download_bytes"] + item["upload_bytes"]))[:64]


def read_router(alias, command):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}", alias):
        raise ValueError("Invalid SSH host alias")
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    result = subprocess.run([
        "ssh", "-n", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=5", alias, command,
    ], capture_output=True, check=True, encoding="utf-8", timeout=12, **options)
    if len(result.stdout) > 1_000_000:
        raise ValueError("Oversized router response")
    return result.stdout


def read_totals(alias):
    devices = parse_totals(read_router(alias, "nlbw -c csv -g mac -o mac -s ,"))
    try:
        leases = read_router(alias, "cat /tmp/dhcp.leases")
    except (OSError, ValueError, subprocess.SubprocessError):
        leases = ""
    try:
        stations = read_router(
            alias,
            """for iface in $(iw dev | awk '$1 == "Interface" {iface=$2} $1 == "type" && $2 == "AP" {print iface}'); do iw dev "$iface" station dump; done""",
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        stations = ""
    wireless = set(re.findall(r"^station ((?:[a-f0-9]{2}:){5}[a-f0-9]{2})\s", stations.lower(), re.M))
    names = {}
    lease_ips = {}
    now = time()
    for line in leases.splitlines():
        parts = line.split()
        if len(parts) < 4 or not re.fullmatch(r"[0-9]{1,16}", parts[0]):
            continue
        expiry = int(parts[0])
        if expiry and expiry <= now:
            continue
        try:
            address = str(IPv4Address(parts[2]))
        except ValueError:
            continue
        mac = parts[1].lower()
        lease_ips.setdefault(mac, set()).add(address)
        if parts[3] != "*" and re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", parts[3]):
            names.setdefault(mac, set()).add(parts[3])
    for item in devices:
        labels = names.get(item["mac"], set())
        if len(labels) == 1:
            item["router_name"] = next(iter(labels))
        if item["mac"] in lease_ips:
            item["router_ips"] = sorted(lease_ips[item["mac"]])[:8]
        if item["mac"] in wireless:
            item["wifi_associated"] = True
    return devices


class RouterUsage:
    def __init__(self, alias, store=None, scope=None):
        self.alias = alias
        self.store = store
        self.scope = scope
        self._baseline_ready = False
        self.current = {"state": "starting", "updated_at": None, "devices": []}

    async def restore(self):
        if not self.store:
            return
        try:
            saved = await run_in_threadpool(self.store.router_traffic, self.scope)
            if saved:
                self.current = {**saved, "state": "unavailable"}
        except (OSError, ValueError, sqlite3.Error):
            pass

    def record(self, devices, observed_at):
        previous = {item["mac"]: item for item in self.current["devices"]}
        for device in devices:
            earlier = previous.get(device["mac"])
            if not earlier:
                continue
            downloaded = device["download_bytes"] - earlier["download_bytes"]
            uploaded = device["upload_bytes"] - earlier["upload_bytes"]
            history = earlier.get("recent_usage", [])
            if self._baseline_ready and downloaded >= 0 and uploaded >= 0:
                history = [*history[-11:], {
                    "from": self.current["updated_at"], "to": observed_at,
                    "download_bytes": downloaded, "upload_bytes": uploaded,
                }]
            if history:
                device["recent_usage"] = history
        self.current = {"state": "ready", "updated_at": observed_at, "devices": devices}
        self._baseline_ready = True

    async def run(self):
        while True:
            try:
                devices = await run_in_threadpool(read_totals, self.alias)
            except (OSError, ValueError, subprocess.SubprocessError):
                self.current = {**self.current, "state": "unavailable"}
                self._baseline_ready = False
            else:
                self.record(devices, datetime.now(timezone.utc).isoformat())
                if self.store:
                    try:
                        await run_in_threadpool(self.store.record_router_traffic, self.scope, self.current)
                    except (OSError, sqlite3.Error):
                        pass
            await asyncio.sleep(60)
