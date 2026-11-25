"""Check DNS and HTTPS for the collector's configured NORTH Cloud origin."""

import asyncio
import json
import logging
import socket
import ssl
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from ipaddress import IPv4Address
from time import monotonic
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from starlette.concurrency import run_in_threadpool

from cloud_sync import NoRedirects


def check_gateway():
    windows = sys.platform == "win32"
    if not windows and not sys.platform.startswith("linux"):
        return "unknown"
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if windows else {}
    route = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object NextHop -ne '0.0.0.0' | "
        "Sort-Object RouteMetric | Select-Object -First 1).NextHop",
    ] if windows else ["ip", "-j", "-4", "route", "show", "default"]
    try:
        output = subprocess.check_output(route, text=True, timeout=8, stderr=subprocess.DEVNULL, **options)
        address = output.strip() if windows else next(
            (item["gateway"] for item in json.loads(output) if item.get("gateway")), "",
        )
        gateway = str(IPv4Address(address))
        if windows:
            status = subprocess.check_output([
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                f"([Net.NetworkInformation.Ping]::new().Send('{gateway}', 1500)).Status",
            ], text=True, timeout=6, stderr=subprocess.DEVNULL, **options)
            return "responded" if status.strip() == "Success" else "no_reply"
        result = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "2", gateway],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4, **options,
        )
        return "responded" if result.returncode == 0 else "no_reply" if result.returncode == 1 else "unknown"
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unknown"


def check_origin(origin):
    destination = urlsplit(origin)
    if (destination.scheme != "https" or not destination.hostname or destination.username or destination.password
            or destination.path not in ("", "/") or destination.query or destination.fragment):
        raise ValueError("An HTTPS cloud origin is required")
    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "dns_ms": None, "https_ms": None, "http_status": None, "gateway": check_gateway(),
        "cloud_probe": True, "https_error": None,
    }
    started = monotonic()
    try:
        socket.getaddrinfo(destination.hostname, destination.port or 443, type=socket.SOCK_STREAM)
        result["dns_ms"] = round((monotonic() - started) * 1000)
    except OSError:
        pass
    started = monotonic()
    request = Request(origin.rstrip("/") + "/api/cloud/health", method="HEAD")
    try:
        with build_opener(NoRedirects()).open(request, timeout=8) as response:
            result["http_status"] = response.status
    except HTTPError as response:
        result["http_status"] = response.code
        response.close()
    except OSError as error:
        reason = getattr(error, "reason", error)
        result["https_error"] = (
            "tls" if isinstance(reason, ssl.SSLError) else
            "timeout" if isinstance(reason, TimeoutError) else "network"
        )
    if result["http_status"] is not None:
        result["https_ms"] = round((monotonic() - started) * 1000)
    return result


class InternetHealth:
    def __init__(self, origin, store, scope):
        self.origin = origin
        self.store = store
        self.scope = scope
        self.current = []

    async def restore(self):
        try:
            self.current = await run_in_threadpool(self.store.internet_checks, self.scope)
        except (OSError, sqlite3.Error):
            logging.getLogger(__name__).warning("Could not restore recent NORTH connectivity checks.")

    async def run(self):
        while True:
            sample = await run_in_threadpool(check_origin, self.origin)
            self.current = [*self.current[-71:], sample]
            try:
                await run_in_threadpool(self.store.record_internet_check, self.scope, sample)
            except (OSError, sqlite3.Error):
                logging.getLogger(__name__).warning("Could not save a NORTH connectivity check.")
            await asyncio.sleep(300)
