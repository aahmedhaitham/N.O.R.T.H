"""Publish a bounded private snapshot to a configured NORTH Cloud workspace."""

import asyncio
import json
import logging
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from starlette.concurrency import run_in_threadpool

from device_watch import findings
from network import snapshot
from north import build_cases, report


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_snapshot(store, neighbor_status, sysmon_status):
    events = store.events()
    cases = sorted(
        build_cases(events), key=lambda case: case["evidence"][-1]["timestamp"], reverse=True,
    )[:25]
    network = {
        **snapshot(events), "neighbors": neighbor_status, "sysmon": sysmon_status, "device_findings": findings(store),
    }
    payload = {"cases": cases, "events": events[-100:], "network": network,
               "reports": {case["id"]: report(case) for case in cases}}
    data = json.dumps(payload).encode()
    if len(data) > 700_000:
        raise ValueError("Collector snapshot exceeds the cloud size limit")
    return data


def send_snapshot(url, key, data):
    destination = urlsplit(url)
    if (destination.scheme != "https" or not destination.hostname or destination.username or destination.password
            or destination.path not in ("", "/") or destination.query or destination.fragment):
        raise ValueError("NORTH_CLOUD_URL must be an HTTPS origin")
    request = Request(
        url.rstrip("/") + "/api/cloud/snapshot", data=data,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with build_opener(NoRedirects()).open(request, timeout=12) as response:
        if response.status != 200:
            raise OSError("Cloud workspace did not accept the snapshot")


async def sync_loop(store, neighbors, sysmon, url, key):
    previous = None
    while True:
        try:
            data = await run_in_threadpool(build_snapshot, store, neighbors.current, sysmon.current)
            if data != previous:
                await run_in_threadpool(send_snapshot, url, key, data)
                previous = data
        except (OSError, ValueError) as error:
            logging.getLogger(__name__).warning("NORTH Cloud sync failed: %s", type(error).__name__)
        await asyncio.sleep(60)
