"""Collect and sync telemetry without running the development servers."""

import asyncio
import logging
import os
import socket
import sys

from cloud_sync import collector_source, snapshot_target, sync_loop
from adapter_traffic import AdapterTraffic
from internet_health import InternetHealth
from journal_monitor import JournalMonitor
from neighbors import NeighborMonitor
from north import configured_store
from router_usage import RouterUsage
from sysmon import SysmonMonitor


async def collect():
    store = configured_store()
    store.initialize()
    neighbors = NeighborMonitor(store, True)
    sysmon = SysmonMonitor(store, sys.platform == "win32")
    cloud_url = os.environ["NORTH_CLOUD_URL"]
    source = collector_source(socket.gethostname())
    health = InternetHealth(cloud_url, store, snapshot_target(cloud_url, source))
    await health.restore()
    alias = os.getenv("NORTH_OPENWRT_HOST")
    router = RouterUsage(alias, store, snapshot_target(cloud_url, source + "|openwrt|" + alias)) if alias else None
    if router:
        await router.restore()
    traffic = AdapterTraffic() if sys.platform == "win32" else None
    journal = JournalMonitor(store) if sys.platform.startswith("linux") else None
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(neighbors.run())
        tasks.create_task(health.run())
        if sys.platform == "win32":
            tasks.create_task(sysmon.run())
        if traffic:
            tasks.create_task(traffic.run())
        if journal:
            tasks.create_task(journal.run())
        if router:
            tasks.create_task(router.run())
        tasks.create_task(sync_loop(
            store, neighbors, sysmon, cloud_url, os.environ["NORTH_CLOUD_INGEST_KEY"], router, health, traffic, journal,
        ))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(collect())
    except KeyboardInterrupt:
        pass
