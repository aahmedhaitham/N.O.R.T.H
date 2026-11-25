"""Collect and sync telemetry without running the development servers."""

import asyncio
import logging
import os
import socket
import sys

from cloud_sync import collector_source, snapshot_target, sync_loop
from adapter_traffic import AdapterTraffic
from internet_health import InternetHealth
from neighbors import NeighborMonitor
from north import configured_store
from router_usage import RouterUsage
from sysmon import SysmonMonitor


async def collect():
    store = configured_store()
    store.initialize()
    neighbors = NeighborMonitor(store, True)
    sysmon = SysmonMonitor(store, sys.platform == "win32")
    alias = os.getenv("NORTH_OPENWRT_HOST")
    router = RouterUsage(alias) if alias else None
    cloud_url = os.environ["NORTH_CLOUD_URL"]
    health = InternetHealth(cloud_url, store, snapshot_target(cloud_url, collector_source(socket.gethostname())))
    await health.restore()
    traffic = AdapterTraffic() if sys.platform == "win32" else None
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(neighbors.run())
        tasks.create_task(health.run())
        if sys.platform == "win32":
            tasks.create_task(sysmon.run())
        if traffic:
            tasks.create_task(traffic.run())
        if router:
            tasks.create_task(router.run())
        tasks.create_task(sync_loop(
            store, neighbors, sysmon, cloud_url, os.environ["NORTH_CLOUD_INGEST_KEY"], router, health, traffic,
        ))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(collect())
    except KeyboardInterrupt:
        pass
