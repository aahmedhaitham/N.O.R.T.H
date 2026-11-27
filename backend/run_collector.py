"""Collect and sync telemetry without running the development servers."""

import asyncio
import json
import logging
import os
import socket
import sys
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

from starlette.concurrency import run_in_threadpool

from cloud_sync import collector_source, snapshot_target, sync_loop
from detection_rules import RuleError, bundled_rules, rule_workspace, run_detection_monitor, scan_local_findings
from adapter_traffic import AdapterTraffic
from internet_health import InternetHealth
from journal_monitor import JournalMonitor
from neighbors import NeighborMonitor
from north import Store, collector_tool, configured_store
from router_usage import RouterUsage
from sysmon import SysmonMonitor
from windows_sources import WindowsSources


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
        if not store.url and os.getenv("NORTH_AUTO_DETECTIONS", "1") == "1":
            tasks.create_task(run_detection_monitor(store))
        tasks.create_task(health.run())
        if sys.platform == "win32":
            tasks.create_task(sysmon.run())
            if not store.url and os.getenv("NORTH_WINDOWS_LOCAL_EVENTS") == "1":
                tasks.create_task(WindowsSources(store, True).run())
        if traffic:
            tasks.create_task(traffic.run())
        if journal:
            tasks.create_task(journal.run())
        if router:
            tasks.create_task(router.run())
        tasks.create_task(sync_loop(
            store, neighbors, sysmon, cloud_url, os.environ["NORTH_CLOUD_INGEST_KEY"], router, health, traffic, journal,
        ))


async def self_test():
    bundled_rules()
    with TemporaryDirectory() as folder:
        store = Store(path=Path(folder) / "smoke.sqlite3")
        await run_in_threadpool(store.initialize)
        if await run_in_threadpool(store.events):
            raise RuntimeError("Collector self-test expected an empty database")
    for script in ("Export-NorthNeighbors.ps1", "Read-NorthSysmon.ps1", "Read-NorthAdapterTraffic.ps1",
                   "Read-NorthWindowsSource.ps1", "Read-NorthTcp.ps1"):
        if not collector_tool(script).is_file():
            raise RuntimeError("Collector script is missing: " + script)
    print("NORTH Collector runtime checks passed.")


async def collect_local():
    store = Store(path=os.environ["NORTH_DB_PATH"])
    await run_in_threadpool(store.initialize)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()

    def watch_parent():
        sys.stdin.buffer.read(1)
        loop.call_soon_threadsafe(stopping.set)

    threading.Thread(target=watch_parent, daemon=True).start()
    async with asyncio.TaskGroup() as tasks:
        monitors = (
            tasks.create_task(NeighborMonitor(store, True).run()),
            tasks.create_task(WindowsSources(store, True).run()),
            tasks.create_task(run_detection_monitor(store)),
        )
        await stopping.wait()
        for monitor in monitors:
            monitor.cancel()


async def main():
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        import ctypes

        await run_in_threadpool(lambda: None)
        # Load the async backend first, then restore normal DLL lookup for system commands.
        if not ctypes.windll.kernel32.SetDllDirectoryW(None):
            raise OSError("Could not restore the Windows DLL search path")
    if sys.argv[1:] == ["--self-test"]:
        await self_test()
    elif sys.argv[1:] == ["--local-monitor"] and sys.platform == "win32":
        await collect_local()
    elif sys.argv[1:] == ["--cloudtrail-workspace"]:
        from cloudtrail import ImportError as CloudTrailImportError, coverage_summary, import_export

        try:
            body = sys.stdin.buffer.read(32_769)
            if len(body) > 32_768:
                raise CloudTrailImportError("The CloudTrail request is too large.")
            command = json.loads(body)
            store = Store(path=os.environ["NORTH_DB_PATH"])
            await run_in_threadpool(store.initialize)
            imported = await run_in_threadpool(import_export, store, command["path"]) if "path" in command else None
            report = await run_in_threadpool(coverage_summary, store)
            print(json.dumps({"coverage": report, "imported": imported}))
        except CloudTrailImportError as error:
            print(json.dumps({"detail": str(error)}))
    elif sys.argv[1:] == ["--rule-workspace"]:
        try:
            body = sys.stdin.buffer.read(200_001)
            if len(body) > 200_000:
                raise RuleError("Rule request is too large")
            command = json.loads(body)
            store = Store(path=os.environ["NORTH_DB_PATH"])
            await run_in_threadpool(store.initialize)
            checks = json.loads(os.getenv("NORTH_RULE_SOURCE_CHECKS", "{}"))
            print(json.dumps(await run_in_threadpool(rule_workspace, store, command, source_checks=checks)))
        except (RuleError, json.JSONDecodeError, UnicodeDecodeError) as error:
            print(json.dumps({"detail": str(error)}))
    elif sys.argv[1:] == ["--evaluate-findings"]:
        store = configured_store()
        if store.url:
            raise SystemExit("Finding evaluation requires a local SQLite database.")
        await run_in_threadpool(store.initialize)
        print(json.dumps(await run_in_threadpool(scan_local_findings, store)))
    elif not sys.argv[1:]:
        await collect()
    else:
        raise SystemExit("Usage: NORTH Collector [--self-test | --evaluate-findings | --local-monitor (Windows) | --rule-workspace | --cloudtrail-workspace]")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
