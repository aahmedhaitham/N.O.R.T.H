"""Sample byte counters reported by Windows network adapters."""

import asyncio
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

from starlette.concurrency import run_in_threadpool


def read_adapters():
    script = Path(__file__).resolve().parents[1] / "tools" / "Read-NorthAdapterTraffic.ps1"
    output = subprocess.check_output(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        encoding="utf-8", timeout=12, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    rows = json.loads(output)
    if not isinstance(rows, list):
        raise ValueError("Expected Windows adapter counters")
    return rows


class AdapterTraffic:
    def __init__(self):
        self.current = {"state": "starting", "updated_at": None, "adapters": []}
        self._counters = {}
        self._sample_time = None

    def record(self, rows, sampled_at, measured_at):
        counters = {}
        adapters = []
        previous_history = {item["name"]: item.get("recent_rates", []) for item in self.current["adapters"]}
        elapsed = measured_at - self._sample_time if self._sample_time is not None else 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            name, received, sent = row.get("name"), row.get("received"), row.get("sent")
            if (not isinstance(name, str) or not name or len(name) > 128 or name in counters or
                    not all(isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value) for value in (received, sent))):
                continue
            rx, tx = int(received), int(sent)
            counters[name] = (rx, tx)
            previous = self._counters.get(name)
            rates = (None, None)
            if previous and elapsed > 0 and rx >= previous[0] and tx >= previous[1]:
                rates = ((rx - previous[0]) / elapsed, (tx - previous[1]) / elapsed)
            adapter = {
                "name": name, "received_bytes": rx, "sent_bytes": tx,
                "receive_rate": rates[0], "send_rate": rates[1],
            }
            history = previous_history.get(name, [])
            if rates[0] is not None:
                history = [*history[-11:], {
                    "sampled_at": sampled_at, "receive_rate": rates[0], "send_rate": rates[1],
                }]
            if history:
                adapter["recent_rates"] = history
            adapters.append(adapter)
            if len(adapters) >= 64:
                break
        self.current = {
            "state": "ready", "updated_at": sampled_at, "adapters": adapters,
        }
        self._counters, self._sample_time = counters, measured_at

    async def run(self):
        while True:
            try:
                rows = await run_in_threadpool(read_adapters)
                self.record(rows, datetime.now(timezone.utc).isoformat(), monotonic())
            except (OSError, ValueError, subprocess.SubprocessError):
                self.current = {**self.current, "state": "unavailable"}
                self._counters = {}
                self._sample_time = None
            await asyncio.sleep(30)
