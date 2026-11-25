"""Capture a short local Ethernet trace for inspection in ATLAS."""

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def find_dumpcap():
    executable = shutil.which("dumpcap")
    if not executable and sys.platform == "win32":
        program_files = os.environ.get("ProgramFiles")
        if program_files:
            installed = Path(program_files) / "Wireshark" / "dumpcap.exe"
            if installed.is_file():
                executable = str(installed)
    if not executable:
        raise ValueError("Dumpcap and a working packet capture driver are required.")
    return executable


def local_interfaces(executable):
    listed = subprocess.check_output([executable, "-D"], text=True, errors="replace", timeout=12)
    platform_names = set() if sys.platform == "win32" else {name for _, name in socket.if_nameindex()}
    interfaces = {}
    for line in listed.splitlines():
        match = re.fullmatch(r"(\d+)\. (\S+)(?: \((.*)\))?", line.strip())
        if not match:
            continue
        index, name, description = match.groups()
        if sys.platform == "win32":
            is_local = re.fullmatch(r"\\Device\\NPF_\{[0-9A-F-]{36}\}", name, flags=re.I)
        else:
            is_local = name in platform_names
        if is_local:
            interfaces[int(index)] = (name, description or name)
    return interfaces


def capture(executable, name, duration, directory):
    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("Choose an existing output directory.")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    output = directory / f"north-{timestamp}-{uuid4().hex[:8]}.pcapng"
    # Reserve a new private file before handing its pathname to dumpcap.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        subprocess.run([
            executable, "-i", name, "-y", "EN10MB", "-p", "-s", "96",
            "-a", f"duration:{duration}", "-a", "filesize:7000", "-c", "5000", "-w", str(output),
        ], timeout=duration + 15, check=True)
        if output.stat().st_size < 28 or output.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("Capture did not produce a usable ATLAS file.")
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        output.unlink(missing_ok=True)
        raise
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="List eligible local interfaces.")
    mode.add_argument("--interface", type=int, help="Select one interface from --list.")
    parser.add_argument("--seconds", type=int, default=15, choices=range(1, 61), metavar="1–60")
    parser.add_argument("--output-dir", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        executable = find_dumpcap()
        interfaces = local_interfaces(executable)
        if args.list:
            for index, (_, label) in interfaces.items():
                print(f"{index}: {label}")
            if not interfaces:
                print("No eligible local interfaces were found.")
            return 0
        if args.interface not in interfaces:
            raise ValueError("Select a local interface from --list.")
        name, label = interfaces[args.interface]
        print(f"Capturing on {label} for up to {args.seconds} seconds.", flush=True)
        output = capture(executable, name, args.seconds, args.output_dir)
        print(f"Saved locally: {output}")
        return 0
    except KeyboardInterrupt:
        print("Capture cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"NORTH capture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
