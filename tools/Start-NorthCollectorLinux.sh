#!/usr/bin/env bash
set -euo pipefail
umask 077
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
runtime="$root/.north-launcher"
source_id="${1:-}"
workspace="${2:-}"

if [[ ! "$source_id" =~ ^collector-[a-f0-9]{20}$ ]]; then
    printf 'Usage: bash tools/Start-NorthCollectorLinux.sh collector-ID [https://workspace]\n' >&2
    exit 2
fi
if [[ -z "$workspace" ]]; then
    read -r -p 'NORTH Cloud HTTPS address: ' workspace
fi
if [[ ! "$workspace" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?/?$ ]]; then
    printf 'Enter an HTTPS workspace origin.\n' >&2
    exit 2
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' ||
    { printf 'The NORTH collector needs Python 3.11 or newer.\n' >&2; exit 1; }
mkdir -p -- "$runtime"
exec 9>"$runtime/collector.lock"
flock -n 9 || { printf 'NORTH Collector is already running in this folder.\n' >&2; exit 1; }
environment="$runtime/collector-python"
if [[ ! -x "$environment/bin/python" ]]; then
    python3 -m venv "$environment"
fi
requirements="$root/backend/requirements.txt"
stamp="$environment/north-requirements.txt"
if ! cmp -s -- "$requirements" "$stamp"; then
    "$environment/bin/python" -m pip install --disable-pip-version-check -r "$requirements"
    cp -- "$requirements" "$stamp"
fi
read -rs -p 'Collector pairing key: ' token
printf '\n'
if [[ ! "$token" =~ ^[a-f0-9]{64}$ ]]; then
    printf 'Expected the 64-character pairing key.\n' >&2
    exit 2
fi
export NORTH_CLOUD_SOURCE="$source_id" NORTH_CLOUD_URL="${workspace%/}" NORTH_CLOUD_INGEST_KEY="$token"
export NORTH_DB_PATH="$runtime/collector.sqlite3"
unset DATABASE_URL token
printf 'NORTH Collector is running. Press Ctrl+C to stop.\n'
exec "$environment/bin/python" "$root/backend/run_collector.py"
