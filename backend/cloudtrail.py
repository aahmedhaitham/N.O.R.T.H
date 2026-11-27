"""Read and normalize local CloudTrail exports without contacting AWS."""

import argparse
import gzip
import hashlib
import json
import re
import zlib
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

MAX_FILE = 8 * 1024 * 1024
MAX_JSON = 16 * 1024 * 1024
MAX_RECORDS = 5_000
TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,127}\Z")
ARN = re.compile(r"arn:aws(?:-[a-z0-9-]+)?:(?:iam|sts)::[0-9]{12}:"
                 r"(?:root|(?:user|role|assumed-role|federated-user)/[A-Za-z0-9+=,.@_/-]{1,256})\Z")
KEY_ID = re.compile(r"(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}", re.IGNORECASE)


class ImportError(ValueError):
    """A plain-language failure suitable for the local importer."""


def token(value):
    return value if isinstance(value, str) and TOKEN.fullmatch(value) and not KEY_ID.search(value) else ""


def normalize(record):
    if not isinstance(record, dict):
        raise ValueError
    event_id = UUID(record["eventID"])
    time = datetime.fromisoformat(record["eventTime"])
    if time.utcoffset() is None:
        raise ValueError
    service = token(record.get("eventSource"))
    name = token(record.get("eventName"))
    if not service or not name:
        raise ValueError
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, dict) else {}
    arn = identity.get("arn")
    if not isinstance(arn, str) or not ARN.fullmatch(arn) or KEY_ID.search(arn):
        arn = ""
    source = record.get("sourceIPAddress")
    try:
        source = str(ip_address(source)) if isinstance(source, str) else ""
    except ValueError:
        source = ""
    fields = {
        "EventSource": service, "EventName": name,
        "IdentityType": token(identity.get("type")), "IdentityArn": arn,
        "AwsRegion": token(record.get("awsRegion")), "ErrorCode": token(record.get("errorCode")),
        "SourceIp": source,
    }
    return {
        "id": hashlib.sha256(("cloudtrail:" + str(event_id)).encode()).hexdigest()[:24],
        "timestamp": time.astimezone(timezone.utc).isoformat(timespec="microseconds"),
        "kind": 3001, "source": "cloudtrail", "source_event_id": str(event_id),
        "host": service, "source_ip": source, "raw": fields,
    }


def read_export(path):
    try:
        with Path(path).open("rb") as file:
            if file.seek(0, 2) > MAX_FILE:
                raise ImportError("The CloudTrail file exceeds the 8 MiB file limit.")
            file.seek(0)
            compressed = file.read(2) == b"\x1f\x8b"
            file.seek(0)
            if compressed:
                with gzip.GzipFile(fileobj=file) as archive:
                    content = archive.read(MAX_JSON + 1)
            else:
                content = file.read(MAX_JSON + 1)
        if len(content) > MAX_JSON:
            raise ImportError("The expanded CloudTrail file exceeds the 16 MiB limit.")
        root = json.loads(content)
        records = root.get("Records") if isinstance(root, dict) else None
        if not isinstance(records, list) or not records:
            raise ImportError("Choose a CloudTrail export containing a nonempty Records array.")
        if len(records) > MAX_RECORDS:
            raise ImportError("The export contains too many events. Choose a smaller export.")
        return [normalize(record) for record in records]
    except ImportError:
        raise
    except (OSError, EOFError, KeyError, ValueError, TypeError, RecursionError, zlib.error) as error:
        raise ImportError("NORTH could not read this CloudTrail export. Check that it is valid JSON or gzip.") from error


def import_export(store, path):
    events = read_export(path)
    inserted = store.ingest_local_windows(events)
    return {
        "records": len(events), "inserted": inserted,
        "start": min(event["timestamp"] for event in events),
        "end": max(event["timestamp"] for event in events),
        "regions": sorted({event["raw"]["AwsRegion"] for event in events if event["raw"]["AwsRegion"]}),
        "event_sources": sorted({event["host"] for event in events}),
    }


def main():
    from north import Store

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    store = Store(path=args.database)
    store.initialize()
    try:
        print(json.dumps(import_export(store, args.file)))
    except ImportError as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
