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


def mapping(value):
    return value if isinstance(value, dict) else {}


def items(value):
    return value[:64] if isinstance(value, list) else []


def request_flags(service, name, request):
    if service == "guardduty.amazonaws.com" and (
        name == "DeleteDetector" or name == "UpdateDetector" and request.get("enable") is False
    ):
        return {"DefenseDisabled": "yes"}
    if service == "iam.amazonaws.com" and name in {"AttachUserPolicy", "AttachRolePolicy"}:
        return {"AdminPolicy": "yes"} if request.get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess" else {}
    if service == "ec2.amazonaws.com" and name == "AuthorizeSecurityGroupIngress":
        permissions = items(mapping(request.get("ipPermissions")).get("items"))
        ranges = items(mapping(request.get("ipRanges")).get("items"))
        for permission in permissions:
            ranges.extend(items(mapping(mapping(permission).get("ipRanges")).get("items")))
        if any(mapping(entry).get("cidrIp") == "0.0.0.0/0" for entry in ranges) or request.get("cidrIp") == "0.0.0.0/0":
            return {"WorldIngress": "yes"}
    if service == "s3.amazonaws.com" and name in {"PutBucketPolicy", "PutBucketAcl"}:
        if request.get("x-amz-acl") in ("public-read", "public-read-write"):
            return {"PublicAccess": "yes"}
        policy = request.get("bucketPolicy")
        if isinstance(policy, str) and len(policy) <= 8192:
            try:
                policy = json.loads(policy)
            except (ValueError, RecursionError):
                return {}
        statements = mapping(policy).get("Statement")
        for statement in [statements] if isinstance(statements, dict) else items(statements):
            statement = mapping(statement)
            principal = statement.get("Principal")
            if statement.get("Effect") == "Allow" and (principal == "*" or mapping(principal).get("AWS") == "*"):
                return {"PublicAccess": "yes"}
    return {}


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
        "SourceIp": source, "Outcome": "error" if record.get("errorCode") else "ok",
        **request_flags(service, name, mapping(record.get("requestParameters"))),
    }
    if service == "signin.amazonaws.com" and name == "ConsoleLogin":
        login = mapping(record.get("responseElements")).get("ConsoleLogin")
        mfa = mapping(record.get("additionalEventData")).get("MFAUsed")
        fields["Login"] = login.lower() if login in ("Success", "Failure") else ""
        fields["Mfa"] = mfa.lower() if mfa in ("Yes", "No") else ""
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


def evaluate_import(store, db, events):
    from detection_rules import configured_rules, evaluate_rules, findings_from_matches
    from event_contract import event_contract

    projected = [event_contract(event) for event in events]
    rules, disabled = configured_rules(db)
    matches = evaluate_rules([rule for rule in rules if rule.id not in disabled and
                              rule.logsource.get("source") == "cloudtrail"], projected)["matches"]
    findings = list(findings_from_matches(matches, projected))

    known = {}
    for event in sorted(projected, key=lambda item: (item["ts"], item["id"])):
        cloud = event["cloudtrail"]
        identity = cloud["identity_arn"]
        if not identity or cloud.get("outcome") != "ok" or cloud.get("login") == "failure":
            continue
        if ":assumed-role/" in identity:
            identity = identity.rsplit("/", 1)[0]
        for name, value in (("region", cloud["region"]), ("source address", event["network"]["src"]["ip"])):
            if not value:
                continue
            scope = hashlib.sha256(("cloudtrail:" + name + ":" + identity).encode()).hexdigest()
            entity = hashlib.sha256(value.encode()).hexdigest()
            if scope not in known:
                known[scope] = db.execute("SELECT 1 FROM local_baseline_entities WHERE scope = ? LIMIT 1",
                                          (scope,)).fetchone() is not None
            inserted = db.execute("INSERT OR IGNORE INTO local_baseline_entities VALUES (?, ?)",
                                  (scope, entity)).rowcount
            if not (inserted and known[scope]):
                continue
            match = {"rule_id": "cloudtrail-first-seen-" + name.replace(" ", "-"),
                     "title": f"CloudTrail identity used a previously unseen {name}", "severity": "low",
                     "attack": ("attack.t1078.004",), "evidence_ids": (event["id"],),
                     "plain_summary": "The observation is new within the imported history for this identity.",
                     "what_to_do": "Compare with approved activity and the time range of your imports."}
            finding, = findings_from_matches([match], [event])
            finding["rarity"] = "first seen"
            findings.append(finding)
    store._write_findings(db, findings)
    return len(findings)


def import_export(store, path):
    events = read_export(path)
    if store.url:
        raise ImportError("CloudTrail imports require the local SQLite store.")
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        inserted = store._insert_events(db, events, local=True, enqueue=True)
        findings = evaluate_import(store, db, events) if inserted else 0
    return {
        "records": len(events), "inserted": inserted, "findings": findings,
        "start": min(event["timestamp"] for event in events),
        "end": max(event["timestamp"] for event in events),
        "regions": sorted({event["raw"]["AwsRegion"] for event in events if event["raw"]["AwsRegion"]}),
        "event_sources": sorted({event["host"] for event in events}),
    }


def coverage_summary(store):
    with store.connect() as db:
        predicate = "json_extract(payload, '$.source') = 'cloudtrail'"
        count, start, end = db.execute(
            f"SELECT count(*), min(timestamp), max(timestamp) FROM local_windows_events WHERE {predicate}"
        ).fetchone()

        def dimensions(field):
            # The caller supplies one of two fixed normalized schema field names.
            rows = db.execute(
                f"SELECT DISTINCT json_extract(payload, '$.raw.{field}') AS value "
                f"FROM local_windows_events WHERE {predicate} AND value <> '' ORDER BY value LIMIT 65"
            ).fetchall()
            return [row[0] for row in rows[:64]], len(rows) > 64

        regions, regions_limited = dimensions("AwsRegion")
        sources, sources_limited = dimensions("EventSource")
    return {"records": count, "start": start, "end": end, "regions": regions, "event_sources": sources,
            "dimensions_limited": regions_limited or sources_limited}


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
