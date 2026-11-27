"""Bounded, read-only evaluation of NORTH's named-selection Sigma subset."""

import asyncio
import hashlib
import json
import logging
import ntpath
import os
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

import regex
import yaml
from starlette.concurrency import run_in_threadpool
from yaml.events import AliasEvent, MappingStartEvent, SequenceStartEvent, CollectionEndEvent
from north import events_in_window, threshold_groups
from event_contract import event_contract
from windows_sources import FIXES


FIELDS = {
    "Image": "process.path", "ProcessName": "process.name", "ParentImage": "process.parent_path",
    "CommandLine": "process.cmdline", "ParentCommandLine": "process.parent_cmdline",
    "TargetFilename": "file.path", "TargetObject": "registry.target", "QueryName": "dns.query",
    "SourceIp": "network.src.ip", "DestinationIp": "network.dst.ip", "EventID": "raw.event_type",
    "Host": "host", "User": "user.name", "Action": "action", "TargetImage": "process.target_path",
    "Provider": "raw.provider",
    "LocalAccount": "raw.local_account", "TargetGroupSid": "raw.group_sid",
    "AssetId": "asset_id", "ProcessGuid": "process.guid",
    "ParentProcessGuid": "process.parent_guid", "SourceImage": "process.source_path",
    "GrantedAccess": "process.granted_access", "ImageLoaded": "process.loaded_image", "LogonType": "raw.logon_type",
}
IDENTIFIER = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,31}")
TOKEN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*|[()]")
TECHNIQUE = re.compile(r"attack\.t[0-9]{4}(?:\.[0-9]{3})?")
MODIFIERS = {"contains", "startswith", "endswith", "re"}
RULE_FIELDS = {"id", "title", "tags", "severity", "logsource", "detection", "falsepositives",
               "plain_summary", "what_to_do", "requires", "tests"}


class RuleError(ValueError):
    pass

@dataclass(frozen=True)
class Correlation:
    kind: str
    group_by: tuple[str, ...]
    window: timedelta
    count: int | None = None
    start: object = None
    context: object = None
    jitter: int = 0
    distinct: str | None = None



@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    tags: tuple
    logsource: dict
    requires: tuple
    falsepositives: tuple
    plain_summary: str
    what_to_do: str
    fixtures: dict
    predicate: object
    correlation: Correlation | None = None
    selections: dict | None = None

    def matches(self, event):
        return all(event.get(key) == value for key, value in self.logsource.items()) and self.predicate(event)

    def evidence(self, events):
        if not self.correlation:
            return [(event["id"],) for event in events if self.matches(event)]
        spec = self.correlation
        keyed = [(tuple(field_value(event, path) for path in spec.group_by), event) for event in events
                 if all(event.get(key) == value for key, value in self.logsource.items())]
        keyed = [(key, event) for key, event in keyed if all(isinstance(value, str) and value for value in key)]
        if spec.kind == "threshold":
            return [tuple(event["id"] for event in group) for _, group in threshold_groups(
                (event for _, event in keyed if self.predicate(event) and (
                    not spec.distinct or isinstance(field_value(event, spec.distinct), str)
                    and field_value(event, spec.distinct)
                )),
                group_key=lambda event: tuple(field_value(event, path) for path in spec.group_by),
                count=spec.count, window=spec.window, time_key="ts",
                distinct_key=(lambda event: field_value(event, spec.distinct).casefold()) if spec.distinct else None)]
        if spec.kind == "interval":
            buckets = defaultdict(list)
            for key, event in sorted(keyed, key=lambda row: (row[1]["ts"], row[1]["id"])):
                if self.predicate(event):
                    buckets[key].append(event)
            groups = []
            for bucket in buckets.values():
                start = 0
                while start + spec.count <= len(bucket):
                    candidates = bucket[start:start + spec.count]
                    times = [datetime.fromisoformat(item["ts"]) for item in candidates]
                    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
                    if min(gaps) >= 5 and max(gaps) - min(gaps) <= spec.jitter and times[-1] - times[0] <= spec.window:
                        groups.append(tuple(item["id"] for item in candidates))
                        start += spec.count
                    else:
                        start += 1
            return groups
        starts, ends, context = [], defaultdict(list), defaultdict(list)
        for key, event in keyed:
            if spec.start(event):
                starts.append((key, event))
            if self.predicate(event):
                ends[key].append(event)
            if spec.context and spec.context(event):
                context[key].append(event)
        groups = []
        for key, event in sorted(starts, key=lambda row: (row[1]["ts"], row[1]["id"])):
            later = [candidate for candidate in events_in_window(event, ends[key], spec.window, time_key="ts")
                     if candidate["id"] != event["id"]]
            if later:
                evidence = [event, *later, *events_in_window(event, context[key], spec.window, time_key="ts")]
                ordered = sorted(evidence, key=lambda item: (item["ts"], item["id"]))
                groups.append(tuple(dict.fromkeys(item["id"] for item in ordered)))
        return groups


class RuleLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key, value in node.value:
            name = self.construct_object(key, deep=deep)
            if not isinstance(name, str) or name in mapping:
                raise RuleError("Rule mapping keys must be unique strings")
            mapping[name] = self.construct_object(value, deep=deep)
        return mapping


def condition_predicate(expression, selections):
    if not isinstance(expression, str) or not expression.strip() or len(expression) > 256:
        raise RuleError("Invalid condition")
    tokens = TOKEN.findall(expression)
    if "".join(tokens) != "".join(expression.split()) or len(tokens) > 48:
        raise RuleError("Invalid condition tokens")
    position = 0

    def take(token):
        nonlocal position
        if position < len(tokens) and tokens[position] == token:
            position += 1
            return True
        return False

    def primary():
        nonlocal position
        if take("not"):
            parent = primary()
            return lambda event: not parent(event)
        if take("("):
            group = disjunction()
            if not take(")"):
                raise RuleError("Missing closing parenthesis")
            return group
        if position >= len(tokens) or tokens[position] not in selections:
            raise RuleError("Unknown selection in condition")
        predicate = selections[tokens[position]]
        position += 1
        return predicate

    def conjunction():
        terms = [primary()]
        while take("and"):
            terms.append(primary())
        return lambda event: all(term(event) for term in terms)

    def disjunction():
        terms = [conjunction()]
        while take("or"):
            terms.append(conjunction())
        return lambda event: any(term(event) for term in terms)

    predicate = disjunction()
    if position != len(tokens):
        raise RuleError("Unexpected condition token")
    return predicate


def field_value(event, path):
    for part in path.split("."):
        if not isinstance(event, dict):
            return None
        event = event.get(part)
    return event


def field_predicate(key, value):
    field, *modifiers = key.split("|")
    operations = [modifier for modifier in modifiers if modifier != "all"]
    if field not in FIELDS or len(operations) > 1 or set(operations) - MODIFIERS or len(set(modifiers)) != len(modifiers):
        raise RuleError("Unsupported field or modifier")
    operation = operations[0] if operations else ""
    values = value if isinstance(value, list) else [value]
    if not 1 <= len(values) <= 12 or any(
        not ((isinstance(item, str) and 0 < len(item) <= 256) or (not operation and type(item) is int))
        for item in values
    ):
        raise RuleError("Invalid field values")
    path = FIELDS[field]
    if operation == "re":
        try:
            expected = [regex.compile(item, regex.IGNORECASE) for item in values]
        except (regex.error, OverflowError) as error:
            raise RuleError("Invalid regular expression") from error
    else:
        expected = [item.casefold() if isinstance(item, str) else item for item in values]

    def match(actual, item):
        if operation == "re":
            return isinstance(actual, str) and item.search(actual[:4096], timeout=.005) is not None
        if not isinstance(actual, str) or not isinstance(item, str):
            return not operation and type(actual) is type(item) and actual == item
        actual = actual[:4096].casefold()
        if operation == "contains":
            return item in actual
        if operation == "startswith":
            return actual.startswith(item)
        if operation == "endswith":
            return actual.endswith(item)
        return actual == item

    combine = all if "all" in modifiers else any

    def evaluate(event):
        actual = field_value(event, path)
        return combine(match(actual, item) for item in expected)

    return evaluate


def selection_predicate(selection):
    if not isinstance(selection, dict) or not 1 <= len(selection) <= 12:
        raise RuleError("A selection must contain one to twelve fields")
    fields = [field_predicate(key, value) for key, value in selection.items()]
    return lambda event: all(predicate(event) for predicate in fields)


def string_list(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 12 or any(
        not isinstance(item, str) or not item.strip() or len(item) > 512 for item in value
    ):
        raise RuleError("Expected bounded, nonempty list of strings")
    return tuple(value)


def compile_rule(data):
    if not isinstance(data, dict) or set(data) - {"correlation"} != RULE_FIELDS:
        raise RuleError("Rule fields are missing or unsupported")
    for label in ("id", "title", "plain_summary", "what_to_do"):
        if not isinstance(data[label], str) or not data[label].strip() or len(data[label]) > 512:
            raise RuleError("Invalid rule text")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", data["id"]):
        raise RuleError("Invalid rule ID")
    if data["severity"] not in ("info", "low", "medium", "high", "critical"):
        raise RuleError("Invalid severity")
    tags, requires, falsepositives = map(string_list, (data["tags"], data["requires"], data["falsepositives"]))
    if not any(TECHNIQUE.fullmatch(tag) for tag in tags):
        raise RuleError("Expected an ATT&CK technique")
    logsource = data["logsource"]
    if not isinstance(logsource, dict) or not logsource or set(logsource) - {"source", "category"} or any(
        not isinstance(value, str) or not value for value in logsource.values()
    ):
        raise RuleError("Invalid logsource")
    fixtures = data["tests"]
    if not isinstance(fixtures, dict) or set(fixtures) != {"positive", "negative"} or any(
        not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,60}\.json", value)
        for value in fixtures.values()
    ):
        raise RuleError("Expected positive and negative fixture filenames")
    detection = data["detection"]
    if not isinstance(detection, dict) or "condition" not in detection or not 2 <= len(detection) <= 9:
        raise RuleError("Expected a condition and named selections")
    selections = {}
    for name, selector in detection.items():
        if name == "condition":
            continue
        if not IDENTIFIER.fullmatch(name) or name in {"and", "or", "not"}:
            raise RuleError("Invalid selection name")
        selections[name] = selection_predicate(selector)
    correlation = None
    if "correlation" in data:
        value = data["correlation"]
        if not isinstance(value, dict) or value.get("type") not in ("threshold", "sequence", "interval"):
            raise RuleError("Unsupported correlation type")
        kind = value["type"]
        field = "start" if kind == "sequence" else "count"
        extra = {"context"} if kind == "sequence" else {"distinct"} if kind == "threshold" else set()
        required = {"type", "group_by", "window_seconds", field} | ({"jitter_seconds"} if kind == "interval" else set())
        if set(value) - extra != required:
            raise RuleError("Invalid correlation fields")
        group_by = string_list(value["group_by"])
        seconds = value["window_seconds"]
        if (len(group_by) > 4 or len(set(group_by)) != len(group_by) or any(key not in FIELDS for key in group_by)
                or type(seconds) is not int or not 1 <= seconds <= 3600):
            raise RuleError("Invalid correlation grouping or window")
        paths = tuple(FIELDS[key] for key in group_by)
        if kind in ("threshold", "interval"):
            count = value["count"]
            jitter = value.get("jitter_seconds", 0)
            if (type(count) is not int or not (3 if kind == "interval" else 2) <= count <= 100
                    or type(jitter) is not int or not 0 <= jitter <= 15):
                raise RuleError("Invalid threshold")
            distinct = value.get("distinct")
            if "distinct" in value and (not isinstance(distinct, str) or distinct not in FIELDS):
                raise RuleError("Invalid distinct field")
            correlation = Correlation(kind, paths, timedelta(seconds=seconds), count=count, jitter=jitter,
                                      distinct=FIELDS.get(distinct))
        else:
            start = value["start"]
            if not isinstance(start, str) or start not in selections:
                raise RuleError("Unknown start selection")
            context = value.get("context")
            if "context" in value and (not isinstance(context, str) or context not in selections):
                raise RuleError("Unknown context selection")
            correlation = Correlation(kind, paths, timedelta(seconds=seconds), start=selections[start],
                                      context=selections.get(context))
    return Rule(data["id"], data["title"], data["severity"], tags, logsource, requires, falsepositives,
                data["plain_summary"], data["what_to_do"], fixtures,
                condition_predicate(detection["condition"], selections), correlation, selections)


def parse_catalog(text):
    if not isinstance(text, str) or len(text) > 128_000:
        raise RuleError("Rule catalog is too large")
    try:
        depth = 0
        for count, event in enumerate(yaml.parse(text, Loader=RuleLoader)):
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
            if depth > 12 or count > 15_000 or isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                raise RuleError("Rule YAML uses unsupported or excessive structure")
        data = yaml.load(text, Loader=RuleLoader)
    except yaml.YAMLError as error:
        raise RuleError("Invalid rule YAML") from error
    if not isinstance(data, list) or not 1 <= len(data) <= 64:
        raise RuleError("Expected a list of rules")
    rules = tuple(compile_rule(rule) for rule in data)
    if len({rule.id for rule in rules}) != len(rules):
        raise RuleError("Duplicate rule ID")
    return rules


@lru_cache(maxsize=1)
def bundled_rules():
    executable = sys.executable if getattr(sys, "frozen", False) else __file__
    return parse_catalog(Path(executable).with_name("rules.yaml").read_text(encoding="utf-8"))


@lru_cache(maxsize=16)
def custom_rules(text):
    return parse_catalog(text)


def configured_rules(db):
    custom = tuple(rule for (text,) in db.execute("SELECT yaml FROM local_custom_rules ORDER BY digest")
                   for rule in custom_rules(text))
    disabled = {identity for (identity,) in db.execute("SELECT id FROM local_rule_disabled")}
    return bundled_rules() + custom, disabled


def active_rules(store):
    with store.connect() as db:
        rules, disabled = configured_rules(db)
    return tuple(rule for rule in rules if rule.id not in disabled)


SENSOR_RULES = (
    "discovery-utility-burst", "powershell-script-write", "scheduled-task-created",
    "registry-run-value-set", "windows-service-installed",
)
SENSOR_LABELS = {
    "verified": "A matching set of recorded events was found.",
    "rule_disabled": "The rule is disabled.",
    "source_missing": "A required event channel could not be found.",
    "access_denied": "Windows denied access to a required event channel.",
    "logging_disabled": "A required event channel is disabled.",
    "source_unavailable": "The collector could not read a required channel.",
    "source_unchecked": "A required channel has no recent source check.",
    "event_not_collected": "A required event type is absent from the sample.",
    "no_recorded_match": "The sampled events did not satisfy the rule.",
    "evaluation_timeout": "Rule evaluation reached its time limit.",
}


def recorded_sensor_check(rules, disabled, events, health):
    observed = {(event["source"], event["raw"]["event_type"]) for event in events}
    results = []
    for rule in rules:
        evidence = ()
        required = [value.split(":", 1) for value in rule.requires]
        if rule.id in disabled:
            outcome = "rule_disabled"
        else:
            try:
                evidence = next(iter(rule.evidence(events)), ())
            except TimeoutError:
                outcome = "evaluation_timeout"
            else:
                if evidence:
                    outcome = "verified"
                else:
                    states = {health.get(source, "unknown") for source, _ in required}
                    failures = (("not_installed", "source_missing"), ("access_denied", "access_denied"),
                                ("misconfigured", "logging_disabled"), ("read_failed", "source_unavailable"),
                                ("unknown", "source_unchecked"))
                    outcome = next((reason for state, reason in failures if state in states), None)
                    if outcome is None:
                        outcome = "event_not_collected" if any(
                            (source, int(kind)) not in observed for source, kind in required
                        ) else "no_recorded_match"
        results.append({"id": rule.id, "title": rule.title, "outcome": outcome,
                        "reason": SENSOR_LABELS[outcome], "evidence_ids": evidence})
    return results


def rule_workspace(store, command=None, *, now=None, source_checks=None):
    """Manage local rules and report coverage supported by observed event types."""
    now = now or datetime.now(timezone.utc)
    command = {} if command is None else command
    action = command.get("action") if isinstance(command, dict) else None
    if action not in (None, "import", "toggle", "test", "verify-sensors") or (action is None and command != {}):
        raise RuleError("Unknown rule action")
    with store.connect() as db:
        if action in ("import", "toggle"):
            db.execute("BEGIN IMMEDIATE")
        rules, disabled = configured_rules(db)
        known = {rule.id: rule for rule in rules}
        if action == "import":
            source = command.get("yaml")
            if not isinstance(source, str) or len(source) > 32_000:
                raise RuleError("Use a YAML catalog of up to 32,000 characters")
            imported = custom_rules(source)
            if len(rules) - len(bundled_rules()) + len(imported) > 16:
                raise RuleError("The local catalog supports up to 16 custom rules")
            if any(rule.id in known for rule in imported):
                raise RuleError("A rule ID already exists")
            for rule in imported:
                if not rule.requires or any(not re.fullmatch(r"(sysmon|security|system|powershell|defender|journalctl):[0-9]{1,6}", need)
                                            for need in rule.requires):
                    raise RuleError("Use supported source:event-id requirements")
            db.execute("INSERT INTO local_custom_rules VALUES (?, ?)", (hashlib.sha256(source.encode()).hexdigest(), source))
            db.executemany("INSERT INTO local_rule_disabled VALUES (?)", [(rule.id,) for rule in imported])
            return {"imported": len(imported)}
        if action in ("toggle", "test"):
            identity = command.get("id")
            if not isinstance(identity, str) or identity not in known:
                raise RuleError("Rule not found")
            if action == "toggle":
                enabled = command.get("enabled")
                if type(enabled) is not bool:
                    raise RuleError("Choose whether to enable the rule")
                if enabled:
                    db.execute("DELETE FROM local_rule_disabled WHERE id = ?", (identity,))
                else:
                    db.execute("INSERT OR IGNORE INTO local_rule_disabled VALUES (?)", (identity,))
                return {"enabled": enabled}
        health = {name: state for name, state, checked_at in db.execute("SELECT * FROM local_source_health")
                  if now - datetime.fromisoformat(checked_at) <= timedelta(minutes=2)}
        observed = {f"{source}:{kind}" for source, kind in
                    db.execute("SELECT source, kind FROM local_observed_event_types")}
    if action == "verify-sensors":
        if command.get("confirmed") is not True:
            raise RuleError("Confirm the recorded evidence check")
        events = [event_contract(event) for event in store.local_windows_events(limit=500)]
        results = recorded_sensor_check([known[identity] for identity in SENSOR_RULES], disabled, events, health)
        event_times = {event["id"]: datetime.fromisoformat(event["ts"]) for event in events}
        for result in results:
            evidence = result["evidence_ids"]
            if evidence and all(now - timedelta(days=1) <= event_times[item] <= now for item in evidence):
                result["finding_id"] = finding_identity(result["id"], evidence)
        report = {"checked_at": now.isoformat(), "sample_size": len(events), "results": results,
                  "verified": sum(result["outcome"] == "verified" for result in results)}
        with store.connect() as db:
            db.execute("INSERT INTO local_sensor_verification (payload) VALUES (?)", (json.dumps(report),))
            db.execute("DELETE FROM local_sensor_verification WHERE id NOT IN "
                       "(SELECT id FROM local_sensor_verification ORDER BY id DESC LIMIT 20)")
        return report
    if action == "test":
        rule = known[identity]
        events = recent_detection_events(store, 500)
        result = evaluate_rules([rule], events)
        if not result["timed_out_rule_ids"] and events:
            chosen_id = command.get("event_id", events[0]["id"])
            chosen = next((event for event in events if event["id"] == chosen_id), None)
            if chosen is None:
                raise RuleError("Choose an event from the replay sample")
            try:
                result["trace"] = {
                    "event_id": chosen["id"],
                    "source_matches": all(chosen.get(key) == value for key, value in rule.logsource.items()),
                    "selections": {name: test(chosen) for name, test in rule.selections.items()},
                    "condition": rule.predicate(chosen),
                }
            except TimeoutError:
                result["timed_out_rule_ids"].append(rule.id)
        if not result["timed_out_rule_ids"] and len(events) > 1:
            duration = datetime.fromisoformat(events[0]["ts"]) - datetime.fromisoformat(events[-1]["ts"])
            count = sum(len(match.get("evidence_groups", match["evidence_ids"])) for match in result["matches"])
            result["noise"] = {"alerts": count, "hours": duration.total_seconds() / 3600,
                               "alerts_per_day": round(count * 86400 / duration.total_seconds(), 2)
                               if duration.total_seconds() >= 3600 else None}
        return {**result, "evaluated_events": len(events), "event_ids": [event["id"] for event in events]}

    for name, check in (source_checks or {}).items():
        state = check.get("state")
        if state == "ready":
            health[name] = "collecting" if check.get("kinds") else "no_data"
            observed.update(f"{name}:{kind}" for kind in check.get("kinds", ()) if type(kind) is int)
        elif state == "unavailable":
            health[name] = {"channel_missing": "not_installed", "access_denied": "access_denied"}.get(
                check.get("problem"), "read_failed")

    def requirement(value):
        source, _, _ = value.partition(":")
        state = health.get(source, "unknown")
        if state == "access_denied":
            detail = "Can’t determine (needs admin)"
        elif state in ("collecting", "no_data"):
            detail = "Observed" if value in observed else "Event type unconfirmed"
        else:
            detail = {"not_installed": "Source not installed", "misconfigured": "Source misconfigured",
                      "read_failed": "Source read failed", "unknown": "No recent source check"}.get(state, "Source unavailable")
        return {"id": value, "state": detail, "source_state": state,
                "fix": FIXES.get(source, "Check whether the collector can read OpenSSH journal events.")}

    with store.connect() as db:
        latest_report = db.execute("SELECT payload FROM local_sensor_verification ORDER BY id DESC LIMIT 1").fetchone()
        report = json.loads(latest_report[0]) if latest_report else None
        verified = set()
        if report and timedelta(0) <= now - datetime.fromisoformat(report["checked_at"]) < timedelta(days=1):
            for result in report["results"]:
                finding_id = result.get("finding_id")
                if finding_id and db.execute("SELECT 1 FROM local_detection_findings WHERE id = ?", (finding_id,)).fetchone():
                    verified.add(result["id"])
    levels = ("blind", "unchecked", "partly", "covered", "verified")
    techniques = defaultdict(int)
    entries = []
    for rule in rules:
        requirements = [requirement(value) for value in rule.requires]
        enabled = rule.id not in disabled
        confirmed = sum(need["state"] == "Observed" for need in requirements)
        coverage = 0
        if enabled:
            if requirements and confirmed == len(requirements):
                coverage = 4 if rule.id in verified else 3
            elif confirmed or any(need["state"] in ("Can’t determine (needs admin)", "Event type unconfirmed")
                                  for need in requirements):
                coverage = 2
            elif any(need["source_state"] == "unknown" for need in requirements):
                coverage = 1
        for tag in filter(TECHNIQUE.fullmatch, rule.tags):
            techniques[tag] = max(techniques[tag], coverage)
        entries.append({"id": rule.id, "title": rule.title, "severity": rule.severity, "enabled": enabled,
                        "attack": rule.tags, "coverage": levels[coverage],
                        "requires": requirements})
    return {"rules": entries, "sensor_report": report,
            "techniques": {tag: levels[level] for tag, level in sorted(techniques.items())}}


def evaluate_rules(rules, events):
    """Return evidence references for successful rules and flag timeouts separately."""
    results, skipped = [], []
    unique_events = tuple({event["id"]: event for event in events}.values())
    for rule in rules:
        try:
            groups = rule.evidence(unique_events)
            matches = tuple(dict.fromkeys(evidence for group in groups for evidence in group))
        except TimeoutError:
            skipped.append(rule.id)
            continue
        if matches:
            results.append({
                "rule_id": rule.id, "title": rule.title, "severity": rule.severity,
                "attack": rule.tags, "evidence_ids": matches, "plain_summary": rule.plain_summary,
                "what_to_do": rule.what_to_do, "falsepositives": rule.falsepositives,
            })
            if rule.correlation:
                results[-1]["evidence_groups"] = groups
    return {"matches": results, "timed_out_rule_ids": skipped}


def finding_identity(rule_id, evidence):
    payload = json.dumps([rule_id, sorted(evidence)], separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()[:24]


def findings_from_matches(matches, events):
    by_id = {event["id"]: event for event in events}
    for match in matches:
        groups = match.get("evidence_groups") or ((identity,) for identity in match["evidence_ids"])
        for group in groups:
            evidence = [by_id[identity] for identity in group]
            identity = finding_identity(match["rule_id"], group)
            yield {**{key: value for key, value in match.items() if key not in ("evidence_groups", "evidence_ids")},
                   "id": identity, "evidence_ids": group,
                   "entities": {"hosts": sorted({event["host"] for event in evidence if event["host"]})},
                   "confidence": "correlated" if len(group) > 1 else "single observation",
                   "rarity": "unknown",
                   "first_seen": min(event["ts"] for event in evidence),
                   "last_seen": max(event["ts"] for event in evidence)}


def recent_detection_events(store, limit):
    events = store.event_page(limit=limit)["events"] + store.local_windows_events(limit=limit)
    events = sorted({event["id"]: event for event in events}.values(),
                    key=lambda item: (item["timestamp"], item["id"]), reverse=True)
    return [event_contract(event) for event in events[:limit]]


def scan_local_findings(store, limit=100):
    if store.url:
        raise ValueError("Detection findings require the local SQLite store")
    events = recent_detection_events(store, limit)
    result = evaluate_rules(active_rules(store), events)
    matches = list(findings_from_matches(result["matches"], events))
    store.record_findings(matches)
    return {"matched_findings": len(matches), "evaluated_events": len(events),
            "timed_out_rule_ids": result["timed_out_rule_ids"]}


def baseline_observations(events):
    for event in sorted(events, key=lambda item: (item["ts"], item["id"])):
        kind = event["raw"]["event_type"]
        source = event["source"]
        path = event["process"]["path"]
        if not event["host"]:
            continue
        if source == "windows_tcp" and kind == 2001:
            local = event["network"]["local"]
            rule_id = "first-seen-listening-endpoint"
            title = "A new local TCP listener appeared"
            entity = [local["ip"], local["port"]]
        elif source not in ("sysmon", "security") or not ntpath.isabs(path):
            continue
        elif (source, kind) in {("sysmon", 1), ("security", 4688)}:
            rule_id = "first-seen-process-path"
            title = "A process started from a new path"
            entity = [ntpath.normpath(path).casefold()]
        elif (source, kind) == ("sysmon", 3) and event["network"]["direction"] == "outbound":
            try:
                address = ip_address(event["network"]["dst"]["ip"])
            except ValueError:
                continue
            if address.is_unspecified or address.is_loopback or address.is_multicast:
                continue
            rule_id = "first-seen-process-destination"
            title = "A process connected to a new destination"
            entity = [ntpath.normpath(path).casefold(), str(address)]
        else:
            continue
        scope = json.dumps([rule_id, event["host"].casefold()], separators=(",", ":"))
        key = hashlib.sha256(json.dumps(entity, separators=(",", ":")).encode()).hexdigest()
        match = {"rule_id": rule_id, "title": title, "severity": "info", "attack": (),
                 "evidence_ids": (event["id"],), "plain_summary": title + " for this PC's learned baseline.",
                 "what_to_do": "Open the evidence and check whether the observation matches an expected change.",
                 "falsepositives": ("New apps, updates, and ordinary network activity can cause this.",)}
        finding, = findings_from_matches([match], [event])
        rare = None
        if rule_id == "first-seen-process-destination":
            rare, = findings_from_matches([{
                **match, "rule_id": "rare-process-destination",
                "title": "A process returned to a rarely observed destination",
                "plain_summary": "This process and destination pair accounted for at most 5% of this PC's outbound observations during learning.",
            }], [event])
        finding["rarity"] = "first seen"
        if rare is not None:
            rare["rarity"] = "rare"
        yield scope, key, finding, rare


def consume_detection_queue(store, rules, *, now=None, learning_hours=24):
    queued = store.pending_detections()
    if not queued:
        return 0
    identities = {identity for identity, _ in queued}
    events = [event for _, event in queued if event is not None]
    if events:
        window = max((rule.correlation.window for rule in rules if rule.correlation), default=timedelta())
        times = [datetime.fromisoformat(event["timestamp"]) for event in events]
        earliest = datetime.min.replace(tzinfo=timezone.utc)
        latest = datetime.max.replace(tzinfo=timezone.utc)
        lower, upper = min(times), max(times)
        context, limited = store.detection_context(
            (earliest if lower - earliest < window else lower - window).isoformat(timespec="microseconds"),
            (latest if latest - upper < window else upper + window).isoformat(timespec="microseconds"),
        )
        projected = [event_contract(event) for event in {event["id"]: event for event in context + events}.values()]
        result = evaluate_rules(rules, projected)
        matches = [item for item in findings_from_matches(result["matches"], projected)
                   if identities.intersection(item["evidence_ids"])]
        neighbors = [{"rule_id": "new-lan-neighbor", "title": "New device observed on the local network",
                      "severity": "info", "attack": (), "evidence_ids": (event["id"],),
                      "plain_summary": "The local neighbor cache recorded an address after the initial device baseline.",
                      "what_to_do": "Check whether you recognize the device or recently changed networks.",
                      "falsepositives": ("A randomized MAC address or a different network can cause this.",)}
                     for event in projected if event["id"] in identities and event["source"] == "neighbor"]
        matches.extend(findings_from_matches(neighbors, projected))
        policy_changes = [
            {"rule_id": "windows-audit-policy-change", "title": "Windows audit policy changed",
             "severity": "low", "attack": (), "evidence_ids": (event["id"],),
             "plain_summary": "Windows recorded an audit-policy change. Check whether it affects the events NORTH can collect.",
             "what_to_do": "Compare the event with approved policy changes."}
            for event in projected if event["id"] in identities
            and event["source"] == "security" and event["raw"]["event_type"] == 4719
        ]
        matches.extend(findings_from_matches(policy_changes, projected))
        if limited or result["timed_out_rule_ids"]:
            logging.getLogger(__name__).warning("Detection batch limits reached: context_limited=%s timed_out_rules=%d",
                                                limited, len(result["timed_out_rule_ids"]))
    else:
        matches = []
    now = now or datetime.now(timezone.utc)
    observations = list(baseline_observations([event_contract(event) for event in events]))
    store.complete_detections(identities, matches, observations=observations,
                              now=now.isoformat(timespec="microseconds"),
                              learning_until=(now + timedelta(hours=learning_hours)).isoformat(timespec="microseconds"))
    return len(queued)


async def run_detection_monitor(store):
    configured = os.getenv("NORTH_BASELINE_LEARNING_HOURS", "24")
    learning_hours = int(configured) if re.fullmatch(r"[0-9]{1,3}", configured) else 24
    if not 1 <= learning_hours <= 720:
        learning_hours = 24
    while True:
        try:
            rules = await run_in_threadpool(active_rules, store)
            consumed = await run_in_threadpool(consume_detection_queue, store, rules, learning_hours=learning_hours)
        except sqlite3.Error as error:
            logging.getLogger(__name__).warning("Local detection scan deferred: %s", type(error).__name__)
            consumed = 0
        await asyncio.sleep(1 if consumed == 100 else 5)
