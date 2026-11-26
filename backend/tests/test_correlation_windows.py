from datetime import datetime, timedelta, timezone

from north import events_in_window, threshold_groups


def event(identity, seconds, group="a"):
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return {"id": identity, "timestamp": timestamp.isoformat(timespec="microseconds"), "group": group}


def test_sequence_window_includes_both_boundaries():
    candidates = [event("before", -1), event("start", 0), event("end", 120), event("after", 120.001)]
    assert events_in_window(event("anchor", 0), candidates, timedelta(seconds=120)) == candidates[1:3]


def test_threshold_sorts_groups_and_consumes_each_match_once():
    first, second, edge = event("one", 0), event("two", 60), event("edge", 300)
    inputs = [edge, event("different", 10, "b"), event("after", 301), second, first]
    assert list(threshold_groups(inputs, group_key=lambda item: item["group"], count=3,
                                 window=timedelta(minutes=5))) == [("a", [first, second, edge])]


def test_threshold_discards_records_just_outside_the_window():
    inputs = [event("one", 0), event("two", 60), event("late", 300.001)]
    assert list(threshold_groups(inputs, group_key=lambda item: item["group"], count=3,
                                 window=timedelta(minutes=5))) == []
