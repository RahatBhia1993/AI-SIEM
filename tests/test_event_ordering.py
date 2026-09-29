from datetime import datetime, timedelta

from siem.event_ordering import EventOrdering


def make_event(ip, seconds):
    return {
        "ip": ip,
        "timestamp": datetime(2026, 9, 28, 10, 0, 0)
        + timedelta(seconds=seconds),
    }


def test_events_are_released_in_timestamp_order():
    ordering = EventOrdering(buffer_size=3)

    ordering.process_event(make_event("10.0.0.1", 30))
    ordering.process_event(make_event("10.0.0.1", 10))

    result = ordering.process_event(
        make_event("10.0.0.1", 20)
    )

    assert result is not None
    assert [
        event["timestamp"].second
        for event in result
    ] == [10, 20, 30]


def test_entities_have_independent_buffers():
    ordering = EventOrdering(buffer_size=2)

    assert ordering.process_event(
        make_event("10.0.0.1", 20)
    ) is None

    assert ordering.process_event(
        make_event("10.0.0.2", 10)
    ) is None

    result = ordering.process_event(
        make_event("10.0.0.1", 10)
    )

    assert result is not None
    assert [
        event["timestamp"].second
        for event in result
    ] == [10, 20]


def test_flush_returns_remaining_events_in_order():
    ordering = EventOrdering(buffer_size=5)

    ordering.process_event(make_event("10.0.0.1", 30))
    ordering.process_event(make_event("10.0.0.1", 10))
    ordering.process_event(make_event("10.0.0.1", 20))

    result = ordering.flush()

    assert "10.0.0.1" in result
    assert [
        event["timestamp"].second
        for event in result["10.0.0.1"]
    ] == [10, 20, 30]


def test_flush_clears_all_buffers():
    ordering = EventOrdering(buffer_size=5)

    ordering.process_event(make_event("10.0.0.1", 10))

    result = ordering.flush()

    assert result
    assert ordering.buffers == {}


def test_reset_clears_all_buffers():
    ordering = EventOrdering(buffer_size=5)

    ordering.process_event(make_event("10.0.0.1", 10))
    ordering.process_event(make_event("10.0.0.2", 20))

    ordering.reset()

    assert ordering.buffers == {}


def test_missing_ip_uses_unknown_entity():
    ordering = EventOrdering(buffer_size=2)

    event_one = {
        "timestamp": datetime(2026, 9, 28, 10, 0, 0)
    }

    event_two = {
        "timestamp": datetime(2026, 9, 28, 10, 0, 1)
    }

    assert ordering.process_event(event_one) is None

    result = ordering.process_event(event_two)

    assert result is not None
    assert len(result) == 2
    assert "unknown" not in ordering.buffers
