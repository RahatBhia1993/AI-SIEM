from datetime import datetime, timedelta
from siem.alert_deduplicator import AlertDeduplicator


def test_find_existing_alert_returns_none_for_missing_key():

    deduplicator = AlertDeduplicator()

    result = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1", datetime.now()
    )

    assert result is None


def test_find_existing_alert_returns_existing_alert():

    deduplicator = AlertDeduplicator()

    alert = {
        "alert_id": "ALT-12345678",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": datetime.now()

    }

    deduplicator.alerts[
        "brute_force:ip:1.1.1.1"
    ] = alert

    result = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1", datetime.now()
    )

    assert result == alert


def test_add_alert_stores_alert():

    deduplicator = AlertDeduplicator()

    alert = {
        "alert_id": "ALT-12345678",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": datetime.now()

    }

    deduplicator.add_alert(alert)

    result = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1", datetime.now()
    )

    assert result == alert


def test_existing_alert_is_preserved():

    deduplicator = AlertDeduplicator()

    alert_a = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "severity": "HIGH",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": datetime.now()

    }

    deduplicator.add_alert(alert_a)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1", datetime.now()
    )

    assert existing == alert_a

def test_alert_within_deduplication_window_is_found():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    last_seen = datetime.now()

    alert = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": datetime.now()
    }

    deduplicator.add_alert(alert)

    new_alert_time = last_seen + timedelta(seconds=60)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1", new_alert_time
    )

    assert existing == alert


def test_alert_outside_deduplication_window_is_not_found():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    last_seen = datetime.now()

    alert = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": datetime.now()
    }

    deduplicator.add_alert(alert)

    new_alert_time = last_seen + timedelta(seconds=360)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        new_alert_time
    )

    assert existing is None

def test_alert_at_exact_deduplication_window_is_found():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    last_seen = datetime.now()

    alert = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": datetime.now()
    }

    deduplicator.add_alert(alert)

    new_alert_time = last_seen + timedelta(seconds=300)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        new_alert_time
    )

    assert existing == alert


def test_duplicate_alert_updates_last_seen():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    last_seen = datetime.now()

    alert = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": last_seen
    }

    deduplicator.add_alert(alert)

    new_alert_time = last_seen + timedelta(seconds=60)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        new_alert_time
    )

    assert existing == alert
    assert existing["last_seen"] == new_alert_time


def test_duplicate_alert_outside_window_does_not_update_last_seen():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    last_seen = datetime.now()

    alert = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": last_seen
    }

    deduplicator.add_alert(alert)

    new_alert_time = last_seen + timedelta(seconds=360)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        new_alert_time
    )

    assert existing is None
    assert alert["last_seen"] == last_seen


def test_new_alert_after_window_replaces_old_alert():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    first_seen = datetime.now()

    alert_a = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": first_seen
    }

    deduplicator.add_alert(alert_a)

    new_alert_time = first_seen + timedelta(seconds=360)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        new_alert_time
    )

    assert existing is None

    alert_b = {
        "alert_id": "ALT-222",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": new_alert_time
    }

    deduplicator.add_alert(alert_b)

    result = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        new_alert_time
    )

    assert result == alert_b


def test_repeated_duplicates_extend_deduplication_window():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    first_seen = datetime.now()

    alert = {
        "alert_id": "ALT-111",
        "alert_type": "brute_force",
        "deduplication_key": "brute_force:ip:1.1.1.1",
        "last_seen": first_seen
    }

    deduplicator.add_alert(alert)

    second_time = first_seen + timedelta(seconds=60)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        second_time
    )

    assert existing == alert
    assert alert["last_seen"] == second_time

    third_time = second_time + timedelta(seconds=240)

    existing = deduplicator.find_existing_alert(
        "brute_force:ip:1.1.1.1",
        third_time
    )

    assert existing == alert
    assert alert["last_seen"] == third_time

