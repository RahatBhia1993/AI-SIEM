from datetime import datetime, timedelta

from siem.alert_factory import AlertFactory
from siem.alert_deduplicator import AlertDeduplicator

from main import run_pipeline


def test_duplicate_alert_is_deduplicated_in_pipeline():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    detection = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.9,
        "entity": {
            "type": "ip",
            "value": "1.1.1.1"
        },
        "source_detector": "brute_force_detector",
        "timestamp": datetime.now()
    }

    # First detection → create alert
    alert = AlertFactory.create_alert(detection)

    deduplicator.add_alert(alert)

    # Simulate duplicate 60 seconds later
    duplicate_time = alert["last_seen"] + timedelta(
        seconds=60
    )

    existing = deduplicator.find_existing_alert(
        alert["deduplication_key"],
        duplicate_time
    )

    assert existing is not None
    assert existing["alert_id"] == alert["alert_id"]
    assert existing["last_seen"] == duplicate_time


def test_duplicate_detections_create_one_alert():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    first_time = datetime.now()

    detection_1 = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.9,
        "entity": {
            "type": "ip",
            "value": "1.1.1.1"
        },
        "source_detector": "brute_force_detector",
        "timestamp": first_time
    }

    alert_1 = AlertFactory.create_alert(detection_1)

    deduplicator.add_alert(alert_1)

    # Second detection for the same IP
    second_time = first_time + timedelta(seconds=60)

    detection_2 = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.9,
        "entity": {
            "type": "ip",
            "value": "1.1.1.1"
        },
        "source_detector": "brute_force_detector",
        "timestamp": second_time
    }

    alert_2 = AlertFactory.create_alert(detection_2)

    existing = deduplicator.find_existing_alert(
        alert_2["deduplication_key"],
        second_time
    )

    assert existing is not None

    # Both detections should have the same deduplication key
    assert (
        alert_1["deduplication_key"]
        == alert_2["deduplication_key"]
    )

    # Original alert should remain
    assert existing["alert_id"] == alert_1["alert_id"]

    # last_seen should move forward
    assert existing["last_seen"] == second_time


def test_duplicate_detection_outside_window_creates_new_alert():

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    first_time = datetime.now()

    detection_1 = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.9,
        "entity": {
            "type": "ip",
            "value": "1.1.1.1"
        },
        "source_detector": "brute_force_detector",
        "timestamp": first_time
    }

    alert_1 = AlertFactory.create_alert(detection_1)

    deduplicator.add_alert(alert_1)

    # 6 minutes later — outside 5-minute window
    second_time = first_time + timedelta(
        seconds=360
    )

    existing = deduplicator.find_existing_alert(
        alert_1["deduplication_key"],
        second_time
    )

    assert existing is None


def test_run_pipeline_returns_deduplicated_alerts():

    raw_logs = [
        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": datetime.now()
        },
        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": datetime.now()
        }
    ]

    result = run_pipeline(raw_logs)

    alerts = result["alerts"]

    assert isinstance(alerts, list)

    for alert in alerts:
        assert "alert_id" in alert
        assert "deduplication_key" in alert
        assert "first_seen" in alert
        assert "last_seen" in alert
