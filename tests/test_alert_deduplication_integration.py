from datetime import timedelta

from siem.alert_factory import AlertFactory
from siem.alert_deduplicator import AlertDeduplicator


def test_alert_factory_output_can_be_deduplicated():

    detection = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 1.0,
        "entity": {
            "type": "ip",
            "value": "1.1.1.1"
        },
        "source_detector": "brute_force_detector",
        "timestamp": None
    }

    alert = AlertFactory.create_alert(detection)

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    deduplicator.add_alert(alert)

    current_time = alert["last_seen"] + timedelta(
        seconds=60
    )

    existing = deduplicator.find_existing_alert(
        alert["deduplication_key"],
        current_time
    )

    assert existing == alert


def test_duplicate_alert_updates_existing_alert():

    detection = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 1.0,
        "entity": {
            "type": "ip",
            "value": "1.1.1.1"
        },
        "source_detector": "brute_force_detector",
        "timestamp": None
    }

    alert = AlertFactory.create_alert(detection)

    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    deduplicator.add_alert(alert)

    new_alert_time = alert["last_seen"] + timedelta(
        seconds=60
    )

    existing = deduplicator.find_existing_alert(
        alert["deduplication_key"],
        new_alert_time
    )

    assert existing["alert_id"] == alert["alert_id"]
    assert existing["last_seen"] == new_alert_time
