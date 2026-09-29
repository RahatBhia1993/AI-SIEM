from datetime import datetime

from siem.alert_factory import AlertFactory


def test_detection_to_unified_alert():

    timestamp = datetime.utcnow()

    detection = {
        "detection_id": "DET-001",
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.9,
        "timestamp": timestamp,
        "entity": {
            "type": "ip",
            "value": "192.168.1.10"
        },
        "source_detector": "BruteForceDetector",
        "mitre_technique": "T1110",
        "evidence": {
            "failed_attempts": 5
        }
    }

    alert = AlertFactory.create_alert(detection)

    assert alert["alert_id"].startswith("ALT-")
    assert alert["alert_type"] == "brute_force"
    assert alert["status"] == "NEW"
    assert alert["severity"] == "HIGH"
    assert alert["confidence"] == 0.9

    assert alert["entity"]["type"] == "ip"
    assert alert["entity"]["value"] == "192.168.1.10"

    assert alert["source"] == "BruteForceDetector"

    assert alert["detected_at"] == timestamp
    assert alert["first_seen"] == timestamp
    assert alert["last_seen"] == timestamp

    assert alert["mitre_technique"] == "T1110"

    assert alert["evidence"]["failed_attempts"] == 5

    assert (
        alert["deduplication_key"]
        == "brute_force:ip:192.168.1.10"
    )


def test_correlation_to_unified_alert():

    first_seen = datetime.utcnow()
    success_time = datetime.utcnow()

    correlation = {
        "correlation_type": "brute_force_success",
        "ip": "192.168.1.20",
        "failed_count": 5,
        "first_seen": first_seen,
        "users": ["alice", "bob"],
        "host_names": ["server01"],
        "success_time": success_time,
        "severity": "HIGH",
        "reason": (
            "Multiple failed logins followed by "
            "successful login"
        )
    }

    alert = AlertFactory.create_alert_from_correlation(
        correlation
    )

    assert alert["alert_id"].startswith("ALT-")
    assert alert["alert_type"] == "brute_force_success"
    assert alert["status"] == "NEW"
    assert alert["severity"] == "HIGH"
    assert alert["confidence"] == 1.0

    assert alert["entity"]["type"] == "ip"
    assert alert["entity"]["value"] == "192.168.1.20"

    assert alert["source"] == "correlation_engine"

    assert alert["detected_at"] == success_time
    assert alert["first_seen"] == first_seen
    assert alert["last_seen"] == success_time

    assert alert["evidence"]["failed_attempts"] == 5

    assert alert["evidence"]["users"] == [
        "alice",
        "bob"
    ]

    assert alert["evidence"]["host_names"] == [
        "server01"
    ]

    assert (
        alert["deduplication_key"]
        == "brute_force_success:ip:192.168.1.20"
    )


def test_rule_to_unified_alert():

    detected_at = datetime.utcnow()
    first_seen = detected_at
    last_seen = detected_at

    rule_finding = {
        "alert_id": "ALERT-001",
        "rule_name": "high_failed_logins",
        "ip": "192.168.1.30",
        "observed_value": 7,
        "condition": ">= 5",
        "severity": "HIGH",
        "mitre_technique": "T1110",
        "detected_at": detected_at,
        "first_seen": first_seen,
        "last_seen": last_seen
    }

    alert = AlertFactory.create_alert_from_rule(
        rule_finding
    )

    assert alert["alert_id"].startswith("ALT-")
    assert alert["alert_type"] == "rule_violation"
    assert alert["status"] == "NEW"
    assert alert["severity"] == "HIGH"
    assert alert["confidence"] == 1.0

    assert alert["entity"]["type"] == "ip"
    assert alert["entity"]["value"] == "192.168.1.30"

    assert alert["source"] == "rule_engine"

    assert alert["detected_at"] == detected_at
    assert alert["first_seen"] == first_seen
    assert alert["last_seen"] == last_seen

    assert alert["mitre_technique"] == "T1110"

    assert (
        alert["evidence"]["rule_name"]
        == "high_failed_logins"
    )

    assert (
        alert["evidence"]["observed_value"]
        == 7
    )

    assert (
        alert["evidence"]["condition"]
        == ">= 5"
    )

    assert (
        alert["deduplication_key"]
        == "rule_violation:ip:192.168.1.30"
    )


def test_all_alerts_have_unified_schema():

    required_fields = {
        "alert_id",
        "alert_type",
        "status",
        "severity",
        "confidence",
        "entity",
        "source",
        "detected_at",
        "first_seen",
        "last_seen",
        "mitre_technique",
        "evidence",
        "deduplication_key"
    }

    detection = {
        "detection_type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.9,
        "timestamp": datetime.utcnow(),
        "entity": {
            "type": "ip",
            "value": "10.0.0.1"
        },
        "source_detector": "BruteForceDetector",
        "mitre_technique": "T1110",
        "evidence": {
            "failed_attempts": 5
        }
    }

    correlation = {
        "correlation_type": "brute_force_success",
        "ip": "10.0.0.2",
        "failed_attempts": 5,
        "first_seen": datetime.utcnow(),
        "users": ["alice"],
        "host_names": ["server01"],
        "success_time": datetime.utcnow(),
        "severity": "HIGH",
        "reason": (
            "Failed logins followed by "
            "successful login"
        )
    }

    rule_finding = {
        "rule_name": "high_failed_logins",
        "ip": "10.0.0.3",
        "observed_value": 7,
        "condition": ">= 5",
        "severity": "HIGH",
        "mitre_technique": "T1110",
        "detected_at": datetime.utcnow(),
        "first_seen": datetime.utcnow(),
        "last_seen": datetime.utcnow()
    }

    alerts = [
        AlertFactory.create_alert(
            detection
        ),

        AlertFactory.create_alert_from_correlation(
            correlation
        ),

        AlertFactory.create_alert_from_rule(
            rule_finding
        )
    ]

    for alert in alerts:

        assert required_fields.issubset(
            alert.keys()
        )
