from datetime import datetime, timedelta

from siem.detection_pipeline import DetectionPipeline
from siem.alert_factory import AlertFactory
from siem.risk_scorer import calculate_risk
from siem.alert_deduplicator import AlertDeduplicator
from siem.incident_manager import process_alert, close_incident
from siem.correlation import CorrelationEngine
from siem.detection_factory import DetectionFactory





def test_pipeline_detects_brute_force_attack():

    # Arrange
    pipeline = DetectionPipeline()

    


    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.10",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    # Act
    detections = pipeline.process(events)

    # Assert
    assert len(detections) >= 1

    brute_force_detections = [
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    ]

    assert len(brute_force_detections) == 1

    detection = brute_force_detections[0]

    assert detection["severity"] == "HIGH"
    assert detection["confidence"] == 1.0
    assert detection["entity"]["type"] == "ip"
    assert detection["entity"]["value"] == "192.168.1.10"
    assert detection["source_detector"] == "SlidingWindowDetector"
    assert detection["mitre_technique"] == "T1110"

    assert detection["evidence"]["failed_attempts"] == 5
    assert detection["evidence"]["detection_threshold"] == 5
    assert detection["evidence"]["window_seconds"] == 60



def test_detection_is_converted_to_unified_alert():

    # Arrange
    pipeline = DetectionPipeline()

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.10",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    # Act
    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    alert = AlertFactory.create_alert(
        brute_force_detection
    )

    # Assert
    assert alert["alert_id"].startswith("ALT-")

    assert alert["alert_type"] == "brute_force"
    assert alert["status"] == "NEW"

    assert alert["severity"] == "HIGH"
    assert alert["confidence"] == 1.0

    assert alert["entity"]["type"] == "ip"
    assert alert["entity"]["value"] == "192.168.1.10"

    assert alert["source"] == "SlidingWindowDetector"

    assert alert["detected_at"] == start_time + timedelta(seconds=40)
    assert alert["first_seen"] == start_time + timedelta(seconds=40)
    assert alert["last_seen"] == start_time + timedelta(seconds=40)

    assert alert["mitre_technique"] == "T1110"

    assert alert["deduplication_key"] == (
        "brute_force:ip:192.168.1.10"
    )

    assert alert["evidence"]["failed_attempts"] == 5


def test_alert_risk_is_calculated_from_real_detection():

    # Arrange
    pipeline = DetectionPipeline()

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.10",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    # Act
    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    alert = AlertFactory.create_alert(
        brute_force_detection
    )

    risk = calculate_risk(
        severity=alert["severity"],
        confidence=alert["confidence"],
        evidence=alert["evidence"]
    )

    # Assert
    assert risk == 77.5
    assert 0 <= risk <= 100


def test_identical_alerts_are_deduplicated():

    # Arrange
    pipeline = DetectionPipeline()
    deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.10",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    # Act
    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    first_alert = AlertFactory.create_alert(
        brute_force_detection
    )

    deduplicator.add_alert(first_alert)

    # Simulate the same alert arriving shortly afterward
    second_detection = dict(brute_force_detection)

    second_detection["timestamp"] = (
        first_alert["last_seen"] + timedelta(seconds=60)
    )

    second_alert = AlertFactory.create_alert(
        second_detection
    )

    existing_alert = deduplicator.find_existing_alert(
        second_alert["deduplication_key"],
        second_alert["detected_at"]
    )

    # Assert
    assert existing_alert is not None

    assert (
        existing_alert["alert_id"]
        == first_alert["alert_id"]
    )

    assert (
        existing_alert["deduplication_key"]
        == second_alert["deduplication_key"]
    )

    assert (
        existing_alert["last_seen"]
        == second_alert["detected_at"]
    )

    assert len(deduplicator.alerts) == 1


def test_alert_flows_into_incident_manager():

    # Arrange
    pipeline = DetectionPipeline()

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.10",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    # Act
    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    alert = AlertFactory.create_alert(
        brute_force_detection
    )

    incidents = {}

    result = process_alert(
        alert,
        incidents
    )

    # Assert
    assert len(result) == 1

    incident_id = next(iter(result))

    incident = result[incident_id]

    assert incident["status"] == "OPEN"
    assert incident["severity"] == "HIGH"

    assert incident["primary_entity"] == "192.168.1.10"

    assert len(incident["alerts"]) == 1
    assert incident["alerts"][0]["alert_id"] == alert["alert_id"]

    assert incident["created_at"] == alert["detected_at"]
    assert incident["updated_at"] == alert["detected_at"]



def test_multiple_alerts_for_same_entity_share_incident():

    # Arrange
    pipeline = DetectionPipeline()
    incidents = {}

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.10",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    # Act
    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    first_alert = AlertFactory.create_alert(
        brute_force_detection
    )

    # Create a second alert representing another detection
    second_alert = {
        **first_alert,
        "alert_id": "ALT-SECOND",
        "alert_type": "suspicious_login",
        "severity": "HIGH",
        "detected_at": start_time + timedelta(seconds=50),
        "last_seen": start_time + timedelta(seconds=50),
        "deduplication_key": "suspicious_login:ip:192.168.1.10"
    }

    incidents = process_alert(
        first_alert,
        incidents
    )

    incidents = process_alert(
        second_alert,
        incidents
    )

    # Assert
    assert len(incidents) == 1

    incident = next(iter(incidents.values()))

    assert incident["status"] == "OPEN"

    assert incident["primary_entity"] == "192.168.1.10"

    assert len(incident["alerts"]) == 2

    assert incident["severity"] == "HIGH"


def test_higher_severity_alert_escalates_existing_incident():

    # Arrange
    pipeline = DetectionPipeline()
    incidents = {}

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.20",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    high_alert = AlertFactory.create_alert(
        brute_force_detection
    )

    # Create a lower-severity version of the same alert
    medium_alert = {
        **high_alert,
        "alert_id": "ALT-MEDIUM",
        "severity": "MEDIUM",
        "detected_at": start_time,
        "last_seen": start_time,
    }

    # First create MEDIUM incident
    incidents = process_alert(
        medium_alert,
        incidents
    )

    incident = next(iter(incidents.values()))

    assert incident["severity"] == "MEDIUM"

    # Then process HIGH alert
    high_alert["detected_at"] = start_time + timedelta(seconds=10)
    high_alert["last_seen"] = start_time + timedelta(seconds=10)

    incidents = process_alert(
        high_alert,
        incidents
    )

    # Assert escalation
    assert len(incidents) == 1

    incident = next(iter(incidents.values()))

    assert incident["severity"] == "HIGH"

    assert len(incident["alerts"]) == 2


def test_lower_severity_alert_does_not_downgrade_incident():

    # Arrange
    pipeline = DetectionPipeline()
    incidents = {}

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.30",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    high_alert = AlertFactory.create_alert(
        brute_force_detection
    )

    # Create the HIGH incident first
    incidents = process_alert(
        high_alert,
        incidents
    )

    incident = next(iter(incidents.values()))

    assert incident["severity"] == "HIGH"

    # Create a lower-severity alert
    medium_alert = {
        **high_alert,
        "alert_id": "ALT-MEDIUM",
        "severity": "MEDIUM",
        "detected_at": start_time + timedelta(seconds=10),
        "last_seen": start_time + timedelta(seconds=10),
    }

    # Process lower-severity alert
    incidents = process_alert(
        medium_alert,
        incidents
    )

    # Assert
    assert len(incidents) == 1

    incident = next(iter(incidents.values()))

    assert incident["severity"] == "HIGH"

    assert len(incident["alerts"]) == 2


def test_closed_incident_does_not_reuse_for_new_alert():

    # Arrange
    pipeline = DetectionPipeline()
    incidents = {}

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    events = []

    for i in range(5):
        events.append(
            {
                "status": "failed",
                "ip": "192.168.1.40",
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
        )

    detections = pipeline.process(events)

    brute_force_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force"
    )

    first_alert = AlertFactory.create_alert(
        brute_force_detection
    )

    # Create first incident
    incidents = process_alert(
        first_alert,
        incidents
    )

    assert len(incidents) == 1

    first_incident = next(iter(incidents.values()))

    first_incident_id = first_incident["incident_id"]

    assert first_incident["status"] == "OPEN"

    # Close the incident
    close_incident(
        incidents,
        "192.168.1.40"
    )

    assert first_incident["status"] == "CLOSED"

    # Create a later alert from the same IP
    second_alert = {
        **first_alert,
        "alert_id": "ALT-SECOND",
        "detected_at": start_time + timedelta(minutes=5),
        "last_seen": start_time + timedelta(minutes=5),
    }

    # Process the new alert
    incidents = process_alert(
        second_alert,
        incidents
    )

    # Assert
    assert len(incidents) == 2

    second_incident = incidents[
        "INC-002"
    ]

    assert second_incident["status"] == "OPEN"

    assert second_incident["primary_entity"] == "192.168.1.40"

    assert second_incident["incident_id"] != first_incident_id

    assert len(second_incident["alerts"]) == 1

def test_different_entities_create_separate_incidents():

    # Arrange
    pipeline = DetectionPipeline()
    incidents = {}

    start_time = datetime(2026, 9, 28, 10, 0, 0)

    def create_events(ip):

        return [
            {
                "status": "failed",
                "ip": ip,
                "user": "admin",
                "host_name": "server-01",
                "timestamp": start_time + timedelta(seconds=i * 10),
            }
            for i in range(5)
        ]

    # Act
    detections_one = pipeline.process(
        create_events("192.168.1.10")
    )

    detections_two = pipeline.process(
        create_events("192.168.1.20")
    )

    detection_one = next(
        detection
        for detection in detections_one
        if detection["detection_type"] == "brute_force"
    )

    detection_two = next(
        detection
        for detection in detections_two
        if detection["detection_type"] == "brute_force"
    )

    alert_one = AlertFactory.create_alert(
        detection_one
    )

    alert_two = AlertFactory.create_alert(
        detection_two
    )

    incidents = process_alert(
        alert_one,
        incidents
    )

    incidents = process_alert(
        alert_two,
        incidents
    )

    # Assert
    assert len(incidents) == 2

    incident_entities = {
        incident["primary_entity"]
        for incident in incidents.values()
    }

    assert incident_entities == {
        "192.168.1.10",
        "192.168.1.20"
    }


def test_correlated_brute_force_success_flows_to_alert():

    # Arrange
    pipeline = DetectionPipeline()

    start_time = datetime(2026, 9, 28, 11, 0, 0)

    events = [
        {
            "status": "failed",
            "ip": "192.168.1.50",
            "user": "admin",
            "host_name": "server-01",
            "timestamp": start_time,
        },
        {
            "status": "failed",
            "ip": "192.168.1.50",
            "user": "admin",
            "host_name": "server-01",
            "timestamp": start_time + timedelta(seconds=20),
        },
        {
            "status": "failed",
            "ip": "192.168.1.50",
            "user": "admin",
            "host_name": "server-01",
            "timestamp": start_time + timedelta(seconds=40),
        },
        {
            "status": "success",
            "ip": "192.168.1.50",
            "user": "admin",
            "host_name": "server-01",
            "timestamp": start_time + timedelta(seconds=50),
        },
    ]

    # Act
    detections = pipeline.process(events)

    correlation_detection = next(
        detection
        for detection in detections
        if detection["detection_type"] == "brute_force_success"
    )

    alert = AlertFactory.create_alert_from_correlation(
        correlation_detection
    )

    # Assert
    assert correlation_detection["detection_type"] == "brute_force_success"

    assert correlation_detection["ip"] == "192.168.1.50"

    assert correlation_detection["failed_count"] == 3

    assert correlation_detection["severity"] == "LOW"

    assert alert["alert_type"] == "brute_force_success"

    assert alert["entity"]["type"] == "ip"

    assert alert["entity"]["value"] == "192.168.1.50"

    assert alert["source"] == "correlation_engine"

    assert alert["confidence"] == 1.0


