from datetime import datetime, timezone

from siem.incident_manager import (
    process_alert,
    close_incident,
    find_open_incident,
)


def create_test_alert(alert_id, severity, ip, detected_at):

    return {
        "alert_id": alert_id,
        "severity": severity,
        "ip": ip,
        "detected_at": detected_at,
    }


def test_create_incident():

    incidents = {}

    detected_at = datetime.now(timezone.utc)

    alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        detected_at,
    )

    result = process_alert(alert, incidents)

    assert len(result) == 1

    incident_id = next(iter(result))
    incident = result[incident_id]

    assert incident["incident_id"] == incident_id
    assert incident["status"] == "OPEN"
    assert incident["severity"] == "HIGH"
    assert incident["primary_entity"] == "192.168.1.10"
    assert incident["created_at"] == detected_at
    assert incident["updated_at"] == detected_at
    assert len(incident["alerts"]) == 1


def test_add_alert_to_existing_incident():

    incidents = {}

    first_time = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 25, 10, 1, tzinfo=timezone.utc)

    first_alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        first_time,
    )

    second_alert = create_test_alert(
        "ALT-002",
        "HIGH",
        "192.168.1.10",
        second_time,
    )

    process_alert(first_alert, incidents)
    result = process_alert(second_alert, incidents)

    assert len(result) == 1

    incident_id = next(iter(result))
    incident = result[incident_id]

    assert len(incident["alerts"]) == 2
    assert incident["alerts"][0]["alert_id"] == "ALT-001"
    assert incident["alerts"][1]["alert_id"] == "ALT-002"
    assert incident["updated_at"] == second_time


def test_incident_severity_escalates():

    incidents = {}

    first_time = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 25, 10, 1, tzinfo=timezone.utc)

    high_alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        first_time,
    )

    critical_alert = create_test_alert(
        "ALT-002",
        "CRITICAL",
        "192.168.1.10",
        second_time,
    )

    process_alert(high_alert, incidents)
    result = process_alert(critical_alert, incidents)

    incident_id = next(iter(result))
    incident = result[incident_id]

    assert incident["severity"] == "CRITICAL"


def test_incident_severity_does_not_downgrade():

    incidents = {}

    first_time = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 25, 10, 1, tzinfo=timezone.utc)

    critical_alert = create_test_alert(
        "ALT-001",
        "CRITICAL",
        "192.168.1.10",
        first_time,
    )

    low_alert = create_test_alert(
        "ALT-002",
        "LOW",
        "192.168.1.10",
        second_time,
    )

    process_alert(critical_alert, incidents)
    result = process_alert(low_alert, incidents)

    incident_id = next(iter(result))
    incident = result[incident_id]

    assert incident["severity"] == "CRITICAL"


def test_incident_can_be_closed():

    incidents = {}

    detected_at = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)

    alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        detected_at,
    )

    process_alert(alert, incidents)

    incident_id = next(iter(incidents))

    close_incident(incidents, "192.168.1.10")

    incident = incidents[incident_id]

    assert incident["status"] == "CLOSED"


def test_new_alert_after_closed_incident_creates_new_incident():

    incidents = {}

    first_time = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 25, 10, 10, tzinfo=timezone.utc)

    first_alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        first_time,
    )

    second_alert = create_test_alert(
        "ALT-002",
        "CRITICAL",
        "192.168.1.10",
        second_time,
    )

    process_alert(first_alert, incidents)

    close_incident(incidents, "192.168.1.10")

    process_alert(second_alert, incidents)

    assert len(incidents) == 2

    incident_ids = list(incidents.keys())

    first_incident = incidents[incident_ids[0]]
    second_incident = incidents[incident_ids[1]]

    assert first_incident["status"] == "CLOSED"
    assert second_incident["status"] == "OPEN"

    assert first_incident["incident_id"] != second_incident["incident_id"]

    assert first_incident["primary_entity"] == "192.168.1.10"
    assert second_incident["primary_entity"] == "192.168.1.10"

    assert len(first_incident["alerts"]) == 1
    assert len(second_incident["alerts"]) == 1


def test_find_open_incident_returns_matching_open_incident():

    incidents = {}

    detected_at = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)

    alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        detected_at,
    )

    process_alert(alert, incidents)

    result = find_open_incident(
        incidents,
        "192.168.1.10",
    )

    assert result is not None
    assert result["status"] == "OPEN"
    assert result["primary_entity"] == "192.168.1.10"


def test_find_open_incident_returns_none_when_no_open_incident_exists():

    incidents = {}

    detected_at = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)

    alert = create_test_alert(
        "ALT-001",
        "HIGH",
        "192.168.1.10",
        detected_at,
    )

    process_alert(alert, incidents)

    close_incident(incidents, "192.168.1.10")

    result = find_open_incident(
        incidents,
        "192.168.1.10",
    )

    assert result is None
