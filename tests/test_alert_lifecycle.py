import pytest

from siem.alert_lifecycle import (
    ALERT_STATES,
    VALID_TRANSITIONS,
    transition_alert,
)


def make_alert(status="NEW"):
    return {
        "alert_id": "alert-001",
        "alert_type": "brute_force",
        "status": status,
        "severity": "HIGH",
        "confidence": 0.95,
        "entity": {
            "type": "IP",
            "value": "192.168.1.10",
        },
    }


def test_new_alert_can_be_acknowledged():
    alert = make_alert("NEW")

    result = transition_alert(alert, "ACKNOWLEDGED")

    assert result["status"] == "ACKNOWLEDGED"


def test_acknowledged_alert_can_be_resolved():
    alert = make_alert("ACKNOWLEDGED")

    result = transition_alert(alert, "RESOLVED")

    assert result["status"] == "RESOLVED"


def test_resolved_alert_can_be_closed():
    alert = make_alert("RESOLVED")

    result = transition_alert(alert, "CLOSED")

    assert result["status"] == "CLOSED"


def test_complete_alert_lifecycle():
    alert = make_alert("NEW")

    transition_alert(alert, "ACKNOWLEDGED")
    transition_alert(alert, "RESOLVED")
    transition_alert(alert, "CLOSED")

    assert alert["status"] == "CLOSED"


def test_invalid_current_status():
    alert = make_alert("INVALID")

    with pytest.raises(ValueError, match="Invalid current alert status"):
        transition_alert(alert, "ACKNOWLEDGED")


def test_invalid_new_status():
    alert = make_alert("NEW")

    with pytest.raises(ValueError, match="Invalid new alert status"):
        transition_alert(alert, "INVALID")


def test_cannot_skip_acknowledged_state():
    alert = make_alert("NEW")

    with pytest.raises(ValueError, match="Invalid alert state transition"):
        transition_alert(alert, "RESOLVED")


def test_cannot_skip_resolved_state():
    alert = make_alert("ACKNOWLEDGED")

    with pytest.raises(ValueError, match="Invalid alert state transition"):
        transition_alert(alert, "CLOSED")


def test_closed_alert_cannot_change_state():
    alert = make_alert("CLOSED")

    with pytest.raises(ValueError, match="Invalid alert state transition"):
        transition_alert(alert, "NEW")


def test_closed_alert_cannot_be_reopened():
    alert = make_alert("CLOSED")

    with pytest.raises(ValueError, match="Invalid alert state transition"):
        transition_alert(alert, "ACKNOWLEDGED")


def test_alert_data_is_preserved():
    alert = make_alert("NEW")

    transition_alert(alert, "ACKNOWLEDGED")

    assert alert["alert_id"] == "alert-001"
    assert alert["alert_type"] == "brute_force"
    assert alert["severity"] == "HIGH"
    assert alert["confidence"] == 0.95
    assert alert["entity"]["type"] == "IP"
    assert alert["entity"]["value"] == "192.168.1.10"
