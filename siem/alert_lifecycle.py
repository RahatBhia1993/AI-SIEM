ALERT_STATES = {
    "NEW",
    "ACKNOWLEDGED",
    "RESOLVED",
    "CLOSED"
}


VALID_TRANSITIONS = {
    "NEW": {"ACKNOWLEDGED"},
    "ACKNOWLEDGED": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set()
}



def transition_alert(alert, new_status):

    status = alert["status"]

    if status not in ALERT_STATES:
        raise ValueError("Invalid current alert status")

    if new_status not in ALERT_STATES:
        raise ValueError("Invalid new alert status")

    if new_status not in VALID_TRANSITIONS[status]:
        raise ValueError("Invalid alert state transition")

    alert["status"] = new_status

    return alert