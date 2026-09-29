severity_rank = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def create_incident(alert, incidents):

    incident_number = len(incidents) + 1

    entity = alert.get("entity", {})

    if isinstance(entity, dict):
        primary_entity = entity.get("value")
    else:
        primary_entity = None

    if primary_entity is None:
        primary_entity = alert.get("ip")

    return {
        "incident_id": f"INC-{incident_number:03d}",
        "status": "OPEN",
        "severity": alert["severity"],
        "primary_entity": primary_entity,
        "created_at": alert["detected_at"],
        "updated_at": alert["detected_at"],
        "alerts": [alert]
    }



def find_open_incident(incidents, ip):

    for incident_id, incident in incidents.items():

        if (
            incident["status"] == "OPEN"
            and incident["primary_entity"] == ip
        ):
            return incident

    return None


def process_alert(alert, incidents):

    ip = alert.get("entity", {}).get("value")
    if ip is None:
        ip= alert.get("ip")

    found = find_open_incident(
        incidents,
        ip
    )

    # Existing open incident
    if found:

        found["alerts"].append(alert)

        found["updated_at"] = alert["detected_at"]

        # Escalate severity, but never downgrade it
        if (
            severity_rank[alert["severity"]]
            > severity_rank[found["severity"]]
        ):
            found["severity"] = alert["severity"]

    # No open incident exists
    else:

        incident = create_incident(
            alert,
            incidents
        )

        incidents[incident["incident_id"]] = incident

    return incidents


def close_incident(incidents, ip):

    incident = find_open_incident(
        incidents,
        ip
    )

    if incident:

        incident["status"] = "CLOSED"

    return incidents
