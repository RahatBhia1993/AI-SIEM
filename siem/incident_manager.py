severity_rank = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

incident_counter = 0


def create_incident(alert):

    global incident_counter

    incident_counter += 1

    return {

        "incident_id": f"INC-{incident_counter:03d}",

        "status": "OPEN",

        "severity": alert["severity"],

        "primary_entity": alert["ip"],

        "created_at": alert["detected_at"],

        "updated_at": alert["detected_at"],

        "alerts": [alert]

    }


def process_alert(alert, incidents):

    ip = alert["ip"]

    if ip not in incidents:

        incidents[ip] = create_incident(alert)

    else:

        incident = incidents[ip]

        incident["alerts"].append(alert)

        incident["updated_at"] = alert["detected_at"]

        if severity_rank[alert["severity"]] > severity_rank[incident["severity"]]:

            incident["severity"] = alert["severity"]

    return incidents
