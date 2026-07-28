def create_entity(alert):

    return {

        "type": "ip",

        "value": alert["ip"],

        "first_seen": alert["detected_at"],

        "last_seen": alert["detected_at"],

        "alert_count": 1,

        "alerts": [alert],

        "incidents": []

    }


def update_entity(entity, alert):

    entity["last_seen"] = alert["detected_at"]

    entity["alert_count"] += 1

    entity["alerts"].append(alert)

    return entity


def process_entity(alert, entities, incident_id=None):

    ip = alert["ip"]

    if ip not in entities:

        entities[ip] = create_entity(alert)

    else:

        update_entity(
            entities[ip],
            alert
        )

    if incident_id:

        if incident_id not in entities[ip]["incidents"]:

            entities[ip]["incidents"].append(
                incident_id
            )

    return entities
