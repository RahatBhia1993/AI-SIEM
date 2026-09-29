from datetime import datetime, timezone

alert_counter = 0


def evaluate(metric_value, operator, expected_value):

    if operator == ">":
        return metric_value > expected_value

    elif operator == ">=":
        return metric_value >= expected_value

    elif operator == "<":
        return metric_value < expected_value

    elif operator == "<=":
        return metric_value <= expected_value

    elif operator == "==":
        return metric_value == expected_value

    elif operator == "!=":
        return metric_value != expected_value

    return False


def evaluate_rules(metrics, rules):

    global alert_counter
    alerts = {}

    for rule in rules:

        rule_name = rule["rule_name"]
        metric_name = rule["metric"]

        if rule_name not in alerts:
            alerts[rule_name] = []

        for ip, data in metrics.items():

            if metric_name not in data:
                continue

            value = data[metric_name]

            result = evaluate(
                value,
                rule["operator"],
                rule["value"]
            )

            if result:

                alert_counter += 1
                timestamp = datetime.now(timezone.utc).isoformat()

                alert = {

                    "alert_id": f"ALERT-{alert_counter:03d}",

                    "rule_name": rule_name,

                    "ip": ip,

                    "observed_value": value,

                    "condition": f"{rule['operator']} {rule['value']}",

                    "severity": rule.get(
                        "severity",
                        "MEDIUM"
                    ),

                    "mitre_technique": rule.get(
                        "mitre_technique",
                        "UNKNOWN"
                    ),

                    "detected_at": timestamp,

                    "first_seen": timestamp,

                    "last_seen": timestamp

                }


                alerts[rule_name].append(alert)

    return alerts