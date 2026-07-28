def flatten_alerts(rule_alerts):

    flattened_alerts = []

    for rule_name, alerts in rule_alerts.items():

        for alert in alerts:

            flattened_alerts.append(alert)

    return flattened_alerts
