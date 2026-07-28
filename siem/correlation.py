from datetime import datetime


def correlate(metrics):

    correlated_alerts = []

    for ip, data in metrics.items():

        if data["failed_logins"] >= 3 and data["successful_logins"] >= 1:

            alert = {

                "alert_id": None,

                "rule_name": "Login Correlation Detection",

                "ip": ip,

                "observed_value": {
                    "failed_logins": data["failed_logins"],
                    "successful_logins": data["successful_logins"]
                },

                "condition": "Failed logins followed by success",

                "severity": "HIGH",

                "mitre_technique": "T1110",

                "detected_at": datetime.utcnow().isoformat(),

                "first_seen": datetime.utcnow().isoformat(),

                "last_seen": datetime.utcnow().isoformat(),

                "reason": "Multiple failed logins followed by successful login"

            }

            correlated_alerts.append(alert)

    return correlated_alerts
