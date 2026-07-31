from datetime import datetime, timedelta

from siem.normalization import normalize_log
from siem.analysis import analyze_logs
from siem.rule_engine import evaluate_rules
from siem.correlation import correlate
from siem.incident_manager import process_alert
from siem.entity_tracker import process_entity
from siem.storage import (
    save_alerts,
    save_incidents,
    save_entities
)
from siem.utils import flatten_alerts
from siem.brute_force_detector import BruteForceDetector

from rules.rule_loader import load_rules


def run_pipeline(raw_logs):

    # ==========================================
    # STEP 1 : NORMALIZATION
    # ==========================================

    normalized_logs = []

    detector = BruteForceDetector(
        {
            "window_size": 60,
            "threshold": 5
        }
    )

    sliding_window_alerts = []

    for log in raw_logs:

        event = normalize_log(log)

        normalized_logs.append(event)

        alert = detector.process_event(event)

        if alert:
            sliding_window_alerts.append(alert)

    # ==========================================
    # STEP 2 : ANALYSIS
    # ==========================================

    metrics = analyze_logs(normalized_logs)

    # ==========================================
    # STEP 3 : LOAD RULES
    # ==========================================

    rules = load_rules(
        "rules/brute_force.json"
    )

    # ==========================================
    # STEP 4 : RULE ENGINE
    # ==========================================

    rule_alerts = evaluate_rules(
        metrics,
        rules
    )

    # ==========================================
    # STEP 5 : CORRELATION ENGINE
    # ==========================================

    correlated_alerts = correlate(metrics)

    # ==========================================
    # STEP 6 : INCIDENT + ENTITY MANAGEMENT
    # ==========================================

    incidents = {}
    entities = {}

    for rule_name, alerts in rule_alerts.items():

        for alert in alerts:

            process_alert(
                alert,
                incidents
            )

            incident_id = incidents[alert["ip"]]["incident_id"]

            process_entity(
                alert,
                entities,
                incident_id
            )

    for alert in correlated_alerts:

        process_alert(
            alert,
            incidents
        )

        incident_id = incidents[alert["ip"]]["incident_id"]

        process_entity(
            alert,
            entities,
            incident_id
        )

    return {

        "normalized_logs": normalized_logs,

        "sliding_window_alerts": sliding_window_alerts,

        "metrics": metrics,

        "rule_alerts": rule_alerts,

        "correlated_alerts": correlated_alerts,

        "incidents": incidents,

        "entities": entities

    }


# ==================================================
# MAIN EXECUTION
# ==================================================

if __name__ == "__main__":

    base = datetime.now()

    raw_logs = [

        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": base
        },
        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": base + timedelta(seconds=10)
        },
        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": base + timedelta(seconds=20)
        },
        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": base + timedelta(seconds=30)
        },
        {
            "ip": "1.1.1.1",
            "action": "failed login",
            "timestamp": base + timedelta(seconds=40)
        },
        {
            "ip": "1.1.1.1",
            "action": "success login",
            "timestamp": base + timedelta(seconds=50)
        },
        {
            "ip": "2.2.2.2",
            "action": "success login",
            "timestamp": base + timedelta(seconds=70)
        }

    ]

    result = run_pipeline(raw_logs)

    alerts = flatten_alerts(
        result["rule_alerts"]
    )

    incidents = list(
        result["incidents"].values()
    )

    entities = list(
        result["entities"].values()
    )

    try:

        save_alerts(alerts)

        save_incidents(incidents)

        save_entities(entities)

    except Exception as e:

        print(f"Storage error: {e}")

    print("\n" + "=" * 60)
    print("SLIDING WINDOW ALERTS")
    print("=" * 60)
    print(result["sliding_window_alerts"])

    print("\n" + "=" * 60)
    print("METRICS")
    print("=" * 60)
    print(result["metrics"])

    print("\n" + "=" * 60)
    print("RULE ALERTS")
    print("=" * 60)
    print(result["rule_alerts"])

    print("\n" + "=" * 60)
    print("CORRELATED ALERTS")
    print("=" * 60)
    print(result["correlated_alerts"])

    print("\n" + "=" * 60)
    print("INCIDENTS")
    print("=" * 60)
    print(result["incidents"])

    print("\n" + "=" * 60)
    print("ENTITIES")
    print("=" * 60)
    print(result["entities"])