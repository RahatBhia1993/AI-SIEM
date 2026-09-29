from datetime import datetime

from siem.normalization import normalize_log
from siem.analysis import analyze_logs
from siem.rule_engine import evaluate_rules
from siem.incident_manager import process_alert
from siem.entity_tracker import process_entity
from siem.storage import (
    save_alerts,
    save_incidents,
    save_entities
)
from siem.utils import flatten_alerts
from siem.detection_pipeline import DetectionPipeline
from siem.alert_factory import AlertFactory
from siem.alert_deduplicator import AlertDeduplicator

from rules.rule_loader import load_rules

from simulations.brute_force_simulation import BruteForceSimulation


def run_pipeline(raw_logs):

    # ==========================================
    # STEP 1 : NORMALIZATION
    # ==========================================

    normalized_logs = []

    for log in raw_logs:

        event = normalize_log(log)

        normalized_logs.append(event)

    # ==========================================
    # STEP 2 : DETECTION PIPELINE
    # ==========================================

    detection_pipeline = DetectionPipeline()

    detections = detection_pipeline.process(
        normalized_logs
    )

    # Separate detections by detector type

    sliding_window_alerts = [
        detection
        for detection in detections
        if detection.get("detection_type") == "brute_force"
    ]

    burst_detections = [
        detection
        for detection in detections
        if detection.get("detection_type") == "burst"
    ]

    # ==========================================
    # STEP 3 : ANALYSIS
    # ==========================================

    metrics = analyze_logs(
        normalized_logs
    )

    # ==========================================
    # STEP 4 : LOAD RULES
    # ==========================================

    rules = load_rules(
        "rules/brute_force.json"
    )

    # ==========================================
    # STEP 5 : RULE ENGINE
    # ==========================================

    rule_alerts = evaluate_rules(
        metrics,
        rules
    )

    # ==========================================
    # STEP 6 : CORRELATION
    # ==========================================

    correlated_alerts = [
        detection
        for detection in detections
        if "correlation_type" in detection
    ]

    # ==========================================
    # STEP 7 : CREATE UNIFIED ALERTS
    # ==========================================

    alert_deduplicator = AlertDeduplicator(
        window_seconds=300
    )

    alerts = []

    # ------------------------------------------
    # Detection Alerts
    # ------------------------------------------

    for detection in detections:

        # Skip correlation detections here.
        # They are converted separately below.
        if "correlation_type" in detection:
            continue

        alert = AlertFactory.create_alert(
            detection
        )

        existing_alert = alert_deduplicator.find_existing_alert(
            alert["deduplication_key"],
            alert["last_seen"]
        )

        if existing_alert is None:

            alert_deduplicator.add_alert(
                alert
            )

            alerts.append(
                alert
            )

    # ------------------------------------------
    # Correlation Alerts
    # ------------------------------------------

    for correlation in correlated_alerts:

        alert = AlertFactory.create_alert_from_correlation(
            correlation
        )

        existing_alert = alert_deduplicator.find_existing_alert(
            alert["deduplication_key"],
            alert["last_seen"]
        )

        if existing_alert is None:

            alert_deduplicator.add_alert(
                alert
            )

            alerts.append(
                alert
            )

    # ------------------------------------------
    # Rule Engine Alerts
    # ------------------------------------------

    for _, rule_alert_list in rule_alerts.items():

        for rule_alert in rule_alert_list:

            alert = AlertFactory.create_alert_from_rule(
                rule_alert
            )

            existing_alert = alert_deduplicator.find_existing_alert(
                alert["deduplication_key"],
                alert["last_seen"]
            )

            if existing_alert is None:

                alert_deduplicator.add_alert(
                    alert
                )

                alerts.append(
                    alert
                )

    # ==========================================
    # STEP 8 : INCIDENT MANAGEMENT
    # ==========================================

    incidents = {}
    entities = {}

    for alert in alerts:

        # The unified alert stores the entity as:
        #
        # "entity": {
        #     "type": "ip",
        #     "value": "1.1.1.1"
        # }
        #
        # The existing IncidentManager expects:
        #
        # alert["ip"]

        alert["ip"] = alert["entity"]["value"]

        process_alert(
            alert,
            incidents
        )

        incident_id = incidents[
            alert["ip"]
        ]["incident_id"]

        process_entity(
            alert,
            entities,
            incident_id
        )

    # ==========================================
    # RETURN RESULTS
    # ==========================================

    return {

        "normalized_logs": normalized_logs,

        "detections": detections,

        "sliding_window_alerts": sliding_window_alerts,

        "burst_detections": burst_detections,

        "metrics": metrics,

        "rule_alerts": rule_alerts,

        "correlated_alerts": correlated_alerts,

        "alerts": alerts,

        "incidents": incidents,

        "entities": entities

    }


# ==================================================
# MAIN EXECUTION
# ==================================================

if __name__ == "__main__":

    # ==========================================
    # CREATE SIMULATION
    # ==========================================

    simulation = BruteForceSimulation(
        attacker_ip="1.1.1.1",
        failed_attempts=5
    )

    raw_logs = simulation.generate_events()

    # Normal user

    raw_logs.append(
        {
            "ip": "2.2.2.2",
            "action": "success login",
            "timestamp": datetime.now()
        }
    )

    # ==========================================
    # RUN PIPELINE
    # ==========================================

    result = run_pipeline(
        raw_logs
    )

    # ==========================================
    # PREPARE STORAGE DATA
    # ==========================================

    alerts = result["alerts"]

    incidents = list(
        result["incidents"].values()
    )

    entities = list(
        result["entities"].values()
    )

    # ==========================================
    # SAVE RESULTS
    # ==========================================

    try:

        save_alerts(
            alerts
        )

        save_incidents(
            incidents
        )

        save_entities(
            entities
        )

    except Exception as e:

        print(
            f"Storage error: {e}"
        )

    # ==========================================
    # DISPLAY RESULTS
    # ==========================================

    print("\n" + "=" * 60)
    print("ALL DETECTIONS")
    print("=" * 60)
    print(
        result["detections"]
    )

    print("\n" + "=" * 60)
    print("UNIFIED ALERTS")
    print("=" * 60)
    print(
        result["alerts"]
    )

    print("\n" + "=" * 60)
    print("SLIDING WINDOW ALERTS")
    print("=" * 60)
    print(
        result["sliding_window_alerts"]
    )

    print("\n" + "=" * 60)
    print("BURST DETECTIONS")
    print("=" * 60)
    print(
        result["burst_detections"]
    )

    print("\n" + "=" * 60)
    print("METRICS")
    print("=" * 60)
    print(
        result["metrics"]
    )

    print("\n" + "=" * 60)
    print("RULE ALERTS")
    print("=" * 60)
    print(
        result["rule_alerts"]
    )

    print("\n" + "=" * 60)
    print("CORRELATED ALERTS")
    print("=" * 60)
    print(
        result["correlated_alerts"]
    )

    print("\n" + "=" * 60)
    print("INCIDENTS")
    print("=" * 60)
    print(
        result["incidents"]
    )

    print("\n" + "=" * 60)
    print("ENTITIES")
    print("=" * 60)
    print(
        result["entities"]
    )
