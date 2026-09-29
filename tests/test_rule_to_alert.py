from siem.rule_engine import evaluate_rules
from siem.alert_factory import AlertFactory


def test_rule_engine_to_unified_alert():

    metrics = {
        "192.168.1.50": {
            "failed_logins": 7,
            "successful_logins": 0,
            "ip_frequency": 7
        }
    }

    rules = [
        {
            "rule_name": "high_failed_logins",
            "metric": "failed_logins",
            "operator": ">=",
            "value": 5,
            "severity": "HIGH",
            "mitre_technique": "T1110"
        }
    ]

    rule_results = evaluate_rules(
        metrics,
        rules
    )

    assert "high_failed_logins" in rule_results

    findings = rule_results["high_failed_logins"]

    assert len(findings) == 1

    rule_finding = findings[0]

    assert rule_finding["rule_name"] == "high_failed_logins"
    assert rule_finding["ip"] == "192.168.1.50"
    assert rule_finding["observed_value"] == 7
    assert rule_finding["severity"] == "HIGH"

    alert = AlertFactory.create_alert_from_rule(
        rule_finding
    )

    assert alert["alert_id"].startswith("ALT-")

    assert alert["alert_type"] == "rule_violation"

    assert alert["status"] == "NEW"

    assert alert["severity"] == "HIGH"

    assert alert["confidence"] == 1.0

    assert alert["entity"]["type"] == "ip"

    assert alert["entity"]["value"] == "192.168.1.50"

    assert alert["source"] == "rule_engine"

    assert alert["mitre_technique"] == "T1110"

    assert alert["evidence"]["rule_name"] == (
        "high_failed_logins"
    )

    assert alert["evidence"]["observed_value"] == 7

    assert alert["evidence"]["condition"] == ">= 5"

    assert (
        alert["deduplication_key"]
        == "rule_violation:ip:192.168.1.50"
    )
