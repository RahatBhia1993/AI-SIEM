from datetime import datetime
import uuid


class AlertFactory:

    @staticmethod
    def create_alert(detection):
        """
        Convert an existing Detection into a Unified Alert.
        """

        timestamp = detection.get("timestamp")

        if timestamp is None:
            timestamp = datetime.utcnow()

        entity = detection.get("entity", {})

        alert_type = detection.get(
            "detection_type",
            "unknown"
        )

        deduplication_key = (
            f"{alert_type}:"
            f"{entity.get('type', 'unknown')}:"
            f"{entity.get('value', 'unknown')}"
        )

        return {
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",

            "alert_type": alert_type,

            "status": "NEW",

            "severity": detection.get(
                "severity",
                "LOW"
            ),

            "confidence": detection.get(
                "confidence",
                0.0
            ),

            "entity": {
                "type": entity.get(
                    "type",
                    "unknown"
                ),

                "value": entity.get(
                    "value",
                    "unknown"
                )
            },

            "source": detection.get(
                "source_detector",
                "unknown"
            ),

            "detected_at": timestamp,

            "first_seen": timestamp,

            "last_seen": timestamp,

            "mitre_technique": detection.get(
                "mitre_technique"
            ),

            "evidence": detection.get(
                "evidence",
                {}
            ),

            "deduplication_key": deduplication_key
        }


    @staticmethod
    def create_alert_from_correlation(correlation):
        """
        Convert a correlation finding into a Unified Alert.
        """

        timestamp = correlation.get(
            "success_time"
        )

        if timestamp is None:
            timestamp = datetime.utcnow()

        entity = {
            "type": "ip",
            "value": correlation.get(
                "ip",
                "unknown"
            )
        }

        alert_type = correlation.get(
            "correlation_type",
            "unknown"
        )

        deduplication_key = (
            f"{alert_type}:"
            f"{entity.get('type', 'unknown')}:"
            f"{entity.get('value', 'unknown')}"
        )

        return {
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",

            "alert_type": alert_type,

            "status": "NEW",

            "severity": correlation.get(
                "severity",
                "LOW"
            ),

            "confidence": 1.0,

            "entity": entity,

            "source": "correlation_engine",

            "detected_at": timestamp,

            "first_seen": correlation.get(
                "first_seen",
                timestamp
            ),

            "last_seen": timestamp,

            "mitre_technique": None,

            "evidence": {
                "failed_attempts": correlation.get(
                    "failed_count",
                    0
                ),

                "users": correlation.get(
                    "users",
                    []
                ),

                "host_names": correlation.get(
                    "host_names",
                    []
                ),

                "reason": correlation.get(
                    "reason",
                    "unknown"
                )
            },

            "deduplication_key": deduplication_key
        }


    @staticmethod
    def create_alert_from_rule(alert):
        """
        Convert a Rule Engine finding into a Unified Alert.
        """

        timestamp = alert.get(
            "detected_at"
        )

        if timestamp is None:
            timestamp = datetime.utcnow()

        entity = {
            "type": "ip",

            "value": alert.get(
                "ip",
                "unknown"
            )
        }

        alert_type = "rule_violation"

        deduplication_key = (
            f"{alert_type}:"
            f"{entity.get('type', 'unknown')}:"
            f"{entity.get('value', 'unknown')}"
        )

        return {
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",

            "alert_type": alert_type,

            "status": "NEW",

            "severity": alert.get(
                "severity",
                "LOW"
            ),

            "confidence": 1.0,

            "entity": entity,

            "source": "rule_engine",

            "detected_at": timestamp,

            "first_seen": alert.get(
                "first_seen",
                timestamp
            ),

            "last_seen": alert.get(
                "last_seen",
                timestamp
            ),

            "mitre_technique": alert.get(
                "mitre_technique"
            ),

            "evidence": {
                "rule_name": alert.get(
                    "rule_name",
                    "unknown"
                ),

                "observed_value": alert.get(
                    "observed_value",
                    "unknown"
                ),

                "condition": alert.get(
                    "condition",
                    "unknown"
                )
            },

            "deduplication_key": deduplication_key
        }
