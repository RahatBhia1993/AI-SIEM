from datetime import datetime
import uuid


class DetectionFactory:

    @staticmethod
    def create_detection(
        detection_type,
        severity,
        confidence,
        entity_type,
        entity_value,
        source_detector,
        evidence,
        mitre_technique=None,
        status="active",
        timestamp=None
    ):

        if timestamp is None:
            timestamp = datetime.utcnow()

        return {

            "detection_id": f"DET-{uuid.uuid4().hex[:8].upper()}",

            "detection_type": detection_type,

            "status": status,

            "severity": severity,

            "confidence": confidence,

            "timestamp": timestamp,

            "entity": {
                "type": entity_type,
                "value": entity_value
            },

            "source_detector": source_detector,

            "mitre_technique": mitre_technique,

            "evidence": evidence

        }