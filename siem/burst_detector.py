from siem.detection_factory import DetectionFactory
from datetime import timedelta


def extract_entities(event):

    entities = []

    fields = {
        "ip": "ip",
        "user": "user",
        "host": "host"
    }

    for entity_type, field in fields.items():

        if field in event and event[field]:

            entities.append(
                {
                    "type": entity_type,
                    "value": event[field]
                }
            )

    return entities


class BurstDetector:

    def __init__(self, threshold, window_seconds):

        self.threshold = threshold

        self.window_seconds = window_seconds

        self.burst_tracker = {}

        self.active_alerts = {}

    def process_event(self, event):

        entities = extract_entities(event)

        detections = []

        for entity in entities:

            key = (
                entity["type"],
                entity["value"]
            )

            if key not in self.burst_tracker:

                self.burst_tracker[key] = {

                    "first_seen": event["timestamp"],

                    "last_seen": event["timestamp"],

                    "events": [event]
                }

            else:

                tracker = self.burst_tracker[key]

                tracker["events"].append(event)

                tracker["last_seen"] = event["timestamp"]

            tracker = self.burst_tracker[key]

            cutoff_time = (

                event["timestamp"]

                -

                timedelta(
                    seconds=self.window_seconds
                )
            )

            tracker["events"] = [

                e

                for e in tracker["events"]

                if e["timestamp"] >= cutoff_time

            ]

            if len(tracker["events"]) >= self.threshold:

                if key not in self.active_alerts:

                    detection = DetectionFactory.create_detection(

                         detection_type="burst",

                         severity="HIGH",

                         confidence=0.95,

                         entity_type=key[0],

                         entity_value=key[1],

                         source_detector="BurstDetector",

                         evidence={
                            "event_count": len(tracker["events"]),
                            "window_seconds": self.window_seconds,
                            "first_seen": tracker["events"][0]["timestamp"],
                            "last_seen": event["timestamp"]
                         },

                         mitre_technique=None,

                         timestamp=event["timestamp"]
                    )

                    self.active_alerts[key] = detection

                    detections.append(
                        detection
                    )

        return detections