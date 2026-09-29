from siem.event_ordering import EventOrdering
from siem.brute_force_detector import BruteForceDetector
from siem.burst_detector import BurstDetector
from siem.detection_manager import DetectionManager
from siem.correlation import CorrelationEngine
from siem.detection_factory import DetectionFactory


class DetectionPipeline:

        def __init__(self):

            # ==========================================
            # Event Ordering
            # ==========================================

            self.event_ordering = EventOrdering(
                buffer_size=10
            )

            # ==========================================
            # Detection Manager
            # ==========================================

            self.detection_manager = DetectionManager()

            # Register all detectors

            self.detection_manager.register_detector(
                BruteForceDetector(
                    {
                        "window_size": 60,
                        "threshold": 5
                    }
                )
            )

            self.detection_manager.register_detector(
                BurstDetector(
                    threshold=5,
                    window_seconds=30
                )
            )

            # ==========================================
            # Correlation Engine
            # ==========================================

            self.correlation_engine = CorrelationEngine()

        def process(self, normalized_events):

            detections = []

            # ==========================================
            # Process Incoming Events
            # ==========================================

            for event in normalized_events:

                ordered_events = self.event_ordering.process_event(
                    event
                )

                if ordered_events:

                    correlation = (
                        self.correlation_engine
                        .correlate_login_sequence(ordered_events)
                    )

                    if correlation:

                        detections.append(
                            self._create_correlation_detection(
                                correlation
                            )
                        )

                    detections.extend(
                        self._run_detectors(
                            ordered_events
                        )
                    )

            # ==========================================
            # Flush Remaining Events
            # ==========================================

            remaining_events = self.event_ordering.flush()

            for _, events in remaining_events.items():

                correlation = (
                    self.correlation_engine
                    .correlate_login_sequence(events)
                )

                if correlation:

                    detections.append(
                        self._create_correlation_detection(
                            correlation
                        )
                    )

                detections.extend(
                    self._run_detectors(
                        events
                    )
                )

            return detections

        def _create_correlation_detection(self, correlation):

            detection = DetectionFactory.create_detection(

                detection_type=correlation["correlation_type"],

                severity=correlation["severity"],

                confidence=1.0,

                entity_type="ip",

                entity_value=correlation["ip"],

                source_detector="CorrelationEngine",

                evidence={
                    "failed_attempts": correlation["failed_count"],
                    "users": correlation["users"],
                    "host_names": correlation["host_names"],
                    "reason": correlation["reason"],
                    "first_seen": correlation["first_seen"],
                    "success_time": correlation["success_time"],
                },

                mitre_technique=None,

                timestamp=correlation["success_time"]
            )

            # Preserve correlation-specific fields
            detection["correlation_type"] = correlation["correlation_type"]
            detection["ip"] = correlation["ip"]
            detection["failed_count"] = correlation["failed_count"]

            return detection


        def _run_detectors(self, events):

            detections = []

            for event in events:

                detections.extend(
                    self.detection_manager.process_event(
                        event
                    )
                )

            return detections
