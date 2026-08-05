from siem.event_ordering import EventOrdering
from siem.brute_force_detector import BruteForceDetector
from siem.burst_detector import BurstDetector
from siem.detection_manager import DetectionManager


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

            detections.extend(

                self._run_detectors(
                    events
                )

            )

        return detections

    def _run_detectors(self, events):

        detections = []

        for event in events:

            detections.extend(

                self.detection_manager.process_event(
                    event
                )

            )

        return detections