class DetectionManager:

    def __init__(self):

        self.detectors = []

    def register_detector(self, detector):

        self.detectors.append(detector)

    def process_event(self, event):

        detections = []

        for detector in self.detectors:

            result = detector.process_event(event)

            if result is None:
                continue

            if isinstance(result, list):

                detections.extend(result)

            else:

                detections.append(result)

        return detections