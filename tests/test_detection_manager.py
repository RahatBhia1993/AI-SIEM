from datetime import datetime

from siem.detection_manager import DetectionManager
from siem.brute_force_detector import BruteForceDetector
from siem.burst_detector import BurstDetector


def test_detection_manager():

    manager = DetectionManager()

    manager.register_detector(
        BruteForceDetector(
            {
                "window_size": 60,
                "threshold": 5
            }
        )
    )

    manager.register_detector(
        BurstDetector(
            threshold=5,
            window_seconds=30
        )
    )

    detections = []

    for _ in range(5):

        event = {
            "ip": "10.0.0.3",
            "status": "failed",
            "timestamp": datetime.now()
        }

        detections.extend(manager.process_event(event))

    print("\nDetection Manager Output:")
    print(detections)

    assert len(detections) == 2

    types = {d["detection_type"] for d in detections}

    assert "brute_force" in types
    assert "burst" in types

    print("\nDetection Types:", types)

    print("\n✅ DetectionManager Test Passed")


if __name__ == "__main__":
    test_detection_manager()