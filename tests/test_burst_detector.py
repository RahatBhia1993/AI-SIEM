from datetime import datetime

from siem.burst_detector import BurstDetector


def test_burst_detector():

    detector = BurstDetector(
        threshold=5,
        window_seconds=30
    )

    detections = []

    for _ in range(5):

        event = {
            "ip": "10.0.0.2",
            "status": "failed",
            "timestamp": datetime.now()
        }

        detections.extend(detector.process_event(event))

    print("\nBurst Detections:")
    print(detections)

    assert len(detections) == 1
    assert detections[0]["detection_type"] == "burst"

    print("\n✅ BurstDetector Test Passed")


if __name__ == "__main__":
    test_burst_detector()