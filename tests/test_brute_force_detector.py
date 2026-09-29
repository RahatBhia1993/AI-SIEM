from datetime import datetime

from siem.brute_force_detector import BruteForceDetector


def test_brute_force_detector():

    detector = BruteForceDetector(
        {
            "window_size": 60,
            "threshold": 5
        }
    )

    detection = None

    for _ in range(5):

        event = {
            "ip": "10.0.0.1",
            "status": "failed",
            "timestamp": datetime.now()
        }

        detection = detector.process_event(event)

    print("\nBrute Force Detection:")
    print(detection)

    assert detection is not None
    assert detection["detection_type"] == "brute_force"
    assert detection["severity"] == "HIGH"
    assert detection["evidence"]["failed_attempts"] == 5
    assert detection["evidence"]["detection_threshold"] == 5
    assert detection["evidence"]["window_seconds"] == 60


    print("\n✅ BruteForceDetector Test Passed")


if __name__ == "__main__":
    test_brute_force_detector()