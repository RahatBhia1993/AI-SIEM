from datetime import datetime

from siem.detection_pipeline import DetectionPipeline


def test_detection_pipeline():

    pipeline = DetectionPipeline()

    events = []

    for i in range(5):

        events.append(
            {
                "ip": "1.1.1.1",
                "user": "alice",
                "host_name": "server-01",
                "status": "failed",
                "timestamp": datetime.now()
            }
        )

    detections = pipeline.process(events)

    print("\nDetections produced:")
    print(detections)

    assert len(detections) >= 2

    print("\n✅ DetectionPipeline Test Passed")


if __name__ == "__main__":
    test_detection_pipeline()