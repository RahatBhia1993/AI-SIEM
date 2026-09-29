from datetime import datetime, timedelta

from siem.correlation import CorrelationEngine


engine = CorrelationEngine()

start_time = datetime(2026, 9, 7, 10, 0, 0)

events = [
    {
        "ip": "10.0.0.5",
        "user": "alice",
        "host_name": "workstation-01",
        "status": "failed",
        "timestamp": start_time
    },
    {
        "ip": "10.0.0.5",
        "user": "bob",
        "host_name": "workstation-02",
        "status": "failed",
        "timestamp": start_time + timedelta(seconds=20)
    },
    {
        "ip": "10.0.0.5",
        "user": "charlie",
        "host_name": "workstation-03",
        "status": "failed",
        "timestamp": start_time + timedelta(seconds=40)
    },
    {
        "ip": "10.0.0.5",
        "user": "charlie",
        "host_name": "workstation-03",
        "status": "success",
        "timestamp": start_time + timedelta(minutes=1)
    }
]




result = engine.correlate_login_sequence(events)

print(result)
