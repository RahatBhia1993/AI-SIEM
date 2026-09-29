from datetime import datetime
from main import run_pipeline

def test_normal_login():

  raw_logs = [
      {
          "ip": "10.0.0.5",
          "action": "success login",
          "timestamp": datetime(2026, 9, 7, 10, 0)
      }
  ]

  result = run_pipeline(raw_logs)

  assert result["correlated_alerts"] == []

  assert result["incidents"] == {}

if __name__ == "_main_":
  test_normal_login()
  print("Test 1 passed")