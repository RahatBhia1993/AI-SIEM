from datetime import timedelta


class BruteForceDetector:

    def __init__(self, config):

        self.config = config

        self.failed_windows = {}

        self.active_alerts = {}

    def process_event(self, event):

        # Ignore anything that isn't a failed login
        if event["status"] != "failed":
            return None

        ip = event["ip"]

        if ip not in self.failed_windows:
            self.failed_windows[ip] = []

        self.failed_windows[ip].append(event)

        window = self.failed_windows[ip]

        while (
            event["timestamp"] - window[0]["timestamp"]
        ).total_seconds() > self.config["window_size"]:

            window.pop(0)

        if len(window) >= self.config["threshold"]:

            if ip not in self.active_alerts:

                alert = {

                    "type": "brute_force",

                    "status": "active",

                    "ip": ip,

                    "timestamp": event["timestamp"],

                    "event_count": len(window),

                    "window_seconds": self.config["window_size"]

                }

                self.active_alerts[ip] = alert

                return alert

        return None