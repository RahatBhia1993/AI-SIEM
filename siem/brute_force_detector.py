class BruteForceDetector:
    """
    Detects brute force login attempts using a sliding time window.
    """

    def __init__(self, config):
        self.config = config
        self.failed_windows = {}
        self.active_alerts = {}

    def process_event(self, event):
        """
        Process a single normalized event.

        Returns:
            alert (dict) if a brute force attack is detected,
            otherwise None.
        """

        # Ignore anything that isn't a failed login
        if event.get("status") != "failed":
            return None

        # Get the source IP
        ip = event["ip"]

        # Create a sliding window for this IP if needed
        if ip not in self.failed_windows:
            self.failed_windows[ip] = []

        # Add the new failed event
        self.failed_windows[ip].append(event)

        # Current sliding window
        ip_window = self.failed_windows[ip]

        # Remove events older than the configured window
        while (
            len(ip_window) > 0 and
            (event["timestamp"] - ip_window[0]["timestamp"]).total_seconds()
            > self.config["window_size"]
        ):
            ip_window.pop(0)

        # Check if threshold has been reached
        if len(ip_window) >= self.config["threshold"]:

            # Avoid creating duplicate active alerts
            if ip not in self.active_alerts:

                alert = {
                    "type": "brute_force",
                    "status": "active",
                    "ip": ip,
                    "timestamp": event["timestamp"],
                    "event_count": len(ip_window),
                    "window_seconds": self.config["window_size"],
                }

                self.active_alerts[ip] = alert
                return alert

        return None

    def clear_alert(self, ip):
        """
        Clear an active alert for an IP address.
        """
        if ip in self.active_alerts:
            del self.active_alerts[ip]