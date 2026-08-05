from datetime import datetime, timedelta


class BruteForceSimulation:

    def __init__(self, attacker_ip, failed_attempts):

        self.attacker_ip = attacker_ip
        self.failed_attempts = failed_attempts

    def generate_events(self):

        events = []

        base = datetime.now()

        # Generate failed logins
        for i in range(self.failed_attempts):

            events.append(
                {
                    "ip": self.attacker_ip,
                    "action": "failed login",
                    "timestamp": base + timedelta(seconds=i * 5)
                }
            )

        # Generate successful login
        events.append(
            {
                "ip": self.attacker_ip,
                "action": "success login",
                "timestamp": base + timedelta(
                    seconds=self.failed_attempts * 5
                )
            }
        )

        return events