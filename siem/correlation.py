from datetime import timedelta




class CorrelationEngine:

    def __init__(self):
        self.states = {}

    def correlate_login_sequence(self, ordered_events):

        if not ordered_events:
            return False



        for event in ordered_events:

            ip = event["ip"]

            # ----------------------------------------
            # Create state for a new IP
            # ----------------------------------------

            if ip not in self.states:

                self.states[ip] = {
                    "failed_count": 0,
                    "first_failed_event_time": None,
                    "users": set(),
                    "host_names": set()
                }



            # ----------------------------------------
            # Check whether the correlation window expired
            # ----------------------------------------

            if self.states[ip]["first_failed_event_time"] is not None:

                difference = (
                    event["timestamp"]
                    - self.states[ip]["first_failed_event_time"]
                )

                if difference > timedelta(minutes=2):

                    self.states[ip] = {
                        "failed_count": 0,
                        "first_failed_event_time": None,
                        "users": set(),
                        "host_names": set()
                    }

            # ----------------------------------------
            # Process failed login
            # ----------------------------------------

            if event["status"] == "failed":

                self.states[ip]["failed_count"] += 1

                if self.states[ip]["first_failed_event_time"] is None:

                    self.states[ip]["first_failed_event_time"] = (
                        event["timestamp"]
                    )

                # Track users involved
                self.states[ip]["users"].add(
                    event["user"]
                )

                # Track hosts involved
                self.states[ip]["host_names"].add(
                    event["host_name"]
                )

            # ----------------------------------------
            # Process successful login
            # ----------------------------------------

            elif event["status"] == "success":

                if (
                    self.states[ip]["failed_count"] >= 3
                    and
                    self.states[ip]["first_failed_event_time"] is not None
                ):

                    time_difference = (
                        event["timestamp"]
                        - self.states[ip]["first_failed_event_time"]
                    )

                    if time_difference <= timedelta(minutes=2):


                        if len(self.states[ip]["users"])>1 and len(self.states[ip]["host_names"])>1:
                            severity = "HIGH"
                        elif len(self.states[ip]["users"])>1 or len(self.states[ip]["host_names"])>1:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"

                        # ----------------------------------------
                        # Create correlation result
                        # ----------------------------------------

                        correlation = {

                            "correlation_type":
                                "brute_force_success",

                            "ip":
                                ip,

                            "failed_count":
                                self.states[ip]["failed_count"],

                            "first_seen":
                                self.states[ip]["first_failed_event_time"],

                            "users":
                                list(self.states[ip]["users"]),

                            "host_names":
                                list(self.states[ip]["host_names"]),

                            "success_time":
                                event["timestamp"],

                            "severity": severity,


                            "reason":
                                (
                                    "3 or more failed logins followed by "
                                    "successful login within 2 minutes"
                                )
                        }

                        # ----------------------------------------
                        # Reset state after successful correlation
                        # ----------------------------------------

                        self.states[ip] = {
                            "failed_count": 0,
                            "first_failed_event_time": None,
                            "users": set(),
                            "host_names": set()
                        }

                        return correlation

        return False
