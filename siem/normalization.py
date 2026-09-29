from datetime import datetime, timezone


def normalize_log(raw_log):

    normalized_log = {

        "event_type": "unknown",

        "ip": "unknown",

        "status": "unknown",

        "user": "unknown",

        "host_name": "unknown",

        "timestamp": None,

        "normalized": False,

        "raw_log": raw_log
    }

    # ----------------------------------------
    # Dictionary Logs
    # ----------------------------------------

    if isinstance(raw_log, dict):

        normalized_log["ip"] = (
            raw_log.get("ip")
            or raw_log.get("source_ip")
            or raw_log.get("src_ip")
        )

        normalized_log["user"] = (
            raw_log.get("username")
            or raw_log.get("user")
            or "unknown"
        )

        normalized_log["host_name"] = (
            raw_log.get("host")
            or raw_log.get("computer")
            or raw_log.get("system")
            or "unknown"
        )

        timestamp = raw_log.get("timestamp")

        # Already a datetime object
        if isinstance(timestamp, datetime):

            normalized_log["timestamp"] = timestamp

        # ISO formatted string
        elif isinstance(timestamp, str):

            normalized_log["timestamp"] = datetime.fromisoformat(timestamp)

        # No timestamp supplied
        else:

            normalized_log["timestamp"] = datetime.now(timezone.utc)

        action = raw_log.get("action") or raw_log.get("event")

        if action:

            action = action.lower()

            normalized_log["event_type"] = "login_attempt"

            if "success" in action:

                normalized_log["status"] = "success"

                normalized_log["normalized"] = True

            elif "fail" in action:

                normalized_log["status"] = "failed"

                normalized_log["normalized"] = True

    # ----------------------------------------
    # String Logs
    # ----------------------------------------

    elif isinstance(raw_log, str):

        log_lower = raw_log.lower()

        normalized_log["event_type"] = "login_attempt"

        if "success" in log_lower:

            normalized_log["status"] = "success"

            normalized_log["normalized"] = True

        elif "fail" in log_lower:

            normalized_log["status"] = "failed"

            normalized_log["normalized"] = True

        parts = raw_log.split()

        # Extract timestamp
        if len(parts) >= 2:

            timestamp_string = parts[0] + " " + parts[1]

            timestamp = datetime.fromisoformat(timestamp_string)

            normalized_log["timestamp"] = timestamp

        # Extract IP
        if "from" in parts:

            ip_index = parts.index("from") + 1

            if ip_index < len(parts):

                normalized_log["ip"] = parts[ip_index]

        # Extract user
        for part in parts:

            if "user=" in part:

                name = part.split("=")

                normalized_log["user"] = name[-1]

        # Extract hostname
        for part in parts:

            if "host=" in part:

                host_name = part.split("=")

                normalized_log["host_name"] = host_name[-1]

    return normalized_log