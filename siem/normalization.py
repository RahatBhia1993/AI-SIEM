from datetime import datetime

def normalize_log(raw_log):

    normalized_log = {

        "event_type": "unknown",
        "ip": "unknown",
        "status": "unknown",
        "timestamp": None,
        "normalized": False,
        "raw_log": raw_log

    }

    # ---------------------------------------
    # Dictionary Logs
    # ---------------------------------------

    if isinstance(raw_log, dict):

        normalized_log["ip"] = (
            raw_log.get("ip")
            or raw_log.get("source_ip")
            or raw_log.get("src_ip")
        )

        # -------------------------------
        # Timestamp Handling
        # -------------------------------

        timestamp = raw_log.get("timestamp")

        if timestamp:
            normalized_log["timestamp"] = datetime.fromisoformat(timestamp)
        else:
            normalized_log["timestamp"] = datetime.utcnow()

        # -------------------------------
        # Event Type
        # -------------------------------

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

    # ---------------------------------------
    # String Logs
    # ---------------------------------------

    elif isinstance(raw_log, str):

        log_lower = raw_log.lower()

        normalized_log["timestamp"] = datetime.utcnow()

        normalized_log["event_type"] = "login_attempt"

        if "success" in log_lower:

            normalized_log["status"] = "success"
            normalized_log["normalized"] = True

        elif "fail" in log_lower:

            normalized_log["status"] = "failed"
            normalized_log["normalized"] = True

        parts = raw_log.split()

        if "from" in parts:

            normalized_log["ip"] = parts[-1]

    return normalized_log