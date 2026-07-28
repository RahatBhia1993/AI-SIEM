def analyze_logs(normalized_logs):

    metrics = {}

    for log in normalized_logs:

        ip = log["ip"]
        status = log["status"]

        if ip not in metrics:
            metrics[ip] = {
                "failed_logins": 0,
                "successful_logins": 0,
                "ip_frequency": 0
            }

        metrics[ip]["ip_frequency"] += 1

        if status == "failed":
            metrics[ip]["failed_logins"] += 1

        elif status == "success":
            metrics[ip]["successful_logins"] += 1

    return metrics