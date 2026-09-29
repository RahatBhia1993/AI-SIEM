SEVERITY_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 50,
    "HIGH": 70,
    "CRITICAL": 80
}


def calculate_risk(severity, confidence, evidence=None):

    if evidence is None:
        evidence = {}

    severity_weight = SEVERITY_WEIGHTS[severity]

    if confidence < 0.0 or confidence > 1.0:
        raise ValueError("Invalid confidence value")

    risk = severity_weight * confidence

    failed_attempts = evidence.get("failed_attempts")
    detection_threshold = evidence.get("detection_threshold")
    users = evidence.get("users")
    host_names= evidence.get("host_names")

    if failed_attempts is not None and detection_threshold is not None:
        failed_attempt_factor = calculate_failed_attempt_factor(
            failed_attempts,
            detection_threshold
        )

        risk += failed_attempt_factor * 30
    
    if users is not None:
        user_factor = calculate_user_factor(users) 
        risk = risk + (user_factor*10)

    if host_names is not None:
        host_name_factor = calculate_host_factor(host_names)
        risk = risk + (host_name_factor*10)

    risk = max(0, min(risk, 100))

    return risk

def calculate_failed_attempt_factor(failed_attempts, detection_threshold):
    if failed_attempts < 0:
        raise ValueError("Invalid failed attempts")

    if detection_threshold <= 0:
        raise ValueError("Invalid detection threshold")

    factor = failed_attempts / (detection_threshold * 4)

    return min(factor, 1.0)


def calculate_user_factor(users):
    if users is None:
        raise ValueError("Invalid Users")
    user_factor = 0
    if len(users)==0:
      user_factor=0.0
    elif (len(users) >0 and len(users)<3):
       user_factor = 0.1
    elif (len(users) >2 and len(users)<5):
       user_factor = 0.3
    elif (len(users) >4 and len(users)<7):
       user_factor = 0.5
    elif (len(users) >6 and len(users)<9):
       user_factor = 0.7
    else:
        user_factor = 1.0
    
    return user_factor


def calculate_host_factor(host_names):
    if host_names is None:
        raise ValueError("Invalid host_names")
    host_name_factor = 0
    if len(host_names)==0:
      host_name_factor=0.0
    elif (len(host_names) >0 and len(host_names)<3):
       host_name_factor = 0.1
    elif (len(host_names) >2 and len(host_names)<5):
       host_name_factor = 0.3
    elif (len(host_names) >4 and len(host_names)<7):
       host_name_factor = 0.5
    elif (len(host_names) >6 and len(host_names)<9):
       host_name_factor = 0.7
    else:
        host_name_factor = 1.0
    
    return host_name_factor
