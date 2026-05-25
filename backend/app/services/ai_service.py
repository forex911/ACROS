def analyze_behavior(data):

    risk_score = 0

    reasons = []

    if data["network_connections"] > 10:
        risk_score += 30
        reasons.append("High network activity detected")

    if data["process_count"] > 100:
        risk_score += 40
        reasons.append("Large number of processes detected")

    if data["cpu_usage"] > 80:
        risk_score += 20
        reasons.append("High CPU usage detected")

    if risk_score >= 70:
        threat_level = "High Risk"

    elif risk_score >= 40:
        threat_level = "Suspicious"

    else:
        threat_level = "Safe"

    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "reasons": reasons
    }