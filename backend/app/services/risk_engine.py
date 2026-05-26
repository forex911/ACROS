def calculate_risk(static_results, telemetry_events, mitre_mappings):
    score = 0
    factors = []

    # 1. Static Risk
    if "pe" in static_results and static_results["pe"].get("is_pe"):
        pe = static_results["pe"]
        if pe.get("is_packed"):
            score += 30
            factors.append("Packed binary detected")
        if pe.get("suspicious_apis"):
            score += 20
            factors.append("Suspicious API imports")
            
    if "python" in static_results:
        py = static_results["python"]
        if py.get("has_base64"):
            score += 15
            factors.append("Uses base64 encoding")
        if py.get("uses_eval_exec"):
            score += 25
            factors.append("Dynamic code execution (eval/exec)")

    if "hash" in static_results:
        if static_results["hash"].get("entropy", 0) > 7.2:
            score += 20
            factors.append("High overall file entropy")

    # 2. Runtime Risk (Heavier weight)
    for evt in telemetry_events:
        t = evt.get("type")
        d = evt.get("data", {})
        if t == "NETWORK_CONNECT" or t == "HTTP_REQUEST":
            score += 15
            factors.append("Initiates outbound network connections")
        elif t == "PROCESS_CREATE":
            cmd = d.get("cmdline", "").lower()
            if "powershell -enc" in cmd or "powershell.exe -e" in cmd:
                score += 50
                factors.append("Encoded PowerShell execution")
            elif "vssadmin" in cmd:
                score += 70
                factors.append("Attempted shadow copy deletion (Ransomware behavior)")

    # Normalize score
    if score > 100:
        score = 100
    if score == 0 and len(factors) == 0:
        score = 5
        factors.append("No distinctly malicious features observed")

    return {
        "score": score,
        "factors": list(set(factors))
    }
