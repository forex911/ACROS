def generate_ai_summary(risk_data, iocs, mitre_mappings, telemetry_events):
    if risk_data["score"] < 15 and not mitre_mappings and not iocs:
        return "No malicious runtime behavior observed. The file appears benign based on static and dynamic analysis."

    summary_parts = []
    
    if risk_data["score"] >= 70:
        summary_parts.append("CRITICAL THREAT DETECTED.")
    elif risk_data["score"] >= 40:
        summary_parts.append("SUSPICIOUS BEHAVIOR DETECTED.")
    else:
        summary_parts.append("LOW RISK BEHAVIOR OBSERVED.")

    if mitre_mappings:
        tactics = [m['name'] for m in mitre_mappings]
        summary_parts.append(f"The sample exhibits {len(tactics)} distinct MITRE ATT&CK techniques, including: {', '.join(tactics[:3])}.")

    network_events = [e for e in telemetry_events if e.get("type") in ("SOCKET_CONNECT", "DNS_QUERY")]
    if network_events:
        network_iocs = [ioc['value'] for ioc in iocs if ioc['type'] in ('ip', 'domain') and ioc['source'] == 'Runtime Telemetry']
        if network_iocs:
            summary_parts.append(f"Network activity was observed, communicating with endpoints (e.g., {network_iocs[0]}).")
        else:
            summary_parts.append("Network activity was observed during runtime execution.")

    if any(evt.get("type") in ("PROCESS_CREATE", "EXECUTION") and "python " not in evt.get("data", {}).get("cmdline", "").lower() for evt in telemetry_events):
        summary_parts.append("The sample actively spawned child processes during sandbox execution.")
        
    for factor in risk_data["factors"]:
        if "Ransomware" in factor:
            summary_parts.append("WARNING: Ransomware-like indicators (e.g. shadow copy deletion) were confirmed in the telemetry stream.")
            break

    if not summary_parts:
        return "Analysis completed. No significant behavioral indicators generated."

    return " ".join(summary_parts)
