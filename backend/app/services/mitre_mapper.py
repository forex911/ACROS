def map_to_mitre(static_results, telemetry_events):
    # Deterministic mapping based purely on observed evidence
    tactics = []
    seen_ids = set()

    def add_tactic(t_id, t_name, evidence):
        if t_id not in seen_ids:
            seen_ids.add(t_id)
            tactics.append({
                "id": t_id,
                "name": t_name,
                "evidence": evidence
            })

    # 1. Analyze Static Evidence
    if "python" in static_results:
        py = static_results["python"]
        if py.get("has_base64"):
            add_tactic("T1140", "Deobfuscate/Decode Files or Information", "Found base64 routines in script")
        if py.get("uses_eval_exec"):
            add_tactic("T1059.006", "Python", "Uses eval/exec for dynamic execution")
        # Removing static powershell mapping to prevent false positives. Must observe runtime.

    if "pe" in static_results and static_results["pe"].get("is_pe"):
        pe = static_results["pe"]
        if pe.get("is_packed"):
            add_tactic("T1027.002", "Software Packing", "High entropy or UPX section detected")
        if pe.get("suspicious_apis"):
            add_tactic("T1055", "Process Injection", f"Suspicious imports found: {', '.join(pe['suspicious_apis'][:3])}")

    # 2. Analyze Runtime Evidence
    for event in telemetry_events:
        evt = event.get("type")
        data = event.get("data", {})
        
        if evt == "PROCESS_CREATE" or evt == "EXECUTION":
            cmd = data.get("cmdline", "").lower()
            if "powershell" in cmd:
                add_tactic("T1059.001", "PowerShell", f"Spawned: {cmd}")
            if "schtasks" in cmd:
                add_tactic("T1053.005", "Scheduled Task", f"Spawned: {cmd}")
            if "vssadmin" in cmd and "shadows" in cmd:
                add_tactic("T1490", "Inhibit System Recovery", f"Spawned: {cmd}")
                
        elif evt == "SOCKET_CONNECT" or evt == "DNS_QUERY" or evt == "HTTP_REQUEST":
            add_tactic("T1071", "Application Layer Protocol", "Observed outbound network connection")

        elif evt == "FILE_WRITE":
            path = data.get("path", "").lower()
            if "startup" in path or "run" in path.split("\\"):
                add_tactic("T1547.001", "Registry Run Keys / Startup Folder", f"Wrote to: {path}")

    return tactics
