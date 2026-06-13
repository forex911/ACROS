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
    if "pe" in static_results and static_results["pe"].get("is_pe"):
        pe = static_results["pe"]
        if pe.get("is_packed"):
            add_tactic("T1027.002", "Software Packing", "High entropy or UPX section detected")
        if pe.get("suspicious_apis"):
            # Only trigger T1055 for actual process injection APIs
            injection_apis = {"virtualallocex", "writeprocessmemory", "createremotethread", "setthreadcontext"}
            found = [api for api in pe["suspicious_apis"] if api.lower() in injection_apis]
            if found:
                add_tactic("T1055", "Process Injection", f"Process injection APIs found: {', '.join(found[:3])}")

    # 2. Analyze Runtime Evidence
    for event in telemetry_events:
        evt = event.get("type")
        data = event.get("data", {})
        
        if evt == "PROCESS_CREATE":
            cmd = data.get("cmdline", "").lower()
            
            # T1059: Command and Scripting Interpreter
            if any(interpreter in cmd for interpreter in ["powershell.exe", "powershell ", "cmd.exe", "cmd ", "bash", "wscript", "cscript"]):
                add_tactic("T1059", "Command and Scripting Interpreter", f"Execution: {cmd[:30]}")
                if "powershell" in cmd:
                    add_tactic("T1059.001", "PowerShell", f"Spawned: {cmd[:30]}")
                elif "cmd" in cmd:
                    add_tactic("T1059.003", "Windows Command Shell", f"Spawned: {cmd[:30]}")

            # Deobfuscation-aware mappings
            deob_layers = data.get("deobfuscation_layers_cmdline", [])
            if deob_layers:
                encoding_chain = " → ".join(l.get("encoding", "") for l in deob_layers)
                add_tactic("T1027", "Obfuscated Files or Information", f"Encoding chain detected: {encoding_chain}")
                add_tactic("T1140", "Deobfuscate/Decode Files or Information", f"Decoded {len(deob_layers)} layer(s): {encoding_chain}")
                if any("powershell_enc" in l.get("encoding", "") for l in deob_layers):
                    add_tactic("T1027.010", "Command Obfuscation", "PowerShell -EncodedCommand detected")

            # Run technique detection on DECODED cmdline (catches hidden commands)
            decoded_cmd = data.get("decoded_cmdline", data.get("normalized_cmdline", ""))
            if decoded_cmd:
                dc = decoded_cmd.lower()
                if any(interpreter in dc for interpreter in ["powershell", "cmd", "bash", "wscript", "cscript"]):
                    add_tactic("T1059", "Command and Scripting Interpreter", f"Decoded execution: {dc[:30]}")
                if "invoke-expression" in dc or "iex" in dc:
                    add_tactic("T1059.001", "PowerShell", f"Decoded IEX: {dc[:30]}")
                if "invoke-webrequest" in dc or "downloadstring" in dc or "downloadfile" in dc or "net.webclient" in dc:
                    add_tactic("T1105", "Ingress Tool Transfer", f"Decoded download: {dc[:30]}")
                if "vssadmin" in dc and "delete" in dc:
                    add_tactic("T1490", "Inhibit System Recovery", f"Decoded vssadmin: {dc[:30]}")
                if "whoami" in dc or "systeminfo" in dc or "ipconfig" in dc or "net user" in dc:
                    add_tactic("T1033", "System Owner/User Discovery", f"Decoded discovery: {dc[:30]}")
                if "schtasks" in dc or "at " in dc:
                    add_tactic("T1053", "Scheduled Task/Job", f"Decoded persistence: {dc[:30]}")
                if "reg add" in dc or "currentversion\\\\run" in dc:
                    add_tactic("T1547.001", "Registry Run Keys / Startup Folder", f"Decoded persistence: {dc[:30]}")
                    
            # T1490: Inhibit System Recovery
            if "vssadmin" in cmd and "delete" in cmd and "shadows" in cmd:
                add_tactic("T1490", "Inhibit System Recovery", f"Observed vssadmin delete shadows: {cmd[:30]}")
            elif "wbadmin" in cmd and "delete" in cmd and "catalog" in cmd:
                add_tactic("T1490", "Inhibit System Recovery", f"Observed wbadmin delete catalog: {cmd[:30]}")
                
            # T1547.001: Registry Run Keys / Startup Folder (Scheduled Task part)
            if "schtasks" in cmd:
                add_tactic("T1547.001", "Registry Run Keys / Startup Folder", f"Observed scheduled task creation: {cmd[:30]}")

        elif evt == "FILE_WRITE":
            path = data.get("path", data.get("filename", "")).lower()
            if "startup" in path:
                add_tactic("T1547.001", "Registry Run Keys / Startup Folder", f"Wrote to startup folder: {path}")

        elif evt == "REGISTRY_MODIFY":
            key = data.get("key", "").lower()
            if "currentversion\\run" in key:
                add_tactic("T1547.001", "Registry Run Keys / Startup Folder", f"Modified Run key: {key}")

        elif evt == "DNS_QUERY":
            domain = data.get("query", "")
            add_tactic("T1046", "Network Service Discovery", f"Resolved domain: {domain}")
            
        elif evt in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
            ip = data.get("dest_ip", "")
            port = data.get("dest_port", "")
            add_tactic("T1071", "Application Layer Protocol", f"Connected to {ip}:{port} (Command and Control)")

    # Post-process for beaconing/C2 combinations
    socket_events = [e for e in telemetry_events if e.get("type") in ("SOCKET_CONNECT", "NETWORK_CONNECT")]
    if len(socket_events) > 1:
        add_tactic("T1571", "Non-Standard Port / Beaconing", "Multiple socket connections established (C2 activity)")

    return tactics
