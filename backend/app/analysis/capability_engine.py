from typing import List
from app.analysis.models import Capability

class CapabilityEngine:
    """
    Capability Engine v2 — Structured Evidence Matching
    ===================================================
    Replaces the original substring-matching engine with structured rules
    that consume ALL evidence sources: PE static analysis, runtime telemetry
    (including registry, memory injection, persistence events), and
    deobfuscated command lines.
    """

    @staticmethod
    def extract_capabilities(static_results: dict, telemetry_events: list) -> List[Capability]:
        caps = []
        seen = set()

        def add_cap(name: str, severity: str, conf: int, ev: str, mitre: List[str], goal: str):
            if name not in seen:
                caps.append(Capability(
                    capability=name,
                    severity=severity,
                    confidence=conf,
                    evidence=[ev],
                    mitre_mapping=mitre,
                    attack_goal=goal
                ))
                seen.add(name)
            else:
                for c in caps:
                    if c.capability == name and ev not in c.evidence:
                        c.evidence.append(ev)

        # ═══════════════════════════════════════════════════════════════
        # 1. STATIC PE EVIDENCE (previously ignored — audit finding #3)
        # ═══════════════════════════════════════════════════════════════
        pe_data = static_results.get("pe", {})
        if pe_data.get("is_pe"):
            # — Process Injection APIs —
            injection_apis = {"virtualallocex", "writeprocessmemory", "createremotethread", "setthreadcontext"}
            pe_suspicious = pe_data.get("suspicious_apis", [])
            pe_api_names = {api.split(":")[-1].lower() for api in pe_suspicious}
            found_injection = pe_api_names & injection_apis
            if found_injection:
                add_cap("Process Injection", "Critical", 95,
                        f"PE imports injection APIs: {', '.join(found_injection)}",
                        ["T1055"], "Defense Evasion")

            # — Packing / Obfuscation —
            if pe_data.get("is_packed"):
                add_cap("Obfuscation", "High", 90,
                        "PE packing detected (high entropy sections or UPX)",
                        ["T1027.002"], "Defense Evasion")

            # — Suspicious API clusters —
            load_apis = {"loadlibrary", "getprocaddress"}
            if pe_api_names & load_apis:
                add_cap("Dynamic API Resolution", "Medium", 75,
                        f"PE imports dynamic loading APIs: {', '.join(pe_api_names & load_apis)}",
                        ["T1027.007"], "Defense Evasion")

            hook_apis = {"setwindowshook", "setwindowshookex"}
            if pe_api_names & hook_apis:
                add_cap("Input Capture", "High", 85,
                        "PE imports hooking APIs (keylogger potential)",
                        ["T1056.001"], "Collection")

        # ═══════════════════════════════════════════════════════════════
        # 2. STATIC PYTHON EVIDENCE
        # ═══════════════════════════════════════════════════════════════
        python_findings = [f.get("rule") for f in static_results.get("python", {}).get("findings", [])]
        has_eval = "EXEC_USAGE" in python_findings
        has_base64 = "BASE64_USAGE" in python_findings

        if has_eval and has_base64:
            add_cap("Obfuscated Execution", "High", 90,
                    "eval() + base64 decode detected",
                    ["T1027", "T1059"], "Defense Evasion")

        if "SUBPROCESS_USAGE" in python_findings:
            add_cap("Subprocess Execution", "Medium", 75,
                    "os.system/subprocess usage in Python script",
                    ["T1059.006"], "Execution")

        if "NETWORK_USAGE" in python_findings:
            add_cap("Network Communication", "Medium", 70,
                    "Network library usage (socket/requests/urllib)",
                    ["T1071"], "Command and Control")

        if "REGISTRY_USAGE" in python_findings:
            add_cap("Registry Access", "High", 85,
                    "winreg/registry access in Python script",
                    ["T1112"], "Defense Evasion")

        if "POWERSHELL_USAGE" in python_findings:
            add_cap("PowerShell Invocation", "High", 85,
                    "PowerShell reference in Python script",
                    ["T1059.001"], "Execution")

        # ═══════════════════════════════════════════════════════════════
        # 3. RUNTIME TELEMETRY EVIDENCE
        # ═══════════════════════════════════════════════════════════════
        for evt in telemetry_events:
            t = evt.get("type")
            d = evt.get("data", {})
            raw_cmd = str(d.get("cmdline", "") or d.get("target", "")).lower()
            # Prefer normalized/decoded content from deobfuscation layer
            cmd = str(d.get("normalized_cmdline", d.get("decoded_cmdline", raw_cmd))).lower()

            # --- Deobfuscation layer evidence ---
            deob_layers = d.get("deobfuscation_layers_cmdline", [])
            if deob_layers:
                chain = " → ".join(l.get("encoding", "") for l in deob_layers)
                add_cap("Obfuscated Execution", "High", 90,
                        f"Decoded {len(deob_layers)} encoding layer(s): {chain}",
                        ["T1027", "T1140"], "Defense Evasion")

            # ── PROCESS_CREATE events ──
            if t == "PROCESS_CREATE":
                # Shadow Copy Deletion (CRITICAL — previously missed)
                if ("vssadmin" in cmd and "delete" in cmd and "shadows" in cmd) or \
                   ("vssadmin" in raw_cmd and "delete" in raw_cmd and "shadows" in raw_cmd):
                    add_cap("Shadow Copy Deletion", "Critical", 98,
                            f"vssadmin delete shadows: {cmd[:60]}",
                            ["T1490"], "Impact")

                if ("wbadmin" in cmd and "delete" in cmd) or \
                   ("wbadmin" in raw_cmd and "delete" in raw_cmd):
                    add_cap("Shadow Copy Deletion", "Critical", 98,
                            f"wbadmin delete: {cmd[:60]}",
                            ["T1490"], "Impact")

                if ("bcdedit" in cmd and "recoveryenabled" in cmd and "no" in cmd) or \
                   ("bcdedit" in raw_cmd and "recoveryenabled" in raw_cmd):
                    add_cap("Shadow Copy Deletion", "Critical", 98,
                            f"bcdedit recovery disabled: {cmd[:60]}",
                            ["T1490"], "Impact")

                # Command Interpreters
                if any(interp in cmd for interp in ["powershell.exe", "powershell ", "pwsh"]):
                    add_cap("PowerShell Invocation", "High", 85,
                            f"PowerShell spawned: {cmd[:60]}",
                            ["T1059.001"], "Execution")
                    if "-enc" in cmd or "-encodedcommand" in cmd:
                        add_cap("Encoded Script Execution", "High", 90,
                                f"PowerShell -EncodedCommand: {cmd[:60]}",
                                ["T1059.001", "T1027.010"], "Defense Evasion")

                if any(interp in cmd for interp in ["cmd.exe", "cmd /c", "cmd /k"]):
                    add_cap("Command Shell Execution", "Medium", 75,
                            f"CMD spawned: {cmd[:60]}",
                            ["T1059.003"], "Execution")

                if any(interp in cmd for interp in ["wscript", "cscript", "mshta"]):
                    add_cap("Script Host Execution", "High", 85,
                            f"Script host spawned: {cmd[:60]}",
                            ["T1059.005"], "Execution")

                # Scheduled Task Persistence
                if "schtasks" in cmd and "/create" in cmd:
                    add_cap("Persistence", "High", 90,
                            f"Scheduled task created: {cmd[:60]}",
                            ["T1053.005"], "Persistence")

                # Registry Run Key Persistence (from command line)
                if "reg" in cmd and "add" in cmd and "currentversion\\run" in cmd:
                    add_cap("Persistence", "High", 90,
                            f"Registry Run key via REG ADD: {cmd[:60]}",
                            ["T1547.001"], "Persistence")

                # Service Creation
                if "sc" in cmd and "create" in cmd:
                    add_cap("Persistence", "High", 90,
                            f"Service created: {cmd[:60]}",
                            ["T1543.003"], "Persistence")

                # Discovery commands
                if any(disc in cmd for disc in ["whoami", "systeminfo", "ipconfig", "net user", "net group", "tasklist"]):
                    add_cap("System Information Discovery", "Medium", 80,
                            f"Discovery command: {cmd[:60]}",
                            ["T1033", "T1082"], "Discovery")

                # Download / Ingress tool transfer
                if any(dl in cmd for dl in ["invoke-webrequest", "downloadstring", "downloadfile",
                                            "net.webclient", "certutil", "bitsadmin", "curl", "wget"]):
                    add_cap("Ingress Tool Transfer", "High", 85,
                            f"Download command: {cmd[:60]}",
                            ["T1105"], "Command and Control")

                # Temp directory execution
                if "temp" in cmd and "python" in cmd and t == "PROCESS_CREATE" and "sentinel_uploads" not in cmd:
                    add_cap("Suspicious Script Execution", "High", 85,
                            "Python script executed from Temp directory",
                            ["T1059.006"], "Execution")

                # --- Decoded command line analysis ---
                decoded_cmd = d.get("decoded_cmdline", d.get("normalized_cmdline", ""))
                if decoded_cmd:
                    dc = decoded_cmd.lower()
                    if "invoke-expression" in dc or "iex" in dc:
                        add_cap("PowerShell Invocation", "High", 90,
                                f"Decoded IEX: {dc[:60]}",
                                ["T1059.001"], "Execution")
                    if any(dl in dc for dl in ["invoke-webrequest", "downloadstring", "downloadfile", "net.webclient"]):
                        add_cap("Ingress Tool Transfer", "High", 85,
                                f"Decoded download: {dc[:60]}",
                                ["T1105"], "Command and Control")
                    if "vssadmin" in dc and "delete" in dc:
                        add_cap("Shadow Copy Deletion", "Critical", 98,
                                f"Decoded vssadmin: {dc[:60]}",
                                ["T1490"], "Impact")
                    if "schtasks" in dc and "/create" in dc:
                        add_cap("Persistence", "High", 90,
                                f"Decoded scheduled task: {dc[:60]}",
                                ["T1053.005"], "Persistence")
                    if "reg add" in dc and "currentversion\\run" in dc:
                        add_cap("Persistence", "High", 90,
                                f"Decoded registry persistence: {dc[:60]}",
                                ["T1547.001"], "Persistence")

            # ── REGISTRY events (NEW — previously dropped) ──
            elif t in ("REGISTRY_CREATE", "REGISTRY_MODIFY"):
                key = d.get("key", "").lower()
                if "currentversion\\run" in key or "currentversion\\runonce" in key:
                    add_cap("Persistence", "High", 90,
                            f"Registry Run key modified: {d.get('key', '')}",
                            ["T1547.001"], "Persistence")
                elif "services\\" in key:
                    add_cap("Persistence", "High", 85,
                            f"Service registry modified: {d.get('key', '')}",
                            ["T1543.003"], "Persistence")
                elif "policies\\explorer\\run" in key:
                    add_cap("Persistence", "High", 90,
                            f"Group Policy Run key: {d.get('key', '')}",
                            ["T1547.001"], "Persistence")

            # ── PERSISTENCE events (NEW) ──
            elif t == "PERSISTENCE_EVENT":
                mechanism = d.get("mechanism", "")
                target = d.get("target", "")
                add_cap("Persistence", "High", 92,
                        f"Persistence via {mechanism}: {target[:60]}",
                        ["T1547.001" if "registry" in mechanism else "T1053.005"], "Persistence")

            # ── MEMORY_INJECTION events (NEW) ──
            elif t == "MEMORY_INJECTION":
                api = d.get("api_call", "unknown")
                add_cap("Process Injection", "Critical", 95,
                        f"Memory injection via {api}",
                        ["T1055"], "Defense Evasion")

            # ── PRIVILEGE_ESCALATION events (NEW) ──
            elif t == "PRIVILEGE_ESCALATION":
                technique = d.get("technique", "unknown")
                add_cap("Privilege Escalation", "Critical", 90,
                        f"Privilege escalation: {technique}",
                        ["T1134" if "token" in technique else "T1548"], "Privilege Escalation")

            # ── FILE_WRITE events ──
            elif t == "FILE_WRITE":
                path = d.get("path", d.get("filename", "")).lower()
                if "startup" in path:
                    add_cap("Persistence", "High", 90,
                            f"Wrote to startup folder: {path}",
                            ["T1547.001"], "Persistence")
                # Ransom note indicators
                if any(note in path for note in ["readme.txt", "decrypt", "ransom", "how_to_recover", "restore_files"]):
                    add_cap("File Encryption", "Critical", 90,
                            f"Possible ransom note dropped: {path}",
                            ["T1486"], "Impact")
                # Encrypted file extension
                if any(path.endswith(ext) for ext in [".encrypted", ".locked", ".crypt", ".enc"]):
                    add_cap("File Encryption", "Critical", 85,
                            f"Encrypted file written: {path}",
                            ["T1486"], "Impact")

            # ── Credential Access ──
            if cmd:
                if "login data" in cmd:
                    add_cap("Credential Access", "Critical", 95,
                            "Browser Login Data access",
                            ["T1555.003"], "Credential Access")
                if "cookies" in cmd and t == "PROCESS_CREATE":
                    add_cap("Session Theft", "Critical", 95,
                            "Cookie database access",
                            ["T1539"], "Credential Access")
                if "discord" in cmd and "leveldb" in cmd:
                    add_cap("Token Theft", "Critical", 95,
                            "Discord token extraction",
                            ["T1528"], "Credential Access")
                if "wallet.dat" in cmd:
                    add_cap("Cryptocurrency Theft", "Critical", 95,
                            "Wallet file access",
                            ["T1552"], "Credential Access")

            # ── Collection ──
            if cmd:
                if "screenshot" in cmd or "prntscrn" in cmd:
                    add_cap("Screen Capture", "Medium", 80,
                            "Screenshot API usage",
                            ["T1113"], "Collection")
                if "webcam" in cmd or "camera" in cmd:
                    add_cap("Webcam Capture", "High", 85,
                            "Webcam API usage",
                            ["T1125"], "Collection")
                if ".zip" in cmd and t in ("FILE_WRITE", "PROCESS_CREATE"):
                    add_cap("Data Staging", "Medium", 80,
                            "ZIP archive creation",
                            ["T1074"], "Collection")

            # ── Defense Evasion (anti-analysis) ──
            if cmd:
                if any(vm in cmd for vm in ["vbox", "vmware", "qemu", "virtualbox", "sandbox"]):
                    add_cap("Defense Evasion", "High", 85,
                            "Anti-VM checks",
                            ["T1497.001"], "Defense Evasion")
                if "isdebuggerpresent" in cmd or "ptrace" in cmd or "checkremotedebuggerpresent" in cmd:
                    add_cap("Defense Evasion", "High", 85,
                            "Anti-Debug checks",
                            ["T1497.001"], "Defense Evasion")

            # ── Exfiltration ──
            if t == "HTTP_REQUEST" and d.get("method") == "POST":
                add_cap("Data Exfiltration", "High", 80,
                        "HTTP POST upload (data exfiltration)",
                        ["T1048"], "Exfiltration")

            # ── Network Communication ──
            if t == "DNS_QUERY":
                domain = d.get("query", "")
                if domain:
                    add_cap("Network Communication", "Low", 50,
                            f"Resolved domain: {domain}",
                            ["T1046"], "Discovery")

            if t in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
                ip = d.get("dest_ip", "")
                port = d.get("dest_port", "")
                add_cap("Network Communication", "Low", 50,
                        f"Connected to {ip}:{port}",
                        ["T1071"], "Command and Control")

        return caps
