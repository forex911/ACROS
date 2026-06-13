from typing import List
from app.analysis.models import Capability

class CapabilityEngine:
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

        # 1. Static Rule Mapping
        python_findings = [f.get("rule") for f in static_results.get("python", {}).get("findings", [])]
        has_eval = "EXEC_USAGE" in python_findings
        has_base64 = "BASE64_USAGE" in python_findings

        if has_eval and has_base64:
            add_cap("Obfuscated Execution", "High", 90, "eval() + base64 decode detected", ["T1027", "T1059"], "Defense Evasion")

        # 2. Runtime Rule Mapping
        for evt in telemetry_events:
            t = evt.get("type")
            d = evt.get("data", {})
            cmd = str(d.get("cmdline", "") or d.get("target", "")).lower()

            # Credential Access
            if "login data" in cmd:
                add_cap("Credential Access", "Critical", 95, "Browser Login Data access", ["T1555.003"], "Credential Access")
            if "cookies" in cmd:
                add_cap("Session Theft", "Critical", 95, "Cookie database access", ["T1539"], "Credential Access")
            if "discord" in cmd and "leveldb" in cmd:
                add_cap("Token Theft", "Critical", 95, "Discord token extraction", ["T1528"], "Credential Access")
            if "wallet.dat" in cmd:
                add_cap("Cryptocurrency Theft", "Critical", 95, "Wallet file access", ["T1552"], "Credential Access")

            # Collection
            if "screenshot" in cmd or "prntscrn" in cmd:
                add_cap("Screen Capture", "Medium", 80, "Screenshot API usage", ["T1113"], "Collection")
            if "webcam" in cmd or "camera" in cmd:
                add_cap("Webcam Capture", "High", 85, "Webcam API usage", ["T1125"], "Collection")
            if ".zip" in cmd and t in ("FILE_WRITE", "PROCESS_CREATE"):
                add_cap("Data Staging", "Medium", 80, "ZIP archive creation", ["T1074"], "Collection")

            # Persistence
            if "cron" in cmd or "crontab" in cmd:
                add_cap("Persistence", "High", 90, "Cron modification", ["T1053.003"], "Persistence")
            if "autostart" in cmd or "run" in cmd and "software\\microsoft\\windows\\currentversion" in cmd:
                add_cap("Persistence", "High", 90, "Autostart creation", ["T1547.001"], "Persistence")

            # Defense Evasion
            if "vbox" in cmd or "vmware" in cmd or "qemu" in cmd:
                add_cap("Defense Evasion", "High", 85, "Anti-VM checks", ["T1497.001"], "Defense Evasion")
            if "isdebuggerpresent" in cmd or "ptrace" in cmd:
                add_cap("Defense Evasion", "High", 85, "Anti-Debug checks", ["T1497.001"], "Defense Evasion")

            # Exfiltration
            if t == "HTTP_REQUEST" and d.get("method") == "POST":
                add_cap("Data Exfiltration", "High", 80, "requests.post() / HTTP POST upload", ["T1048"], "Exfiltration")

        return caps
