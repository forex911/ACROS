from typing import List
from app.analysis.models import Capability, BehaviorChain

class BehaviorEngine:
    @staticmethod
    def detect_chains(capabilities: List[Capability]) -> List[BehaviorChain]:
        chains = []
        caps_by_name = {c.capability: c for c in capabilities}
        cap_names = set(caps_by_name.keys())

        def add_chain(name: str, sev: str, conf: int, req_caps: List[str], goal: str):
            evidence = []
            for c in req_caps:
                evidence.extend(caps_by_name[c].evidence)
            chains.append(BehaviorChain(
                chain_name=name,
                severity=sev,
                confidence=conf,
                evidence=list(set(evidence)),
                attack_goal=goal
            ))

        # Infostealer Chain
        if "Credential Access" in cap_names or "Session Theft" in cap_names:
            if "Data Staging" in cap_names and "Data Exfiltration" in cap_names:
                req = [c for c in ["Credential Access", "Session Theft", "Data Staging", "Data Exfiltration"] if c in cap_names]
                add_chain("Infostealer Chain", "Critical", 95, req, "Information Theft")

        # Surveillance Chain
        if "Screen Capture" in cap_names and "Data Staging" in cap_names and "Data Exfiltration" in cap_names:
            add_chain("Surveillance Chain", "High", 90, ["Screen Capture", "Data Staging", "Data Exfiltration"], "Espionage")

        # RAT Chain
        if "Persistence" in cap_names and "Data Exfiltration" in cap_names:
            add_chain("RAT Chain", "Critical", 90, ["Persistence", "Data Exfiltration"], "Command and Control")

        # Dropper Chain
        if "Data Staging" in cap_names and "Obfuscated Execution" in cap_names:
            add_chain("Dropper Chain", "High", 85, ["Data Staging", "Obfuscated Execution"], "Execution")

        return chains
