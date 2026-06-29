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

        # ── Ransomware Chain (NEW — critical gap fix) ──
        if "Shadow Copy Deletion" in cap_names:
            # Shadow copy deletion alone is strong ransomware signal
            ransomware_caps = [c for c in ["Shadow Copy Deletion", "Persistence", "File Encryption"] if c in cap_names]
            add_chain("Ransomware Chain", "Critical", 98, ransomware_caps, "Ransomware")

        # ── Infostealer Chain ──
        if "Credential Access" in cap_names or "Session Theft" in cap_names:
            if "Data Staging" in cap_names and "Data Exfiltration" in cap_names:
                req = [c for c in ["Credential Access", "Session Theft", "Data Staging", "Data Exfiltration"] if c in cap_names]
                add_chain("Infostealer Chain", "Critical", 95, req, "Information Theft")

        # ── Surveillance Chain ──
        if "Screen Capture" in cap_names and "Data Staging" in cap_names and "Data Exfiltration" in cap_names:
            add_chain("Surveillance Chain", "High", 90, ["Screen Capture", "Data Staging", "Data Exfiltration"], "Espionage")

        # ── RAT Chain ──
        if "Persistence" in cap_names and "Data Exfiltration" in cap_names:
            add_chain("RAT Chain", "Critical", 90, ["Persistence", "Data Exfiltration"], "Command and Control")

        # ── Injection Chain (NEW) ──
        if "Process Injection" in cap_names and "Network Communication" in cap_names:
            injection_caps = [c for c in ["Process Injection", "Network Communication", "Defense Evasion"] if c in cap_names]
            add_chain("Injection Chain", "Critical", 95, injection_caps, "Code Injection")

        # ── Dropper Chain ──
        if "Data Staging" in cap_names and "Obfuscated Execution" in cap_names:
            add_chain("Dropper Chain", "High", 85, ["Data Staging", "Obfuscated Execution"], "Execution")

        # ── Persistence + C2 Chain (NEW) ──
        if "Persistence" in cap_names and "Network Communication" in cap_names:
            c2_caps = [c for c in ["Persistence", "Network Communication", "Ingress Tool Transfer"] if c in cap_names]
            if "RAT Chain" not in {ch.chain_name for ch in chains}:  # avoid duplicating RAT chain evidence
                add_chain("C2 Persistence Chain", "High", 85, c2_caps, "Command and Control")

        # ── Credential Stealer (standalone, no exfil needed) ──
        cred_caps = {"Credential Access", "Session Theft", "Token Theft", "Cryptocurrency Theft"}
        found_cred = cap_names & cred_caps
        if len(found_cred) >= 2:
            if "Infostealer Chain" not in {ch.chain_name for ch in chains}:
                add_chain("Credential Harvester Chain", "Critical", 90,
                          [c for c in found_cred if c in caps_by_name], "Credential Theft")

        return chains
