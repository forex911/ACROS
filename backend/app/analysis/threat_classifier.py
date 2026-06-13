from typing import List
from app.analysis.models import Capability, BehaviorChain, ThreatClassification

class ThreatClassifier:
    @staticmethod
    def classify(capabilities: List[Capability], chains: List[BehaviorChain]) -> ThreatClassification:
        cap_names = {c.capability for c in capabilities}
        chain_names = {c.chain_name for c in chains}

        evidence = []
        for c in capabilities:
            evidence.extend(c.evidence)
        for ch in chains:
            evidence.extend(ch.evidence)
        evidence = list(set(evidence))

        if "Infostealer Chain" in chain_names or ("Credential Access" in cap_names and "Data Exfiltration" in cap_names):
            return ThreatClassification(family="Infostealer", confidence=95, evidence=evidence)
            
        if "RAT Chain" in chain_names:
            return ThreatClassification(family="RAT", confidence=90, evidence=evidence)

        if "Credential Access" in cap_names or "Session Theft" in cap_names or "Cryptocurrency Theft" in cap_names:
            return ThreatClassification(family="Credential Stealer", confidence=85, evidence=evidence)

        if "Ransomware Chain" in chain_names or "Shadow Copy Deletion" in cap_names: # Extensibility
            return ThreatClassification(family="Ransomware", confidence=95, evidence=evidence)

        if "Data Staging" in cap_names and "Data Exfiltration" in cap_names:
            return ThreatClassification(family="Data Exfiltration Tool", confidence=85, evidence=evidence)

        if "Dropper Chain" in chain_names:
            return ThreatClassification(family="Dropper", confidence=80, evidence=evidence)

        if "Screen Capture" in cap_names or "Webcam Capture" in cap_names:
            return ThreatClassification(family="Spyware", confidence=85, evidence=evidence)

        return ThreatClassification(family="Unknown", confidence=0, evidence=evidence)
