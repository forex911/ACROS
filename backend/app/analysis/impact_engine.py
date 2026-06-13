from typing import List
from app.analysis.models import Capability, BehaviorChain, ImpactAssessment

class ImpactEngine:
    @staticmethod
    def calculate_impact(capabilities: List[Capability], chains: List[BehaviorChain]) -> ImpactAssessment:
        cap_names = {c.capability for c in capabilities}
        chain_names = {c.chain_name for c in chains}

        confidentiality = "Low"
        integrity = "Low"
        availability = "Low"

        # Confidentiality
        if "Credential Access" in cap_names or "Session Theft" in cap_names or "Cryptocurrency Theft" in cap_names:
            confidentiality = "Critical"
        elif "Data Exfiltration" in cap_names or "Screen Capture" in cap_names:
            confidentiality = max(confidentiality, "High", key=lambda x: ["Low", "Medium", "High", "Critical"].index(x))

        # Integrity
        if "Persistence" in cap_names or "Obfuscated Execution" in cap_names:
            integrity = max(integrity, "Medium", key=lambda x: ["Low", "Medium", "High", "Critical"].index(x))
        if "Ransomware" in chain_names:
            integrity = "Critical"

        # Availability
        if "Ransomware" in chain_names:
            availability = "Critical"

        return ImpactAssessment(
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability
        )
