from typing import List
from app.analysis.models import Capability, BehaviorChain, ThreatClassification, RiskAssessment

class RiskEngine:
    @staticmethod
    def calculate_risk(
        capabilities: List[Capability], 
        chains: List[BehaviorChain], 
        threat: ThreatClassification,
        mitre_tactics_count: int,
        impact_score: int
    ) -> RiskAssessment:
        
        # 1. Base scores out of 100
        cap_score = min(100, sum([25 if c.severity == "Critical" else 15 if c.severity == "High" else 10 for c in capabilities]))
        chain_score = min(100, sum([30 for c in chains]))
        threat_score = 100 if threat.family != "Unknown" else 0
        mitre_score = min(100, mitre_tactics_count * 10)
        
        # 2. Weighted calculation
        # Final Risk = 35% Capability Risk, 25% Behavior Risk, 20% Threat Family Risk, 10% ATT&CK Coverage, 10% Confidence Modifier
        weighted_cap = cap_score * 0.35
        weighted_chain = chain_score * 0.25
        weighted_threat = threat_score * 0.20
        weighted_mitre = mitre_score * 0.10
        
        # 3. Confidence Modifier
        # Base it on the max confidence we have across inputs
        max_conf = threat.confidence
        if not max_conf and chains:
            max_conf = max([c.confidence for c in chains])
        if not max_conf and capabilities:
            max_conf = max([c.confidence for c in capabilities])
            
        confidence_mod = (max_conf / 100.0) * 10
        
        final_score = int(weighted_cap + weighted_chain + weighted_threat + weighted_mitre + confidence_mod)
        if not capabilities and not chains:
            final_score = min(final_score, 5)
            
        if final_score > 100:
            final_score = 100

        # 4. Severity mapping
        if final_score <= 29:
            severity = "LOW"
        elif final_score <= 59:
            severity = "MEDIUM"
        elif final_score <= 84:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # 5. Extract reasoning
        reasoning = []
        if threat.family != "Unknown":
            reasoning.append(f"Threat classified as {threat.family}")
        for ch in chains:
            reasoning.append(f"Detected {ch.chain_name}")
        for cap in capabilities:
            reasoning.append(f"Exhibits {cap.capability} capability")

        return RiskAssessment(
            score=final_score,
            severity=severity,
            confidence=max_conf,
            verdict=threat.family if threat.family != "Unknown" else ("Suspicious" if final_score > 30 else "Benign"),
            score_breakdown={
                "capability_risk": round(weighted_cap, 2),
                "behavior_risk": round(weighted_chain, 2),
                "threat_risk": round(weighted_threat, 2),
                "mitre_risk": round(weighted_mitre, 2),
                "confidence_mod": round(confidence_mod, 2)
            },
            reasoning=list(set(reasoning))
        )
