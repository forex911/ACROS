from typing import List
from app.analysis.models import Capability, BehaviorChain, ThreatClassification, RiskAssessment

class RiskEngine:
    @staticmethod
    def calculate_risk(
        capabilities: List[Capability], 
        chains: List[BehaviorChain], 
        threat: ThreatClassification,
        mitre_tactics_count: int,
        impact_score: int,
        ml_risk_score: float = 0.0
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
            
        # 3.5. Incorporate ML Risk Score
        # If the ML model detects high risk, don't let rule-based logic underestimate it
        if ml_risk_score > final_score:
            final_score = int(ml_risk_score)
            
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

    @staticmethod
    def propagate_artifact_risk(parent_assessment: RiskAssessment, max_child_score: int) -> RiskAssessment:
        """
        Elevate parent risk score if a child artifact has a higher risk score.
        Uses a 90% propagation factor (dropper inherits near-full severity of payload).
        """
        if max_child_score <= parent_assessment.score:
            return parent_assessment

        # 90% propagation
        propagated_score = int(max_child_score * 0.9)
        if propagated_score <= parent_assessment.score:
            return parent_assessment

        final_score = propagated_score
        if final_score <= 29:
            severity = "LOW"
        elif final_score <= 59:
            severity = "MEDIUM"
        elif final_score <= 84:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # Update assessment
        parent_assessment.score = final_score
        parent_assessment.severity = severity
        
        # Add reasoning
        parent_assessment.reasoning.append(
            f"Risk score elevated to {severity} ({final_score}) due to high-risk dropped/downloaded artifacts."
        )

        return parent_assessment
