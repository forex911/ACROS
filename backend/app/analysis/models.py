from pydantic import BaseModel
from typing import List, Dict, Optional


class Capability(BaseModel):
    capability: str
    severity: str
    confidence: int
    evidence: List[str]
    mitre_mapping: List[str]
    attack_goal: str


class BehaviorChain(BaseModel):
    chain_name: str
    severity: str
    confidence: int
    evidence: List[str]
    attack_goal: str


class ThreatClassification(BaseModel):
    family: str
    confidence: int
    evidence: List[str]


class ImpactAssessment(BaseModel):
    confidentiality: str
    integrity: str
    availability: str


class ScoreContributor(BaseModel):
    """Structured contributor for score explainability.

    Every point in the final risk score traces back to a specific
    evidence source via this model.

    Example::

        {
            "source": "YARA",
            "reason": "Known ransomware signature (LockBit)",
            "points": 35,
            "technique": ""
        }
    """
    source: str        # "YARA", "MITRE", "Runtime", "Static", "IOC", "Behavior", "Graph"
    reason: str        # Human-readable explanation
    points: int        # Score contribution
    technique: str = ""  # Optional MITRE technique ID (e.g., "T1490")


class RiskAssessment(BaseModel):
    score: int
    severity: str
    confidence: int
    verdict: str
    score_breakdown: Dict[str, float]
    modifiers: Dict[str, float] = {}
    reasoning: List[str]
    contributors: List[ScoreContributor] = []


class AnalystReport(BaseModel):
    executive_summary: str
    technical_findings: List[str]
    threat_classification: ThreatClassification
    mitre_coverage: List[str]
    impact_assessment: ImpactAssessment
    recommended_actions: List[str]
    risk_assessment: RiskAssessment
