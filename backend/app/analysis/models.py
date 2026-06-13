from pydantic import BaseModel
from typing import List, Dict

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

class RiskAssessment(BaseModel):
    score: int
    severity: str
    confidence: int
    verdict: str
    score_breakdown: Dict[str, float]
    reasoning: List[str]

class AnalystReport(BaseModel):
    executive_summary: str
    technical_findings: List[str]
    threat_classification: ThreatClassification
    mitre_coverage: List[str]
    impact_assessment: ImpactAssessment
    recommended_actions: List[str]
    risk_assessment: RiskAssessment
