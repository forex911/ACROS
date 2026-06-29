"""
Pipeline Context — Shared Mutable State for Pipeline Stages
============================================================
A single context object passed through the entire analysis pipeline.
Every stage reads from and writes to this context, ensuring all data
flows through a single, well-defined object.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from app.analysis.models import (
    Capability, BehaviorChain, ThreatClassification,
    ImpactAssessment, RiskAssessment, AnalystReport,
)
from app.analysis.evidence_envelope import EvidenceEnvelope


@dataclass
class PipelineContext:
    """Shared mutable context for the analysis pipeline."""

    # ── Input (set before pipeline starts) ──
    job_id: str = ""
    local_path: str = ""
    filename: str = ""

    # ── Static Analysis ──
    static_results: Dict[str, Any] = field(default_factory=dict)

    # ── Runtime / Sandbox ──
    telemetry_events: List[Dict] = field(default_factory=list)

    # ── Artifact Engine ──
    artifact_report: Dict[str, Any] = field(default_factory=dict)

    # ── Deobfuscation ──
    deobfuscation_report: Dict[str, Any] = field(default_factory=dict)

    # ── Correlation ──
    iocs: List[Dict] = field(default_factory=list)
    mitre_mappings: List[Dict] = field(default_factory=list)
    yara_matches: List[Dict] = field(default_factory=list)
    yara_match_names: List[str] = field(default_factory=list)

    # ── Analysis Engine Outputs ──
    capabilities: List[Capability] = field(default_factory=list)
    behavior_chains: List[BehaviorChain] = field(default_factory=list)
    threat: Optional[ThreatClassification] = None
    impact: Optional[ImpactAssessment] = None

    # ── Evidence Envelope ──
    envelope: Optional[EvidenceEnvelope] = None

    # ── Risk / Report ──
    risk_assessment: Optional[RiskAssessment] = None
    analyst_report: Optional[AnalystReport] = None
    attack_timeline: List[Dict] = field(default_factory=list)

    # ── Final Report ──
    report: Dict[str, Any] = field(default_factory=dict)

    # ── Pipeline Logs ──
    logs: List[str] = field(default_factory=list)

    def log(self, message: str):
        """Append a log message to the pipeline log."""
        self.logs.append(message)
