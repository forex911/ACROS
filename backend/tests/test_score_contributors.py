"""
Score Contributors — Test Suite
================================
Verifies that RiskEngineV2 emits structured ScoreContributor objects
for every scoring layer, enabling full traceability.
"""

import pytest
from app.analysis.evidence_envelope import (
    EvidenceEnvelope, StaticEvidence, RuntimeEvidence,
    IOCEvidence, DetectionEvidence, GraphEvidence,
)
from app.analysis.models import (
    Capability, BehaviorChain, ThreatClassification, ScoreContributor,
)
from app.analysis.risk_engine_v2 import RiskEngineV2


def _make_cap(name, severity="High", conf=85, evidence=None, mitre=None, goal=""):
    return Capability(
        capability=name,
        severity=severity,
        confidence=conf,
        evidence=evidence or [f"{name} detected"],
        mitre_mapping=mitre or [],
        attack_goal=goal,
    )


class TestContributorsEmitted:
    """Every scoring layer must emit structured contributors."""

    def test_benign_has_no_contributors(self):
        envelope = EvidenceEnvelope(job_id="test-contrib-benign")
        result = RiskEngineV2.calculate_risk(envelope)
        assert result.contributors == []

    def test_static_contributors(self):
        envelope = EvidenceEnvelope(
            job_id="test-contrib-static",
            static=StaticEvidence(
                is_packed=True,
                suspicious_apis=["VirtualAllocEx", "WriteProcessMemory"],
            ),
        )
        result = RiskEngineV2.calculate_risk(envelope)
        static_contribs = [c for c in result.contributors if c.source == "Static"]
        assert len(static_contribs) >= 2  # packed + suspicious APIs
        total_static_points = sum(c.points for c in static_contribs)
        assert total_static_points > 0

    def test_runtime_contributors(self):
        envelope = EvidenceEnvelope(
            job_id="test-contrib-runtime",
            capabilities=[
                _make_cap("Persistence", severity="High"),
                _make_cap("Data Exfiltration", severity="Critical"),
            ],
        )
        result = RiskEngineV2.calculate_risk(envelope)
        runtime_contribs = [c for c in result.contributors if c.source == "Runtime"]
        assert len(runtime_contribs) == 2

    def test_mitre_contributors_have_technique_id(self):
        envelope = EvidenceEnvelope(
            job_id="test-contrib-mitre",
            detections=DetectionEvidence(
                mitre_techniques=[
                    {"id": "T1490", "name": "Inhibit System Recovery"},
                    {"id": "T1486", "name": "Data Encrypted for Impact"},
                ],
            ),
        )
        result = RiskEngineV2.calculate_risk(envelope)
        mitre_contribs = [c for c in result.contributors if c.source == "MITRE"]
        assert len(mitre_contribs) == 2
        assert mitre_contribs[0].technique == "T1490"
        assert mitre_contribs[1].technique == "T1486"

    def test_ioc_contributors(self):
        envelope = EvidenceEnvelope(
            job_id="test-contrib-ioc",
            iocs=IOCEvidence(
                iocs=[
                    {"type": "ip", "value": "1.2.3.4", "confidence": "High", "source": "Runtime"},
                    {"type": "domain", "value": "evil.com", "confidence": "High", "source": "Runtime"},
                ],
                high_confidence_count=2,
            ),
        )
        result = RiskEngineV2.calculate_risk(envelope)
        ioc_contribs = [c for c in result.contributors if c.source == "IOC"]
        assert len(ioc_contribs) == 1  # single IOC contributor summarizing all IOCs
        assert ioc_contribs[0].points > 0

    def test_behavior_contributors(self):
        caps = [
            _make_cap("Credential Access"),
            _make_cap("Data Exfiltration"),
        ]
        envelope = EvidenceEnvelope(
            job_id="test-contrib-behavior",
            capabilities=caps,
            behavior_chains=[
                BehaviorChain(
                    chain_name="Infostealer Chain",
                    severity="Critical",
                    confidence=95,
                    evidence=["test"],
                    attack_goal="Information Theft",
                ),
            ],
        )
        result = RiskEngineV2.calculate_risk(envelope)
        behavior_contribs = [c for c in result.contributors if c.source == "Behavior"]
        assert len(behavior_contribs) == 1
        assert behavior_contribs[0].points == 40  # Critical behavior chain = 40

    def test_yara_contributors(self):
        envelope = EvidenceEnvelope(
            job_id="test-contrib-yara",
            detections=DetectionEvidence(
                yara_matches=[
                    {"rule": "Ransomware_LockBit", "meta": {"category": "ransomware"}, "tags": []},
                ],
            ),
        )
        result = RiskEngineV2.calculate_risk(envelope)
        yara_contribs = [c for c in result.contributors if c.source == "YARA"]
        assert len(yara_contribs) == 1
        assert yara_contribs[0].points == 50  # ransomware YARA = 50

    def test_graph_contributors(self):
        envelope = EvidenceEnvelope(
            job_id="test-contrib-graph",
            graph=GraphEvidence(chain_length=5, has_c2_persistence=True),
        )
        result = RiskEngineV2.calculate_risk(envelope)
        graph_contribs = [c for c in result.contributors if c.source == "Graph"]
        assert len(graph_contribs) == 1
        assert graph_contribs[0].points > 0


class TestContributorSerialization:
    """Verify contributors serialize correctly in the RiskAssessment output."""

    def test_contributors_in_model_dump(self):
        envelope = EvidenceEnvelope(
            job_id="test-serial",
            static=StaticEvidence(is_packed=True),
        )
        result = RiskEngineV2.calculate_risk(envelope)
        dumped = result.model_dump()
        assert "contributors" in dumped
        assert isinstance(dumped["contributors"], list)
        if dumped["contributors"]:
            c = dumped["contributors"][0]
            assert "source" in c
            assert "reason" in c
            assert "points" in c
