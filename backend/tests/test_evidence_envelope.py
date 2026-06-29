"""
Evidence Envelope — Test Suite
===============================
Verifies that the EvidenceEnvelope factory method correctly
populates all evidence layers from raw pipeline outputs.
"""

import pytest
from app.analysis.evidence_envelope import (
    EvidenceEnvelope, StaticEvidence, RuntimeEvidence,
    IOCEvidence, DetectionEvidence, GraphEvidence, AnalysisMetadata,
)
from app.analysis.models import (
    Capability, BehaviorChain, ThreatClassification, ScoreContributor,
)


class TestEvidenceEnvelopeConstruction:
    """Verify EvidenceEnvelope can be constructed directly."""

    def test_minimal_construction(self):
        envelope = EvidenceEnvelope(job_id="test-001")
        assert envelope.job_id == "test-001"
        assert envelope.static.is_packed is False
        assert envelope.runtime.total_events == 0
        assert envelope.iocs.iocs == []
        assert envelope.graph.chain_length == 0
        assert envelope.graph.has_c2_persistence is False

    def test_graph_evidence_populated(self):
        envelope = EvidenceEnvelope(
            job_id="test-002",
            graph=GraphEvidence(
                chain_length=5,
                has_c2_persistence=True,
                reasoning=["C2 persistence co-occurrence detected"],
            ),
        )
        assert envelope.graph.chain_length == 5
        assert envelope.graph.has_c2_persistence is True
        assert len(envelope.graph.reasoning) == 1

    def test_backward_compat_properties(self):
        """Verify envelope.graph_chain_length proxies to envelope.graph.chain_length."""
        envelope = EvidenceEnvelope(job_id="test-003")
        envelope.graph_chain_length = 4
        assert envelope.graph.chain_length == 4
        assert envelope.graph_chain_length == 4

        envelope.graph_has_c2_persistence = True
        assert envelope.graph.has_c2_persistence is True
        assert envelope.graph_has_c2_persistence is True


class TestEvidenceEnvelopeBuild:
    """Verify the .build() factory method."""

    def test_build_with_empty_inputs(self):
        envelope = EvidenceEnvelope.build(
            job_id="test-build-001",
            static_results={},
            telemetry_events=[],
            iocs=[],
            mitre_mappings=[],
            yara_matches=[],
            capabilities=[],
            behavior_chains=[],
            threat=ThreatClassification(family="Unknown", confidence=0, evidence=[]),
        )
        assert envelope.job_id == "test-build-001"
        assert envelope.static.pe_imports == []
        assert envelope.runtime.total_events == 0
        assert envelope.iocs.high_confidence_count == 0

    def test_build_classifies_telemetry_events(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 1}},
            {"type": "PROCESS_CREATE", "data": {"pid": 2}},
            {"type": "SOCKET_CONNECT", "data": {"dest_ip": "1.2.3.4"}},
            {"type": "DNS_QUERY", "data": {"query": "evil.com"}},
            {"type": "REGISTRY_MODIFY", "data": {"key": "HKLM\\..."}},
        ]
        envelope = EvidenceEnvelope.build(
            job_id="test-build-002",
            static_results={},
            telemetry_events=events,
            iocs=[],
            mitre_mappings=[],
            yara_matches=[],
            capabilities=[],
            behavior_chains=[],
            threat=ThreatClassification(family="Unknown", confidence=0, evidence=[]),
        )
        assert len(envelope.runtime.process_events) == 2
        assert len(envelope.runtime.network_events) == 1
        assert len(envelope.runtime.dns_events) == 1
        assert len(envelope.runtime.registry_events) == 1
        assert envelope.runtime.total_events == 5

    def test_build_counts_high_confidence_iocs(self):
        iocs = [
            {"type": "ip", "value": "1.2.3.4", "confidence": "High"},
            {"type": "domain", "value": "evil.com", "confidence": "High"},
            {"type": "url", "value": "http://ok.com", "confidence": "Low"},
        ]
        envelope = EvidenceEnvelope.build(
            job_id="test-build-003",
            static_results={},
            telemetry_events=[],
            iocs=iocs,
            mitre_mappings=[],
            yara_matches=[],
            capabilities=[],
            behavior_chains=[],
            threat=ThreatClassification(family="Unknown", confidence=0, evidence=[]),
        )
        assert envelope.iocs.high_confidence_count == 2
        assert envelope.iocs.unique_malicious_ips == 1
        assert envelope.iocs.unique_c2_domains == 1

    def test_build_populates_yara_from_strings(self):
        """YARA matches provided as plain strings should become dicts."""
        envelope = EvidenceEnvelope.build(
            job_id="test-build-004",
            static_results={},
            telemetry_events=[],
            iocs=[],
            mitre_mappings=[],
            yara_matches=["Ransomware_LockBit", "Suspicious_Packed"],
            capabilities=[],
            behavior_chains=[],
            threat=ThreatClassification(family="Unknown", confidence=0, evidence=[]),
        )
        assert len(envelope.detections.yara_matches) == 2
        assert envelope.detections.yara_matches[0]["rule"] == "Ransomware_LockBit"

    def test_build_populates_metadata(self):
        envelope = EvidenceEnvelope.build(
            job_id="test-meta",
            static_results={"hash": {"sha256": "abc123"}},
            telemetry_events=[],
            iocs=[],
            mitre_mappings=[],
            yara_matches=[],
            capabilities=[],
            behavior_chains=[],
            threat=ThreatClassification(family="Unknown", confidence=0, evidence=[]),
            filename="malware.exe",
        )
        assert envelope.metadata.job_id == "test-meta"
        assert envelope.metadata.filename == "malware.exe"
        assert envelope.metadata.sha256 == "abc123"


class TestScoreContributorModel:
    """Verify ScoreContributor model works correctly."""

    def test_basic_contributor(self):
        c = ScoreContributor(source="YARA", reason="LockBit match", points=35)
        assert c.source == "YARA"
        assert c.points == 35
        assert c.technique == ""  # default

    def test_contributor_with_technique(self):
        c = ScoreContributor(
            source="MITRE", reason="Shadow copy deletion", points=40, technique="T1490"
        )
        assert c.technique == "T1490"

    def test_contributor_serialization(self):
        c = ScoreContributor(source="IOC", reason="5 high-confidence IOCs", points=20)
        d = c.model_dump()
        assert d["source"] == "IOC"
        assert d["points"] == 20
