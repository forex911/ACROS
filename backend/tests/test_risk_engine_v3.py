import pytest
from app.analysis.evidence_envelope import (
    EvidenceEnvelope,
    StaticEvidence,
    RuntimeEvidence,
    IOCEvidence,
    DetectionEvidence,
)
from app.analysis.models import Capability
from app.analysis.v3.evidence_builder import EvidenceBuilder
from app.analysis.v3.behaviour_graph import BehaviourGraphAnalyzer
from app.analysis.v3.confidence_engine import ConfidenceEngine
from app.analysis.v3.threat_inference import ThreatInference
from app.analysis.v3.risk_engine_v3 import RiskEngineV3
from app.analysis.v3.evidence_node import EvidenceSource, EvidenceCategory


@pytest.fixture
def sample_ransomware_envelope():
    static = StaticEvidence(
        is_packed=True,
        suspicious_apis=["CryptEncrypt", "CryptAcquireContext", "vssadmin.exe"],
        max_section_entropy=7.5
    )
    
    runtime = RuntimeEvidence(
        process_events=[
            {"type": "PROCESS_CREATE", "timestamp": "1", "data": {"pid": 100, "name": "malware.exe", "cmdline": "malware.exe"}},
            {"type": "PROCESS_CREATE", "timestamp": "2", "data": {"pid": 200, "ppid": 100, "name": "vssadmin.exe", "cmdline": "vssadmin.exe delete shadows /all /quiet"}},
        ],
        file_events=[
            {"type": "FILE_WRITE", "timestamp": "3", "data": {"pid": 100, "path": "C:\\Users\\test\\Desktop\\important.doc.encrypted"}},
            {"type": "FILE_WRITE", "timestamp": "4", "data": {"pid": 100, "path": "C:\\Users\\test\\Desktop\\README_DECRYPT.txt"}},
        ],
        network_events=[
            {"type": "NETWORK_CONNECT", "timestamp": "5", "data": {"pid": 100, "dest_ip": "185.123.123.123", "dest_port": 443}},
        ],
        registry_events=[
            {"type": "REGISTRY_MODIFY", "timestamp": "6", "data": {"pid": 100, "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"}}
        ],
        dns_events=[],
        memory_injection_events=[],
        persistence_events=[
            {"type": "PERSISTENCE_EVENT", "timestamp": "7", "data": {"pid": 100, "mechanism": "Registry Run Key", "target": "malware.exe"}}
        ],
        privilege_escalation_events=[]
    )
    
    detections = DetectionEvidence(
        yara_matches=[{"rule": "Ransomware_Generic_1", "meta": {"description": "Ransomware"}, "tags": ["ransomware"]}],
        mitre_techniques=[
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
            {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
            {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
        ]
    )
    
    iocs = IOCEvidence(
        iocs=[
            {"type": "ip", "value": "185.123.123.123", "confidence": "High", "source": "Network"},
        ],
        high_confidence_count=1
    )
    
    return EvidenceEnvelope(
        job_id="test_job_1",
        static=static,
        runtime=runtime,
        iocs=iocs,
        detections=detections,
        filename="malware.exe",
        capabilities=[
            Capability(
                capability="Shadow Copy Deletion",
                severity="Critical",
                confidence=95,
                evidence=["vssadmin delete shadows"],
                mitre_mapping=["T1490"],
                attack_goal="Inhibit System Recovery"
            ),
            Capability(
                capability="File Encryption",
                severity="Critical",
                confidence=90,
                evidence=["README_DECRYPT.txt"],
                mitre_mapping=["T1486"],
                attack_goal="Data Encrypted for Impact"
            )
        ]
    )


@pytest.fixture
def sample_benign_envelope():
    static = StaticEvidence(
        is_packed=False,
        suspicious_apis=[],
        max_section_entropy=5.0
    )
    
    runtime = RuntimeEvidence(
        process_events=[
            {"type": "PROCESS_CREATE", "timestamp": "1", "data": {"pid": 100, "name": "calc.exe", "cmdline": "calc.exe"}},
        ],
        file_events=[],
        network_events=[],
        registry_events=[],
        dns_events=[],
        memory_injection_events=[],
        persistence_events=[],
        privilege_escalation_events=[]
    )
    
    return EvidenceEnvelope(
        job_id="test_job_benign",
        static=static,
        runtime=runtime,
        filename="calc.exe"
    )


def test_evidence_builder(sample_ransomware_envelope):
    graph = EvidenceBuilder.build(sample_ransomware_envelope)
    
    assert graph.node_count > 0
    assert graph.edge_count > 0
    
    # Check if sources are parsed correctly
    assert len(graph.get_nodes_by_source(EvidenceSource.STATIC)) > 0
    assert len(graph.get_nodes_by_source(EvidenceSource.RUNTIME)) > 0
    assert len(graph.get_nodes_by_source(EvidenceSource.YARA)) > 0
    assert len(graph.get_nodes_by_source(EvidenceSource.IOC)) > 0
    assert len(graph.get_nodes_by_source(EvidenceSource.MITRE)) > 0

    # Ensure temporal relationships are built
    has_temporal = any(e.relation == "temporal" for e in graph.edges)
    assert has_temporal


def test_behaviour_graph(sample_ransomware_envelope):
    graph = EvidenceBuilder.build(sample_ransomware_envelope)
    chains = BehaviourGraphAnalyzer.discover_chains(graph)
    complexity = BehaviourGraphAnalyzer.compute_complexity(graph, chains)
    
    assert len(chains) > 0
    assert complexity.score > 0
    
    # Verify expected categories are in chains
    all_categories = set()
    for chain in chains:
        all_categories.update(chain.categories)
        
    assert EvidenceCategory.PROCESS_SPAWN.value in all_categories
    assert EvidenceCategory.FILE_OPERATION.value in all_categories


def test_threat_inference(sample_ransomware_envelope):
    graph = EvidenceBuilder.build(sample_ransomware_envelope)
    chains = BehaviourGraphAnalyzer.discover_chains(graph)
    
    distribution = ThreatInference.infer(graph, chains)
    family, conf = ThreatInference.classify(distribution)
    
    assert family == "Ransomware"
    assert conf > 0.5


def test_confidence_engine(sample_ransomware_envelope):
    graph = EvidenceBuilder.build(sample_ransomware_envelope)
    chains = BehaviourGraphAnalyzer.discover_chains(graph)
    complexity = BehaviourGraphAnalyzer.compute_complexity(graph, chains)
    
    engine = ConfidenceEngine()
    ev_conf, b_conf, overall = engine.propagate(graph, chains, complexity)
    
    assert ev_conf > 0.7
    assert b_conf > 0.5
    assert overall > 0.6
    assert len(engine.trace) > 0


def test_risk_engine_v3_ransomware(sample_ransomware_envelope):
    assessment = RiskEngineV3.calculate_risk(sample_ransomware_envelope)
    
    assert assessment.score >= 80
    assert assessment.severity == "CRITICAL"
    assert assessment.verdict == "Confirmed Ransomware"
    assert "evidence_tree" in assessment.model_dump()
    assert len(assessment.confidence_trace) > 0


def test_risk_engine_v3_benign(sample_benign_envelope):
    assessment = RiskEngineV3.calculate_risk(sample_benign_envelope)
    
    assert assessment.score <= 25
    assert assessment.severity == "LOW"
    assert assessment.verdict == "Benign"
