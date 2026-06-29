"""
Evidence Envelope — Unified Evidence Container for Risk Engine v2
================================================================
Collects ALL evidence sources into a single object before scoring begins.
This eliminates the disconnected-engines problem identified in the audit:
every evidence source is available to every scorer.

Evidence layers:
    - Static:     PE analysis, strings, entropy, Python findings
    - Runtime:    Telemetry events categorized by type
    - IOC:        Extracted IOCs with confidence levels
    - Detection:  YARA matches, MITRE techniques, threat classification
    - Graph:      Attack chain metrics derived from Neo4j
    - Metadata:   Analysis run metadata (job_id, filename, timing)

Analysis engine outputs:
    - Capabilities: Extracted capabilities from telemetry
    - BehaviorChains: Detected multi-step attack patterns
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime
from app.analysis.models import Capability, BehaviorChain, ThreatClassification


class StaticEvidence(BaseModel):
    """Evidence extracted from static analysis (PE, Python, strings)."""
    pe_imports: List[str] = Field(default_factory=list)
    is_packed: bool = False
    suspicious_apis: List[str] = Field(default_factory=list)
    max_section_entropy: float = 0.0
    sections: List[Dict] = Field(default_factory=list)
    string_iocs: Dict[str, List[str]] = Field(default_factory=dict)  # ips, urls, domains
    python_findings: List[str] = Field(default_factory=list)
    total_strings_count: int = 0


class RuntimeEvidence(BaseModel):
    """Evidence from sandbox execution telemetry."""
    process_events: List[Dict] = Field(default_factory=list)
    network_events: List[Dict] = Field(default_factory=list)
    dns_events: List[Dict] = Field(default_factory=list)
    file_events: List[Dict] = Field(default_factory=list)
    registry_events: List[Dict] = Field(default_factory=list)
    memory_injection_events: List[Dict] = Field(default_factory=list)
    persistence_events: List[Dict] = Field(default_factory=list)
    privilege_escalation_events: List[Dict] = Field(default_factory=list)
    total_events: int = 0


class IOCEvidence(BaseModel):
    """Evidence from IOC extraction pipeline."""
    iocs: List[Dict] = Field(default_factory=list)
    high_confidence_count: int = 0
    unique_c2_domains: int = 0
    unique_malicious_ips: int = 0


class DetectionEvidence(BaseModel):
    """Evidence from detection engines (YARA, MITRE, threat classification)."""
    yara_matches: List[Dict] = Field(default_factory=list)
    mitre_techniques: List[Dict] = Field(default_factory=list)
    threat_classification: Optional[ThreatClassification] = None


class GraphEvidence(BaseModel):
    """Evidence derived from Neo4j graph analysis.

    Populated by the Graph Scorer acting as an evidence provider.
    The Risk Engine consumes this without ever querying Neo4j directly.
    """
    chain_length: int = 0
    has_c2_persistence: bool = False
    attack_path_nodes: List[str] = Field(default_factory=list)
    reasoning: List[str] = Field(default_factory=list)


class AnalysisMetadata(BaseModel):
    """Metadata about the analysis run itself."""
    job_id: str = ""
    filename: str = ""
    sha256: str = ""
    analysis_start: Optional[datetime] = None
    analysis_end: Optional[datetime] = None
    sandbox_mode: str = "mock"


class EvidenceEnvelope(BaseModel):
    """
    The unified evidence container passed to Risk Engine v2.

    Collects outputs from every analysis stage so that the scoring engine
    has access to ALL evidence. No evidence source is ignored.
    """
    job_id: str

    # Evidence layers
    static: StaticEvidence = Field(default_factory=StaticEvidence)
    runtime: RuntimeEvidence = Field(default_factory=RuntimeEvidence)
    iocs: IOCEvidence = Field(default_factory=IOCEvidence)
    detections: DetectionEvidence = Field(default_factory=DetectionEvidence)
    graph: GraphEvidence = Field(default_factory=GraphEvidence)
    metadata: AnalysisMetadata = Field(default_factory=AnalysisMetadata)

    # Analysis engine outputs
    capabilities: List[Capability] = Field(default_factory=list)
    behavior_chains: List[BehaviorChain] = Field(default_factory=list)

    # --- Backward compatibility properties ---
    # These allow RiskEngineV2 to keep using envelope.graph_chain_length
    # during the transition to envelope.graph.chain_length
    @property
    def graph_chain_length(self) -> int:
        return self.graph.chain_length

    @graph_chain_length.setter
    def graph_chain_length(self, value: int):
        self.graph.chain_length = value

    @property
    def graph_has_c2_persistence(self) -> bool:
        return self.graph.has_c2_persistence

    @graph_has_c2_persistence.setter
    def graph_has_c2_persistence(self, value: bool):
        self.graph.has_c2_persistence = value

    @classmethod
    def build(
        cls,
        job_id: str,
        static_results: dict,
        telemetry_events: list,
        iocs: list,
        mitre_mappings: list,
        yara_matches: list,
        capabilities: list,
        behavior_chains: list,
        threat: ThreatClassification,
        filename: str = "",
        sha256: str = "",
    ) -> "EvidenceEnvelope":
        """
        Factory method that assembles an EvidenceEnvelope from the raw
        outputs of each pipeline stage. This is the single integration
        point that replaces scattered argument passing.
        """
        # --- Static Evidence ---
        pe_data = static_results.get("pe", {})
        strings_data = static_results.get("strings", {})
        python_data = static_results.get("python", {})

        max_entropy = 0.0
        for section in pe_data.get("sections", []):
            max_entropy = max(max_entropy, section.get("entropy", 0.0))

        static = StaticEvidence(
            pe_imports=pe_data.get("imports", []),
            is_packed=pe_data.get("is_packed", False),
            suspicious_apis=pe_data.get("suspicious_apis", []),
            max_section_entropy=max_entropy,
            sections=pe_data.get("sections", []),
            string_iocs={
                "ips": strings_data.get("ips", []),
                "urls": strings_data.get("urls", []),
                "domains": strings_data.get("domains", []),
            },
            python_findings=[
                f.get("rule", "") for f in python_data.get("findings", [])
            ],
            total_strings_count=strings_data.get("total_strings_count", 0),
        )

        # --- Runtime Evidence ---
        process_events = []
        network_events = []
        dns_events = []
        file_events = []
        registry_events = []
        memory_injection_events = []
        persistence_events = []
        privilege_escalation_events = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            if evt_type == "PROCESS_CREATE":
                process_events.append(event)
            elif evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
                network_events.append(event)
            elif evt_type == "DNS_QUERY":
                dns_events.append(event)
            elif evt_type in ("FILE_WRITE", "FILE_READ", "FILE_CREATE", "FILE_DELETE"):
                file_events.append(event)
            elif evt_type in ("REGISTRY_CREATE", "REGISTRY_MODIFY"):
                registry_events.append(event)
            elif evt_type == "MEMORY_INJECTION":
                memory_injection_events.append(event)
            elif evt_type == "PERSISTENCE_EVENT":
                persistence_events.append(event)
            elif evt_type == "PRIVILEGE_ESCALATION":
                privilege_escalation_events.append(event)

        runtime = RuntimeEvidence(
            process_events=process_events,
            network_events=network_events,
            dns_events=dns_events,
            file_events=file_events,
            registry_events=registry_events,
            memory_injection_events=memory_injection_events,
            persistence_events=persistence_events,
            privilege_escalation_events=privilege_escalation_events,
            total_events=len(telemetry_events),
        )

        # --- IOC Evidence ---
        high_conf = [
            i for i in iocs 
            if i.get("confidence") == "High" 
            and not (i.get("type") in ("sha256", "md5") and "Static Analysis (Hash)" in i.get("source", ""))
        ]
        c2_domains = set()
        mal_ips = set()
        for ioc in high_conf:
            if ioc.get("type") == "domain":
                c2_domains.add(ioc.get("value"))
            elif ioc.get("type") == "ip":
                mal_ips.add(ioc.get("value"))

        ioc_evidence = IOCEvidence(
            iocs=iocs,
            high_confidence_count=len(high_conf),
            unique_c2_domains=len(c2_domains),
            unique_malicious_ips=len(mal_ips),
        )

        # --- Detection Evidence ---
        # Build full YARA match dicts (not just rule names)
        yara_match_dicts = []
        for match in yara_matches:
            if isinstance(match, str):
                yara_match_dicts.append({"rule": match, "tags": [], "meta": {}})
            elif isinstance(match, dict):
                yara_match_dicts.append(match)

        detections = DetectionEvidence(
            yara_matches=yara_match_dicts,
            mitre_techniques=mitre_mappings,
            threat_classification=threat,
        )

        # --- Metadata ---
        hash_data = static_results.get("hash", {})
        metadata = AnalysisMetadata(
            job_id=job_id,
            filename=filename,
            sha256=sha256 or hash_data.get("sha256", ""),
            analysis_start=datetime.utcnow(),
        )

        return cls(
            job_id=job_id,
            static=static,
            runtime=runtime,
            iocs=ioc_evidence,
            detections=detections,
            capabilities=capabilities,
            behavior_chains=behavior_chains,
            metadata=metadata,
        )
