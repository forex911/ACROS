"""
Evidence Node — Atomic Unit of the V3 Scoring System
=====================================================
Every observation from every subsystem (static analysis, runtime telemetry,
YARA, IOC extraction, MITRE mapping, graph correlation) becomes an
EvidenceNode.  Nodes carry computed confidence — never hardcoded points.

Confidence is derived from:
  - source_reliability  (how trustworthy is this source type?)
  - observation_quality (how specific / unambiguous is the observation?)
  - supporting evidence (how many independent signals corroborate this?)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════

class EvidenceSource(str, Enum):
    """Where the evidence originated."""
    STATIC = "static"
    RUNTIME = "runtime"
    YARA = "yara"
    IOC = "ioc"
    MITRE = "mitre"
    GRAPH = "graph"


class EvidenceCategory(str, Enum):
    """Semantic category of the observation."""
    PROCESS_SPAWN = "process_spawn"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_OPERATION = "file_operation"
    REGISTRY_OPERATION = "registry_operation"
    MEMORY_INJECTION = "memory_injection"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    ENCRYPTION = "encryption"
    OBFUSCATION = "obfuscation"
    SIGNATURE_MATCH = "signature_match"
    INDICATOR = "indicator"
    TECHNIQUE = "technique"
    STRUCTURAL = "structural"          # PE packing, entropy, etc.
    GRAPH_METRIC = "graph_metric"      # Neo4j-derived
    COLLECTION = "collection"          # Screenshot, webcam, etc.
    DISCOVERY = "discovery"            # whoami, systeminfo, etc.
    DEFENSE_EVASION = "defense_evasion"


# ═══════════════════════════════════════════════════════════════════════
# Source Reliability
# ═══════════════════════════════════════════════════════════════════════

# NOT score weights.  These represent how trustworthy a source type is
# as a measurement instrument.  Runtime observation of actual execution
# is the gold standard.  Static string matches are the least reliable.
SOURCE_RELIABILITY: Dict[EvidenceSource, float] = {
    EvidenceSource.RUNTIME: 0.95,
    EvidenceSource.GRAPH:   0.90,
    EvidenceSource.YARA:    0.85,
    EvidenceSource.IOC:     0.60,      # averaged; corroborated IOCs get boosted
    EvidenceSource.STATIC:  0.75,
    EvidenceSource.MITRE:   0.70,
}


# ═══════════════════════════════════════════════════════════════════════
# Evidence Node
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class EvidenceNode:
    """
    A single observation from any subsystem.

    Immutable after creation (frozen semantics enforced by convention;
    we use a regular dataclass so pydantic serialization stays simple).
    """

    # Identity
    source: EvidenceSource
    category: EvidenceCategory
    description: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None

    # Computed confidence  (0.0 – 1.0)
    confidence: float = 0.0
    source_reliability: float = 0.0
    observation_quality: float = 0.5   # default "medium" quality

    # Relationships  (populated by EvidenceBuilder)
    dependencies: List[str] = field(default_factory=list)
    supporting_observations: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Unique ID (computed lazily)
    _id: Optional[str] = field(default=None, repr=False)

    # ── ID generation ──────────────────────────────────────────────
    @property
    def id(self) -> str:
        if self._id is None:
            # Deterministic hash from source + category + description
            key = f"{self.source.value}:{self.category.value}:{self.description}"
            self._id = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self._id

    # ── Confidence computation ─────────────────────────────────────
    def compute_initial_confidence(self) -> None:
        """
        Set initial confidence from source reliability and observation quality.

        Called once during graph construction.  Subsequent propagation
        (corroboration boost) is handled by the ConfidenceEngine.
        """
        self.source_reliability = SOURCE_RELIABILITY.get(
            self.source, 0.50
        )
        self.confidence = self.source_reliability * self.observation_quality

    # ── Serialization ──────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source.value,
            "category": self.category.value,
            "description": self.description,
            "confidence": round(self.confidence, 4),
            "source_reliability": round(self.source_reliability, 4),
            "observation_quality": round(self.observation_quality, 4),
            "mitre_techniques": self.mitre_techniques,
            "dependencies": self.dependencies,
            "supporting_observations": self.supporting_observations,
            "timestamp": self.timestamp,
        }
