"""
Threat Inference Engine — Probabilistic Threat Family Classification
=====================================================================
Replaces V2's first-match if/elif ThreatClassifier with a probabilistic
inference engine that computes a confidence distribution over all
threat families.

Instead of:
    if "Infostealer Chain" in chain_names:
        return "Infostealer", 95

V3 does:
    distribution = infer(evidence_graph, behaviour_chains)
    # {"Ransomware": 0.87, "RAT": 0.12, "Dropper": 0.05, ...}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.analysis.v3.evidence_graph import EvidenceGraph
from app.analysis.v3.evidence_node import EvidenceCategory, EvidenceNode
from app.analysis.v3.behaviour_graph import BehaviourChain
from app.analysis.v3.confidence_engine import noisy_or


# ═══════════════════════════════════════════════════════════════════════
# Threat Family Signatures (Declarative Subgraph Templates)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ThreatSignature:
    """
    Declarative definition of a threat family.

    Instead of hardcoded if/elif logic, each family defines:
    - required_categories:  Must be present for this family
    - supporting_categories:  Increase confidence if present
    - mitre_techniques:  Expected MITRE techniques
    """
    family: str
    required_categories: Set[EvidenceCategory]
    supporting_categories: Set[EvidenceCategory] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)


# Threat family definitions  (loaded as data, not logic)
THREAT_SIGNATURES: List[ThreatSignature] = [
    ThreatSignature(
        family="Ransomware",
        required_categories={EvidenceCategory.ENCRYPTION},
        supporting_categories={
            EvidenceCategory.PERSISTENCE,
            EvidenceCategory.PROCESS_SPAWN,
            EvidenceCategory.FILE_OPERATION,
            EvidenceCategory.NETWORK_CONNECTION,
        },
        mitre_techniques={"T1486", "T1490", "T1547.001"},
    ),
    ThreatSignature(
        family="RAT",
        required_categories={
            EvidenceCategory.PERSISTENCE,
            EvidenceCategory.NETWORK_CONNECTION,
        },
        supporting_categories={
            EvidenceCategory.PROCESS_SPAWN,
            EvidenceCategory.REGISTRY_OPERATION,
            EvidenceCategory.DISCOVERY,
            EvidenceCategory.COLLECTION,
        },
        mitre_techniques={"T1071", "T1547.001", "T1059", "T1105"},
    ),
    ThreatSignature(
        family="Infostealer",
        required_categories={EvidenceCategory.CREDENTIAL_ACCESS},
        supporting_categories={
            EvidenceCategory.DATA_EXFILTRATION,
            EvidenceCategory.COLLECTION,
            EvidenceCategory.NETWORK_CONNECTION,
        },
        mitre_techniques={"T1555.003", "T1539", "T1528", "T1552", "T1048"},
    ),
    ThreatSignature(
        family="Credential Stealer",
        required_categories={EvidenceCategory.CREDENTIAL_ACCESS},
        supporting_categories={
            EvidenceCategory.NETWORK_CONNECTION,
            EvidenceCategory.FILE_OPERATION,
        },
        mitre_techniques={"T1555.003", "T1539", "T1528"},
    ),
    ThreatSignature(
        family="Dropper",
        required_categories={
            EvidenceCategory.NETWORK_CONNECTION,
            EvidenceCategory.FILE_OPERATION,
        },
        supporting_categories={
            EvidenceCategory.OBFUSCATION,
            EvidenceCategory.PROCESS_SPAWN,
        },
        mitre_techniques={"T1105", "T1059"},
    ),
    ThreatSignature(
        family="Backdoor",
        required_categories={
            EvidenceCategory.PERSISTENCE,
            EvidenceCategory.NETWORK_CONNECTION,
        },
        supporting_categories={
            EvidenceCategory.MEMORY_INJECTION,
            EvidenceCategory.DEFENSE_EVASION,
            EvidenceCategory.PROCESS_SPAWN,
        },
        mitre_techniques={"T1055", "T1071", "T1547.001"},
    ),
    ThreatSignature(
        family="Worm",
        required_categories={
            EvidenceCategory.NETWORK_CONNECTION,
            EvidenceCategory.FILE_OPERATION,
        },
        supporting_categories={
            EvidenceCategory.DISCOVERY,
            EvidenceCategory.PROCESS_SPAWN,
        },
        mitre_techniques={"T1046", "T1105"},
    ),
    ThreatSignature(
        family="Spyware",
        required_categories={EvidenceCategory.COLLECTION},
        supporting_categories={
            EvidenceCategory.PERSISTENCE,
            EvidenceCategory.NETWORK_CONNECTION,
            EvidenceCategory.DATA_EXFILTRATION,
        },
        mitre_techniques={"T1113", "T1125", "T1074"},
    ),
    ThreatSignature(
        family="Miner",
        required_categories={EvidenceCategory.NETWORK_CONNECTION},
        supporting_categories={
            EvidenceCategory.PERSISTENCE,
            EvidenceCategory.DEFENSE_EVASION,
        },
        mitre_techniques={"T1496"},
    ),
    ThreatSignature(
        family="Loader",
        required_categories={
            EvidenceCategory.NETWORK_CONNECTION,
            EvidenceCategory.PROCESS_SPAWN,
        },
        supporting_categories={
            EvidenceCategory.OBFUSCATION,
            EvidenceCategory.MEMORY_INJECTION,
        },
        mitre_techniques={"T1105", "T1059"},
    ),
]


# ═══════════════════════════════════════════════════════════════════════
# Threat Inference
# ═══════════════════════════════════════════════════════════════════════

class ThreatInference:
    """
    Probabilistic threat family inference.

    Computes a confidence distribution over all known threat families
    by matching evidence against declarative signature templates.
    """

    @staticmethod
    def infer(
        graph: EvidenceGraph,
        chains: List[BehaviourChain],
    ) -> Dict[str, float]:
        """
        Compute probability distribution: {family: confidence}

        The confidence for each family is derived from three factors:
        1. Coverage: fraction of required categories present
        2. Quality:  average confidence of matched evidence nodes
        3. Coherence: how connected the matched nodes are
        """
        if not graph.nodes:
            return {}

        # Collect observed categories and their best confidence
        observed_categories: Dict[EvidenceCategory, float] = {}
        for node in graph.nodes.values():
            current_best = observed_categories.get(node.category, 0.0)
            observed_categories[node.category] = max(current_best, node.confidence)

        # Collect observed MITRE techniques
        observed_mitre: Set[str] = set()
        for node in graph.nodes.values():
            observed_mitre.update(node.mitre_techniques)
        for chain in chains:
            observed_mitre.update(chain.mitre_coverage)

        # Score each threat family
        distribution: Dict[str, float] = {}

        for sig in THREAT_SIGNATURES:
            # 1. Coverage: what fraction of required categories are present?
            required_present = sig.required_categories & set(observed_categories.keys())
            if not required_present:
                distribution[sig.family] = 0.0
                continue

            coverage = len(required_present) / len(sig.required_categories)

            # 2. Quality: average confidence of matched required categories
            required_confidences = [
                observed_categories[cat] for cat in required_present
            ]
            quality = sum(required_confidences) / len(required_confidences)

            # 3. Supporting evidence boost (Noisy-OR of supporting categories)
            support_present = sig.supporting_categories & set(observed_categories.keys())
            support_confidences = [observed_categories[cat] for cat in support_present]
            support_boost = noisy_or(support_confidences) if support_confidences else 0.0

            # 4. MITRE overlap (what fraction of expected techniques are seen?)
            if sig.mitre_techniques:
                mitre_overlap = len(sig.mitre_techniques & observed_mitre) / len(sig.mitre_techniques)
            else:
                mitre_overlap = 0.0

            # Combine: coverage × quality × (1 + support boost) × (1 + mitre overlap)
            # Then normalize to [0, 1]
            raw_confidence = coverage * quality * (1 + support_boost * 0.3) * (1 + mitre_overlap * 0.2)
            # Clamp to [0, 1]
            distribution[sig.family] = min(1.0, raw_confidence)

        return distribution

    @staticmethod
    def classify(distribution: Dict[str, float]) -> Tuple[str, float]:
        """
        Pick the top family from the distribution.
        Returns (family, confidence).
        """
        if not distribution:
            return "Unknown", 0.0

        best_family = max(distribution, key=distribution.get)
        best_conf = distribution[best_family]

        if best_conf < 0.1:
            return "Unknown", 0.0

        return best_family, best_conf
