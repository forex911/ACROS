"""
Behaviour Graph — Graph-Traversal-Based Behaviour Discovery
=============================================================
Replaces V2's hardcoded BehaviorEngine.detect_chains() with automatic
behaviour pattern discovery via graph traversal.

Instead of:
    if "Shadow Copy Deletion" in cap_names:
        add_chain("Ransomware", "Critical", 98, ...)

V3 does:
    chains = discover_causal_chains(evidence_graph)
    complexity = compute_complexity(chains, evidence_graph)
    # Complexity and confidence emerge from graph structure
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.analysis.v3.evidence_graph import EvidenceGraph
from app.analysis.v3.evidence_node import EvidenceCategory, EvidenceNode


# ═══════════════════════════════════════════════════════════════════════
# Behaviour Chain
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BehaviourChain:
    """
    A discovered causal chain of evidence nodes representing
    coordinated malicious behaviour.
    """
    chain_id: str
    node_ids: List[str]
    categories: List[str]          # Ordered categories in the chain
    descriptions: List[str]        # Human-readable descriptions
    confidence: float              # Derived from constituent node confidences
    complexity: float              # Graph-derived complexity metric
    terminal_category: str         # Category of the chain's terminal node
    mitre_coverage: List[str]      # MITRE techniques touched

    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id,
            "length": len(self.node_ids),
            "categories": self.categories,
            "descriptions": self.descriptions,
            "confidence": round(self.confidence, 4),
            "complexity": round(self.complexity, 4),
            "terminal_category": self.terminal_category,
            "mitre_coverage": self.mitre_coverage,
        }


# ═══════════════════════════════════════════════════════════════════════
# Behavioural Complexity
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BehaviouralComplexity:
    """
    Aggregate behavioural complexity computed from the evidence graph.
    Higher complexity = more coordinated malicious behaviour.
    """
    depth: int = 0                   # Longest chain length
    width: int = 0                   # Max parallel activities
    branching_factor: float = 0.0    # Average out-degree
    category_diversity: int = 0      # Distinct categories in chains
    mitre_diversity: int = 0         # Distinct MITRE tactics in chains
    chain_count: int = 0             # Number of discovered chains
    coordination_ratio: float = 0.0  # Ratio of connected vs isolated nodes
    event_density: float = 0.0       # Edges per node

    @property
    def score(self) -> float:
        """
        Combined complexity score (0.0 – 1.0).

        Derived from graph properties, NOT from hardcoded weights.
        Uses a logarithmic combination so that each additional metric
        has diminishing influence (naturally avoids inflation).
        """
        factors = [
            _log_scale(self.depth, 10),           # chains up to depth 10 matter
            _log_scale(self.width, 15),            # width up to 15
            _log_scale(self.branching_factor, 5),  # branching up to 5
            _log_scale(self.category_diversity, 8), # up to 8 categories
            _log_scale(self.mitre_diversity, 6),    # up to 6 tactics
            _log_scale(self.chain_count, 5),        # up to 5 chains
            min(1.0, self.coordination_ratio),
            min(1.0, self.event_density),
        ]

        # Geometric mean: penalizes if any single factor is very low
        product = 1.0
        for f in factors:
            product *= max(0.01, f)   # floor at 0.01 to avoid zeroing out

        return product ** (1.0 / len(factors))

    def to_dict(self) -> Dict:
        return {
            "depth": self.depth,
            "width": self.width,
            "branching_factor": round(self.branching_factor, 2),
            "category_diversity": self.category_diversity,
            "mitre_diversity": self.mitre_diversity,
            "chain_count": self.chain_count,
            "coordination_ratio": round(self.coordination_ratio, 4),
            "event_density": round(self.event_density, 4),
            "complexity_score": round(self.score, 4),
        }


# ═══════════════════════════════════════════════════════════════════════
# Behaviour Discovery
# ═══════════════════════════════════════════════════════════════════════

class BehaviourGraphAnalyzer:
    """
    Discovers behavioural patterns and computes complexity metrics
    from an EvidenceGraph without any hardcoded chain definitions.
    """

    @staticmethod
    def discover_chains(graph: EvidenceGraph) -> List[BehaviourChain]:
        """
        Find all maximal causal chains in the evidence graph.
        A chain is a directed path through evidence nodes representing
        a sequence of causally or temporally related observations.
        """
        raw_paths = graph.find_all_maximal_paths()

        chains: List[BehaviourChain] = []
        for i, path in enumerate(raw_paths):
            nodes = [graph.get_node(nid) for nid in path]
            nodes = [n for n in nodes if n is not None]

            if len(nodes) < 2:
                continue

            # Compute chain confidence from constituent node confidences
            # using geometric mean (penalizes weak links)
            confidences = [n.confidence for n in nodes if n.confidence > 0]
            if confidences:
                chain_conf = _geometric_mean(confidences)
            else:
                chain_conf = 0.0

            # Chain complexity = chain length normalized by diversity
            categories = [n.category.value for n in nodes]
            unique_cats = set(categories)
            mitre = []
            for n in nodes:
                mitre.extend(n.mitre_techniques)
            unique_mitre = list(set(mitre))

            complexity = _log_scale(len(nodes), 10) * _log_scale(len(unique_cats), 6)

            chains.append(BehaviourChain(
                chain_id=f"chain_{i:03d}",
                node_ids=path,
                categories=categories,
                descriptions=[n.description for n in nodes],
                confidence=chain_conf,
                complexity=complexity,
                terminal_category=categories[-1] if categories else "",
                mitre_coverage=unique_mitre,
            ))

        # Sort by confidence × complexity (most significant first)
        chains.sort(key=lambda c: c.confidence * c.complexity, reverse=True)
        return chains

    @staticmethod
    def compute_complexity(
        graph: EvidenceGraph,
        chains: List[BehaviourChain],
    ) -> BehaviouralComplexity:
        """
        Compute aggregate behavioural complexity from graph structure
        and discovered chains.
        """
        # Category diversity across all chains
        all_categories: Set[str] = set()
        all_mitre: Set[str] = set()
        for chain in chains:
            all_categories.update(chain.categories)
            all_mitre.update(chain.mitre_coverage)

        # Coordination ratio: connected nodes / total nodes
        total_nodes = graph.node_count
        connected_nodes = total_nodes - len([
            n for n in graph.nodes.values()
            if not graph.get_children(n.id) and not graph.get_parents(n.id)
        ])
        coordination = connected_nodes / total_nodes if total_nodes > 0 else 0.0

        # Event density: edges / nodes
        density = graph.edge_count / total_nodes if total_nodes > 0 else 0.0

        return BehaviouralComplexity(
            depth=graph.depth(),
            width=graph.width(),
            branching_factor=graph.branching_factor(),
            category_diversity=len(all_categories),
            mitre_diversity=len(all_mitre),
            chain_count=len(chains),
            coordination_ratio=coordination,
            event_density=min(3.0, density),   # cap density to [0, 3]
        )


# ═══════════════════════════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════════════════════════

def _log_scale(value: float, ceiling: float) -> float:
    """Logarithmic scaling of value to [0, 1] range with diminishing returns."""
    if value <= 0:
        return 0.0
    return min(1.0, math.log1p(value) / math.log1p(ceiling))


def _geometric_mean(values: List[float]) -> float:
    """Geometric mean of a list of positive floats."""
    if not values:
        return 0.0
    product = 1.0
    for v in values:
        product *= max(0.001, v)
    return product ** (1.0 / len(values))
