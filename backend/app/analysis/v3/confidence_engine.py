"""
Confidence Propagation Engine — Noisy-OR Confidence Combination
================================================================
The mathematical core of V3.  Replaces all hardcoded point values
with a principled confidence propagation algorithm.

Algorithm: Bottom-Up Noisy-OR Propagation
─────────────────────────────────────────
1. Start with leaf evidence nodes (raw observations)
2. Each leaf has initial confidence = source_reliability × observation_quality
3. For each group of related evidence:
   a. If from INDEPENDENT sources → combine with Noisy-OR:
      combined = 1 - Π(1 - child_confidence)
   b. If from SAME source → take max (avoid double-counting)
4. Corroboration: N independent sources naturally boost confidence
   via the Noisy-OR formula (built-in diminishing returns)
5. Propagate upward: evidence → behaviour → threat → overall

Why Noisy-OR?
─────────────
- Standard probabilistic model for combining independent evidence
- 3 independent 60% signals → 93.6% combined (natural corroboration)
- 10th signal adds less than 2nd (built-in diminishing returns)
- Deterministic, explainable, no training data required
- Drop-in replaceable with Bayesian net or GNN in future
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.analysis.v3.evidence_graph import EvidenceGraph
from app.analysis.v3.evidence_node import EvidenceCategory, EvidenceNode, EvidenceSource
from app.analysis.v3.behaviour_graph import BehaviourChain, BehaviouralComplexity


# ═══════════════════════════════════════════════════════════════════════
# Confidence Trace (for explainability)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ConfidenceStep:
    """One step in the confidence propagation trace."""
    layer: str                   # "evidence", "behaviour", "threat", "overall"
    description: str
    input_confidences: List[float]
    method: str                  # "noisy_or", "geometric_mean", "max"
    output_confidence: float
    contributing_nodes: List[str]  # Node IDs

    def to_dict(self) -> Dict:
        return {
            "layer": self.layer,
            "description": self.description,
            "input_confidences": [round(c, 4) for c in self.input_confidences],
            "method": self.method,
            "output_confidence": round(self.output_confidence, 4),
            "contributing_nodes": self.contributing_nodes,
        }


# ═══════════════════════════════════════════════════════════════════════
# Confidence Engine
# ═══════════════════════════════════════════════════════════════════════

class ConfidenceEngine:
    """
    Propagates confidence bottom-up through the evidence layers.

    No subsystem directly modifies the final score.  Every confidence
    value is derived from evidence below it.
    """

    def __init__(self) -> None:
        self.trace: List[ConfidenceStep] = []

    def propagate(
        self,
        graph: EvidenceGraph,
        chains: List[BehaviourChain],
        complexity: BehaviouralComplexity,
    ) -> Tuple[float, float, float]:
        """
        Run the full propagation pipeline.

        Returns:
            (evidence_confidence, behaviour_confidence, overall_confidence)
        """
        self.trace = []

        evidence_conf = self._propagate_evidence(graph)
        behaviour_conf = self._propagate_behaviour(chains, complexity)
        overall = self._combine_layers(evidence_conf, behaviour_conf)

        return evidence_conf, behaviour_conf, overall

    # ── Layer 1: Evidence Confidence ───────────────────────────────

    def _propagate_evidence(self, graph: EvidenceGraph) -> float:
        """
        Combine evidence node confidences using source-aware Noisy-OR.

        Nodes from independent sources combine multiplicatively.
        Nodes from the same source combine via max (avoid double-counting).
        """
        if not graph.nodes:
            return 0.0

        # Group nodes by category, then by source within each category
        by_category: Dict[EvidenceCategory, Dict[EvidenceSource, List[float]]] = {}
        for node in graph.nodes.values():
            cat_dict = by_category.setdefault(node.category, {})
            cat_dict.setdefault(node.source, []).append(node.confidence)

        # For each category: take max within each source, then Noisy-OR across sources
        category_confidences: Dict[str, float] = {}
        for cat, source_dict in by_category.items():
            per_source_max = [max(confs) for confs in source_dict.values()]
            combined = noisy_or(per_source_max)
            category_confidences[cat.value] = combined

            self.trace.append(ConfidenceStep(
                layer="evidence",
                description=f"Category '{cat.value}': {len(source_dict)} sources, "
                            f"per-source max → Noisy-OR",
                input_confidences=per_source_max,
                method="noisy_or",
                output_confidence=combined,
                contributing_nodes=[
                    n.id for n in graph.nodes.values() if n.category == cat
                ][:10],   # cap for readability
            ))

        if not category_confidences:
            return 0.0

        # Combine all category confidences with Noisy-OR
        all_cat_confs = list(category_confidences.values())
        evidence_conf = noisy_or(all_cat_confs)

        self.trace.append(ConfidenceStep(
            layer="evidence",
            description=f"All {len(all_cat_confs)} categories combined",
            input_confidences=all_cat_confs,
            method="noisy_or",
            output_confidence=evidence_conf,
            contributing_nodes=[],
        ))

        return evidence_conf

    # ── Layer 2: Behaviour Confidence ──────────────────────────────

    def _propagate_behaviour(
        self,
        chains: List[BehaviourChain],
        complexity: BehaviouralComplexity,
    ) -> float:
        """
        Derive behaviour confidence from discovered chains and
        structural complexity.

        Uses geometric mean of chain confidence and complexity score
        so that both must be meaningfully present.
        """
        if not chains:
            # No chains discovered → low (but not zero) behaviour confidence
            # based on complexity alone
            base = complexity.score
            self.trace.append(ConfidenceStep(
                layer="behaviour",
                description="No causal chains discovered; using complexity only",
                input_confidences=[base],
                method="passthrough",
                output_confidence=base,
                contributing_nodes=[],
            ))
            return base

        # Combine top chain confidences via Noisy-OR
        # (more chains from independent evidence strengthen the conclusion)
        top_chains = chains[:10]   # cap at top 10 chains
        chain_confs = [c.confidence for c in top_chains]
        chain_combined = noisy_or(chain_confs)

        # Blend with complexity
        complexity_score = complexity.score
        behaviour_conf = geometric_mean([chain_combined, complexity_score])

        self.trace.append(ConfidenceStep(
            layer="behaviour",
            description=f"{len(top_chains)} chains (Noisy-OR) × complexity (geometric mean)",
            input_confidences=[chain_combined, complexity_score],
            method="geometric_mean",
            output_confidence=behaviour_conf,
            contributing_nodes=[c.chain_id for c in top_chains],
        ))

        return behaviour_conf

    # ── Layer 3: Overall Confidence ────────────────────────────────

    def _combine_layers(
        self,
        evidence_conf: float,
        behaviour_conf: float,
    ) -> float:
        """
        Final combination of evidence and behaviour confidence.

        Uses geometric mean so that both evidence AND behaviour
        must be present for high overall confidence.  A sample with
        lots of evidence but no coordinated behaviour (e.g., noisy
        benignware) will get moderated.
        """
        overall = geometric_mean([evidence_conf, behaviour_conf])

        self.trace.append(ConfidenceStep(
            layer="overall",
            description="Evidence × Behaviour (geometric mean)",
            input_confidences=[evidence_conf, behaviour_conf],
            method="geometric_mean",
            output_confidence=overall,
            contributing_nodes=[],
        ))

        return overall


# ═══════════════════════════════════════════════════════════════════════
# Mathematical Primitives
# ═══════════════════════════════════════════════════════════════════════

def noisy_or(probabilities: List[float]) -> float:
    """
    Noisy-OR combination of independent probabilities.

    P(at least one true) = 1 - Π(1 - p_i)

    Properties:
    - Two 50% signals → 75%
    - Three 60% signals → 93.6%
    - Built-in diminishing returns
    - Deterministic and explainable
    """
    if not probabilities:
        return 0.0

    complement_product = 1.0
    for p in probabilities:
        complement_product *= (1.0 - max(0.0, min(1.0, p)))

    return 1.0 - complement_product


def geometric_mean(values: List[float]) -> float:
    """
    Geometric mean of positive values.

    Penalizes if any single input is weak — you can't compensate
    for zero evidence with maximum behaviour complexity.
    """
    if not values:
        return 0.0

    product = 1.0
    for v in values:
        product *= max(0.001, v)  # floor to avoid zeroing

    return product ** (1.0 / len(values))
