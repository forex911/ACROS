"""
Score Generator — Converts Propagated Confidence to Risk Score
===============================================================
The final step of V3.  Maps the propagated confidence (0.0–1.0)
to a 0–100 risk score and generates the full explainability report.

No hardcoded score values.  The score emerges from:
    Evidence Confidence  →  Behaviour Confidence  →  Overall Confidence  →  Score
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from app.analysis.models import RiskAssessment, ScoreContributor
from app.analysis.v3.confidence_engine import ConfidenceStep
from app.analysis.v3.behaviour_graph import BehaviourChain, BehaviouralComplexity


# ═══════════════════════════════════════════════════════════════════════
# Output Model
# ═══════════════════════════════════════════════════════════════════════

class RiskAssessmentV3(RiskAssessment):
    """
    V3 risk assessment — extends V2's RiskAssessment for backward
    compatibility while adding evidence-derived fields.
    """
    # V3 additions
    evidence_tree: Dict = Field(default_factory=dict)
    behaviour_tree: Dict = Field(default_factory=dict)
    threat_distribution: Dict[str, float] = Field(default_factory=dict)
    confidence_trace: List[Dict] = Field(default_factory=list)
    complexity_metrics: Dict = Field(default_factory=dict)
    engine_version: str = "v3"


# ═══════════════════════════════════════════════════════════════════════
# Score Generator
# ═══════════════════════════════════════════════════════════════════════

class ScoreGenerator:
    """
    Converts propagated confidence into a 0–100 risk score with
    full explainability.
    """

    @staticmethod
    def generate(
        evidence_confidence: float,
        behaviour_confidence: float,
        overall_confidence: float,
        threat_family: str,
        threat_family_confidence: float,
        threat_distribution: Dict[str, float],
        chains: List[BehaviourChain],
        complexity: BehaviouralComplexity,
        evidence_tree: Dict,
        confidence_trace: List[ConfidenceStep],
        source_diversity: int,
    ) -> RiskAssessmentV3:
        """
        Generate the final V3 risk assessment.

        The score is derived from overall_confidence using a calibrated
        sigmoid mapping that:
        - Compresses very low confidences to the 0-20 range
        - Has a steep transition around 0.4-0.6
        - Compresses very high confidences to the 80-100 range
        """

        # ── Score Mapping ──────────────────────────────────────────
        score = _confidence_to_score(overall_confidence)

        # ── Severity Band ──────────────────────────────────────────
        severity = _score_to_severity(score)

        # ── Confidence (as V2-compatible integer 0–100) ────────────
        confidence_int = int(overall_confidence * 100)

        # ── Verdict ────────────────────────────────────────────────
        verdict = _determine_verdict(
            score, source_diversity, threat_family, threat_family_confidence
        )

        # ── Build V2-compatible score breakdown ────────────────────
        score_breakdown = {
            "evidence_confidence": round(evidence_confidence, 4),
            "behaviour_confidence": round(behaviour_confidence, 4),
            "threat_confidence": round(threat_family_confidence, 4),
            "overall_confidence": round(overall_confidence, 4),
        }

        # ── Build V2-compatible reasoning ──────────────────────────
        reasoning = _build_reasoning(
            evidence_confidence, behaviour_confidence,
            overall_confidence, threat_family, threat_family_confidence,
            chains, complexity, source_diversity, score,
        )

        # ── Build V2-compatible contributors ───────────────────────
        contributors = _build_contributors(
            chains, threat_family, threat_family_confidence,
            evidence_confidence, behaviour_confidence,
        )

        # ── Build behaviour tree ───────────────────────────────────
        behaviour_tree = {
            "chains": [c.to_dict() for c in chains[:10]],
            "complexity": complexity.to_dict(),
        }

        return RiskAssessmentV3(
            score=score,
            severity=severity,
            confidence=confidence_int,
            verdict=verdict,
            score_breakdown=score_breakdown,
            modifiers={},   # V3 has no additive modifiers
            reasoning=reasoning,
            contributors=contributors,
            evidence_tree=evidence_tree,
            behaviour_tree=behaviour_tree,
            threat_distribution={
                k: round(v, 4) for k, v in threat_distribution.items() if v > 0.01
            },
            confidence_trace=[step.to_dict() for step in confidence_trace],
            complexity_metrics=complexity.to_dict(),
        )


# ═══════════════════════════════════════════════════════════════════════
# Score Mapping
# ═══════════════════════════════════════════════════════════════════════

def _confidence_to_score(confidence: float) -> int:
    """
    Map confidence (0.0–1.0) to score (0–100) using a calibrated
    sigmoid that preserves the full dynamic range.

    The mapping is:
        score = 100 × sigmoid(k × (confidence - midpoint))

    Where k controls steepness and midpoint is the inflection point.
    Calibrated so that:
        - confidence 0.0  →  score ~0
        - confidence 0.3  →  score ~20
        - confidence 0.5  →  score ~50
        - confidence 0.7  →  score ~80
        - confidence 1.0  →  score ~100
    """
    if confidence <= 0.0:
        return 0
    if confidence >= 1.0:
        return 100

    # Steepness and midpoint calibration
    k = 8.0
    midpoint = 0.5

    logit = k * (confidence - midpoint)
    sigmoid_value = 1.0 / (1.0 + math.exp(-logit))

    return max(0, min(100, int(round(sigmoid_value * 100))))


def _score_to_severity(score: int) -> str:
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 75:
        return "HIGH"
    else:
        return "CRITICAL"


def _determine_verdict(
    score: int,
    source_diversity: int,
    threat_family: str,
    threat_confidence: float,
) -> str:
    """Evidence-breadth-aware verdict."""
    has_family = threat_family != "Unknown" and threat_confidence > 0.3

    # High breadth + high score = confirmed
    if source_diversity >= 4 and score > 50:
        return f"Confirmed {threat_family}" if has_family else "Confirmed Malicious"

    if has_family and threat_confidence > 0.6:
        return threat_family

    if source_diversity >= 3 and score > 40:
        return "Highly Suspicious"

    if score > 50:
        return "Suspicious"
    elif score > 25:
        return "Low Confidence Suspicious"
    else:
        return "Benign"


# ═══════════════════════════════════════════════════════════════════════
# Explainability helpers
# ═══════════════════════════════════════════════════════════════════════

def _build_reasoning(
    evidence_conf: float,
    behaviour_conf: float,
    overall_conf: float,
    threat_family: str,
    threat_conf: float,
    chains: List[BehaviourChain],
    complexity: BehaviouralComplexity,
    source_diversity: int,
    score: int,
) -> List[str]:
    """Build human-readable reasoning list (V2-compatible format)."""
    reasoning = []

    reasoning.append(
        f"Evidence confidence: {evidence_conf:.2%} "
        f"({source_diversity} independent sources)"
    )

    if chains:
        reasoning.append(
            f"Behaviour confidence: {behaviour_conf:.2%} "
            f"({len(chains)} causal chains discovered, "
            f"complexity={complexity.score:.2f})"
        )
        for chain in chains[:5]:
            reasoning.append(
                f"  Chain: {' → '.join(chain.categories[:6])} "
                f"(confidence={chain.confidence:.2%})"
            )

    if threat_family != "Unknown":
        reasoning.append(
            f"Threat classification: {threat_family} "
            f"(confidence={threat_conf:.2%})"
        )

    reasoning.append(
        f"Overall confidence: {overall_conf:.2%} → Score: {score}/100"
    )

    return reasoning


def _build_contributors(
    chains: List[BehaviourChain],
    threat_family: str,
    threat_conf: float,
    evidence_conf: float,
    behaviour_conf: float,
) -> List[ScoreContributor]:
    """Build V2-compatible contributors list."""
    contributors = []

    contributors.append(ScoreContributor(
        source="Evidence",
        reason=f"Aggregated evidence confidence: {evidence_conf:.2%}",
        points=int(evidence_conf * 50),   # approximate for V2 display
    ))

    if chains:
        contributors.append(ScoreContributor(
            source="Behaviour",
            reason=f"{len(chains)} causal chains → confidence: {behaviour_conf:.2%}",
            points=int(behaviour_conf * 30),
        ))

    if threat_family != "Unknown":
        contributors.append(ScoreContributor(
            source="Threat",
            reason=f"Classified as {threat_family} ({threat_conf:.0%})",
            points=int(threat_conf * 20),
        ))

    return contributors
