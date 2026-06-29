"""
Risk Engine V3 — Orchestrator
===============================
Ties together the Evidence Graph, Behaviour Discovery, Confidence
Propagation, Threat Inference, and Score Generation into a single
entry point that the pipeline calls.

This is a drop-in replacement for RiskEngineV2.calculate_risk().
"""

from __future__ import annotations

from typing import Optional

from app.analysis.evidence_envelope import EvidenceEnvelope
from app.analysis.models import RiskAssessment, ScoreContributor
from app.analysis.v3.evidence_builder import EvidenceBuilder
from app.analysis.v3.behaviour_graph import BehaviourGraphAnalyzer
from app.analysis.v3.confidence_engine import ConfidenceEngine
from app.analysis.v3.threat_inference import ThreatInference
from app.analysis.v3.score_generator import RiskAssessmentV3, ScoreGenerator


class RiskEngineV3:
    """
    Evidence-Based Dynamic Scoring Engine.

    Pipeline:
        EvidenceEnvelope
          → EvidenceGraph (builder)
            → BehaviourChains + Complexity (behaviour analyzer)
              → Confidence Propagation (noisy-OR engine)
                → Threat Inference (probabilistic)
                  → Final Score + Explainability Report

    Every point in the final score traces back to specific evidence
    through the confidence trace.  No hardcoded score values.
    """

    @staticmethod
    def calculate_risk(envelope: EvidenceEnvelope) -> RiskAssessmentV3:
        """
        Main entry point — replaces RiskEngineV2.calculate_risk().

        Accepts the same EvidenceEnvelope, returns a RiskAssessmentV3
        (which extends RiskAssessment for backward compatibility).
        """

        # ── Step 1: Build Evidence Graph ───────────────────────────
        evidence_graph = EvidenceBuilder.build(envelope)

        # ── Step 2: Discover Behaviour Patterns ────────────────────
        chains = BehaviourGraphAnalyzer.discover_chains(evidence_graph)
        complexity = BehaviourGraphAnalyzer.compute_complexity(
            evidence_graph, chains
        )

        # ── Step 3: Propagate Confidence ───────────────────────────
        engine = ConfidenceEngine()
        evidence_conf, behaviour_conf, overall_conf = engine.propagate(
            evidence_graph, chains, complexity
        )

        # ── Step 4: Infer Threat Family ────────────────────────────
        threat_distribution = ThreatInference.infer(evidence_graph, chains)
        threat_family, threat_conf = ThreatInference.classify(threat_distribution)

        # Blend threat confidence into overall (if we have a classification)
        if threat_conf > 0.1:
            # Boost overall confidence when a threat family is identified
            # but let the evidence speak — don't override low evidence
            from app.analysis.v3.confidence_engine import geometric_mean
            overall_conf = geometric_mean([overall_conf, overall_conf, threat_conf])

        # ── Step 5: Generate Score ─────────────────────────────────
        assessment = ScoreGenerator.generate(
            evidence_confidence=evidence_conf,
            behaviour_confidence=behaviour_conf,
            overall_confidence=overall_conf,
            threat_family=threat_family,
            threat_family_confidence=threat_conf,
            threat_distribution=threat_distribution,
            chains=chains,
            complexity=complexity,
            evidence_tree=evidence_graph.to_dict(),
            confidence_trace=engine.trace,
            source_diversity=evidence_graph.source_diversity(),
        )

        return assessment

    @staticmethod
    def propagate_artifact_risk(
        parent_assessment: RiskAssessment,
        max_child_score: int,
    ) -> RiskAssessment:
        """
        Elevate parent risk if a child artifact scored higher.
        Uses 90% propagation factor (same as V2).
        """
        if max_child_score <= parent_assessment.score:
            return parent_assessment

        propagated_score = int(max_child_score * 0.9)
        if propagated_score <= parent_assessment.score:
            return parent_assessment

        final_score = min(100, propagated_score)

        if final_score <= 25:
            severity = "LOW"
        elif final_score <= 50:
            severity = "MEDIUM"
        elif final_score <= 75:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        parent_assessment.score = final_score
        parent_assessment.severity = severity
        parent_assessment.reasoning.append(
            f"Risk elevated to {severity} ({final_score}) "
            f"due to high-risk child artifacts."
        )
        parent_assessment.contributors.append(ScoreContributor(
            source="Artifact",
            reason="Risk propagated from high-risk child artifact",
            points=final_score - parent_assessment.score
            if final_score > parent_assessment.score
            else 0,
        ))

        return parent_assessment
