"""
Risk Engine v2 — Layered Scoring Architecture
==============================================
Replaces the original RiskEngine with a 6-layer scoring model plus
additive modifiers. Every point in the final score traces back to
specific evidence via both the reasoning list and the structured
contributors list.

Score Layers:
    1. Static Risk       (20%)  — PE analysis, strings, entropy
    2. Runtime Risk      (35%)  — Capabilities from telemetry  
    3. MITRE Risk        (20%)  — Severity-weighted ATT&CK techniques
    4. IOC Risk          (10%)  — Confidence-weighted IOC intelligence
    5. Behavior Risk     (10%)  — Behavior chain severity
    6. Threat Confidence  (5%)  — Threat family classification

Additive Modifiers:
    + YARA modifier   (0–50 points)
    + Graph bonus     (0–15 points)

Improvements (v2.1):
    - Cross-layer corroboration multiplier
    - Behavior chain minimum floor enforcement
    - Adaptive weights (PE vs script detection)
    - Runtime diminishing returns
    - Weighted confidence calculation
    - Evidence-breadth verdict logic
"""

from typing import List, Dict, Tuple
from app.analysis.models import (
    Capability, BehaviorChain, ThreatClassification,
    RiskAssessment, ScoreContributor,
)
from app.analysis.evidence_envelope import EvidenceEnvelope
from app.analysis.mitre_severity import score_mitre_techniques
from app.analysis.yara_scorer import score_yara_matches
from app.analysis.ioc_scorer import score_iocs


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

# Default layer weights (PE binary)
_PE_WEIGHTS = {
    "static": 0.20, "runtime": 0.35, "mitre": 0.20,
    "ioc": 0.10, "behavior": 0.10, "threat": 0.05,
}

# Script-adapted weights (Python, JS, BAT — no PE data)
_SCRIPT_WEIGHTS = {
    "static": 0.30, "runtime": 0.20, "mitre": 0.25,
    "ioc": 0.10, "behavior": 0.10, "threat": 0.05,
}

# Minimum floor scores enforced when a behavior chain of this severity
# is detected with confidence >= 80%
BEHAVIOR_FLOORS = {
    "Critical": 65,
    "High": 45,
    "Medium": 30,
}

# Cross-layer corroboration multiplier thresholds
_CORROBORATION = {
    5: 1.30,
    4: 1.25,
    3: 1.15,
    2: 1.05,
}


class RiskEngineV2:
    """
    Layered risk scoring engine. All inputs come via EvidenceEnvelope
    so no evidence source can be accidentally ignored.
    """

    @staticmethod
    def calculate_risk(envelope: EvidenceEnvelope) -> RiskAssessment:
        all_reasoning = []
        all_contributors: List[ScoreContributor] = []

        # ── Detect sample type and select weight profile ──
        is_script = _is_script_sample(envelope)
        weights = _SCRIPT_WEIGHTS if is_script else _PE_WEIGHTS

        if is_script:
            all_reasoning.append("Engine: Script-mode weights applied (no PE data)")

        # ── Layer 1: Static Risk ──
        static_score, static_reasons, static_contribs = _score_static(envelope)
        all_reasoning.extend(static_reasons)
        all_contributors.extend(static_contribs)

        # ── Layer 2: Runtime Risk (with diminishing returns) ──
        runtime_score, runtime_reasons, runtime_contribs = _score_runtime(envelope)
        all_reasoning.extend(runtime_reasons)
        all_contributors.extend(runtime_contribs)

        # ── Layer 3: MITRE Risk ──
        mitre_score, mitre_reasons = score_mitre_techniques(
            envelope.detections.mitre_techniques
        )
        all_reasoning.extend(mitre_reasons)
        # Build contributors from MITRE reasoning
        for tech in envelope.detections.mitre_techniques:
            tech_id = tech.get("id", "")
            tech_name = tech.get("name", tech_id)
            from app.analysis.mitre_severity import get_technique_severity
            severity = get_technique_severity(tech_id)
            all_contributors.append(ScoreContributor(
                source="MITRE",
                reason=f"{tech_id} {tech_name}",
                points=severity,
                technique=tech_id,
            ))

        # ── Layer 4: IOC Risk ──
        ioc_score, ioc_reasons = score_iocs(envelope.iocs.iocs)
        all_reasoning.extend(ioc_reasons)
        if ioc_score > 0:
            all_contributors.append(ScoreContributor(
                source="IOC",
                reason=f"{len(envelope.iocs.iocs)} IOCs extracted ({envelope.iocs.high_confidence_count} high confidence)",
                points=ioc_score,
            ))

        # ── Layer 5: Behavior Risk ──
        behavior_score, behavior_reasons, behavior_contribs = _score_behavior(envelope)
        all_reasoning.extend(behavior_reasons)
        all_contributors.extend(behavior_contribs)

        # ── Layer 6: Threat Confidence ──
        threat_score, threat_reasons, threat_contribs = _score_threat(envelope)
        all_reasoning.extend(threat_reasons)
        all_contributors.extend(threat_contribs)

        # ── Weighted Base Score ──
        layer_scores = {
            "static": static_score,
            "runtime": runtime_score,
            "mitre": mitre_score,
            "ioc": ioc_score,
            "behavior": behavior_score,
            "threat": threat_score,
        }

        base_score = sum(layer_scores[k] * weights[k] for k in weights)

        # ── Cross-Layer Corroboration Multiplier ──
        layers_active = sum(1 for v in layer_scores.values() if v > 0)
        multiplier = 1.0
        for threshold, mult in sorted(_CORROBORATION.items(), reverse=True):
            if layers_active >= threshold:
                multiplier = mult
                break

        if multiplier > 1.0:
            old_base = base_score
            base_score *= multiplier
            all_reasoning.append(
                f"Corroboration: {layers_active}/6 layers active → ×{multiplier:.2f} "
                f"({old_base:.1f} → {base_score:.1f})"
            )
            all_contributors.append(ScoreContributor(
                source="Corroboration",
                reason=f"{layers_active}/6 evidence layers corroborate",
                points=int(base_score - old_base),
            ))

        # ── Additive Modifiers ──
        yara_mod, yara_reasons = score_yara_matches(
            envelope.detections.yara_matches
        )
        all_reasoning.extend(yara_reasons)
        if yara_mod > 0:
            all_contributors.append(ScoreContributor(
                source="YARA",
                reason=yara_reasons[0] if yara_reasons else "YARA match",
                points=yara_mod,
            ))

        graph_mod = 0
        graph_reasons = []
        if envelope.graph_chain_length >= 3:
            if envelope.graph_chain_length >= 5:
                graph_mod += 12
                graph_reasons.append(f"Graph: chain length {envelope.graph_chain_length} → +12")
            elif envelope.graph_chain_length >= 4:
                graph_mod += 8
                graph_reasons.append(f"Graph: chain length {envelope.graph_chain_length} → +8")
            else:
                graph_mod += 5
                graph_reasons.append(f"Graph: chain length {envelope.graph_chain_length} → +5")

        if envelope.graph_has_c2_persistence:
            graph_mod += 15
            graph_reasons.append("Graph: C2 + Persistence co-occurrence → +15")
        all_reasoning.extend(graph_reasons)
        if graph_mod > 0:
            all_contributors.append(ScoreContributor(
                source="Graph",
                reason="; ".join(graph_reasons),
                points=graph_mod,
            ))

        # ── Final Score (before floor) ──
        final_score = int(base_score + yara_mod + graph_mod)

        # ── Behavior Chain Floor Enforcement ──
        floor = _get_behavior_floor(envelope)
        if floor > 0 and final_score < floor:
            all_reasoning.append(
                f"Floor: Behavior chain enforces minimum score {floor} "
                f"(was {final_score})"
            )
            all_contributors.append(ScoreContributor(
                source="Floor",
                reason=f"Critical behavior chain enforces minimum {floor}",
                points=floor - final_score,
            ))
            final_score = floor

        final_score = max(0, min(100, final_score))

        # ── Severity Band ──
        if final_score <= 25:
            severity = "LOW"
        elif final_score <= 50:
            severity = "MEDIUM"
        elif final_score <= 75:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # ── Confidence (weighted average) ──
        confidence = _calculate_confidence(envelope)

        # ── Verdict (evidence-breadth aware) ──
        threat = envelope.detections.threat_classification
        verdict = _determine_verdict(final_score, layers_active, threat)

        return RiskAssessment(
            score=final_score,
            severity=severity,
            confidence=confidence,
            verdict=verdict,
            score_breakdown={
                "static_risk": round(layer_scores["static"] * weights["static"], 2),
                "runtime_risk": round(layer_scores["runtime"] * weights["runtime"], 2),
                "mitre_risk": round(layer_scores["mitre"] * weights["mitre"], 2),
                "ioc_risk": round(layer_scores["ioc"] * weights["ioc"], 2),
                "behavior_risk": round(layer_scores["behavior"] * weights["behavior"], 2),
                "threat_confidence": round(layer_scores["threat"] * weights["threat"], 2),
            },
            modifiers={
                "yara_modifier": float(yara_mod),
                "graph_modifier": float(graph_mod),
                "corroboration_multiplier": float(multiplier),
            },
            reasoning=list(dict.fromkeys(all_reasoning)),  # deduplicate preserving order
            contributors=all_contributors,
        )

    @staticmethod
    def propagate_artifact_risk(parent_assessment: RiskAssessment, max_child_score: int) -> RiskAssessment:
        """
        Elevate parent risk score if a child artifact has a higher risk score.
        Uses a 90% propagation factor.
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
            f"Risk elevated to {severity} ({final_score}) due to high-risk child artifacts."
        )
        parent_assessment.contributors.append(ScoreContributor(
            source="Artifact",
            reason="Risk propagated from high-risk child artifact",
            points=final_score - parent_assessment.score if final_score > parent_assessment.score else 0,
        ))

        return parent_assessment


# ═══════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════

def _is_script_sample(envelope: EvidenceEnvelope) -> bool:
    """Detect whether the sample is a script (no PE data) vs a PE binary."""
    s = envelope.static
    return (
        not s.pe_imports
        and not s.is_packed
        and s.max_section_entropy == 0.0
        and not s.sections
    )


def _get_behavior_floor(envelope: EvidenceEnvelope) -> int:
    """Return the highest applicable behavior floor score."""
    floor = 0
    for chain in envelope.behavior_chains:
        if chain.confidence >= 80:
            chain_floor = BEHAVIOR_FLOORS.get(chain.severity, 0)
            floor = max(floor, chain_floor)
    return floor


def _calculate_confidence(envelope: EvidenceEnvelope) -> int:
    """Weighted average confidence across all evidence sources."""
    signals: List[Tuple[int, float]] = []

    threat = envelope.detections.threat_classification
    if threat and threat.family != "Unknown":
        signals.append((threat.confidence, 3.0))

    for chain in envelope.behavior_chains:
        signals.append((chain.confidence, 2.0))

    for cap in envelope.capabilities:
        if cap.severity in ("Critical", "High"):
            signals.append((cap.confidence, 1.0))

    if not signals:
        return 0

    weighted_sum = sum(c * w for c, w in signals)
    weight_total = sum(w for _, w in signals)
    return int(weighted_sum / weight_total) if weight_total > 0 else 0


def _determine_verdict(score: int, layers_active: int, threat) -> str:
    """Evidence-breadth-aware verdict determination."""
    family = threat.family if threat and threat.family != "Unknown" else None

    # Confirmed malicious: high breadth + high score
    if layers_active >= 4 and score > 50:
        return f"Confirmed {family}" if family else "Confirmed Malicious"

    # Named threat
    if family:
        return family

    # Highly suspicious: moderate breadth + moderate score
    if layers_active >= 3 and score > 40:
        return "Highly Suspicious"

    # Standard thresholds
    if score > 50:
        return "Suspicious"
    elif score > 25:
        return "Low Confidence Suspicious"
    else:
        return "Benign"


# ═══════════════════════════════════════════════════════════════════════
# Layer Scoring Functions
# ═══════════════════════════════════════════════════════════════════════

def _score_static(envelope: EvidenceEnvelope) -> Tuple[int, List[str], List[ScoreContributor]]:
    """Layer 1: Static analysis risk (0–100)."""
    score = 0
    reasoning = []
    contributors = []
    s = envelope.static

    # PE Packing
    if s.is_packed:
        score += 30
        reasoning.append("Static: PE is packed (high entropy/UPX) → +30")
        contributors.append(ScoreContributor(source="Static", reason="PE is packed (high entropy/UPX)", points=30))

    # Suspicious APIs
    if s.suspicious_apis:
        api_score = min(40, len(s.suspicious_apis) * 8)
        score += api_score
        reasoning.append(f"Static: {len(s.suspicious_apis)} suspicious APIs → +{api_score}")
        contributors.append(ScoreContributor(source="Static", reason=f"{len(s.suspicious_apis)} suspicious APIs detected", points=api_score))

    # High entropy sections (even if not flagged as packed)
    if s.max_section_entropy > 7.0 and not s.is_packed:
        score += 15
        reasoning.append(f"Static: High section entropy ({s.max_section_entropy:.1f}) → +15")
        contributors.append(ScoreContributor(source="Static", reason=f"High section entropy ({s.max_section_entropy:.1f})", points=15))

    # String IOCs in binary
    string_ioc_count = (
        len(s.string_iocs.get("ips", [])) +
        len(s.string_iocs.get("urls", [])) +
        len(s.string_iocs.get("domains", []))
    )
    if string_ioc_count > 0:
        ioc_score = min(20, string_ioc_count * 5)
        score += ioc_score
        reasoning.append(f"Static: {string_ioc_count} IOCs in strings → +{ioc_score}")
        contributors.append(ScoreContributor(source="Static", reason=f"{string_ioc_count} IOCs found in binary strings", points=ioc_score))

    # Python static findings
    if s.python_findings:
        py_score = min(50, len(s.python_findings) * 12)
        score += py_score
        reasoning.append(f"Static: {len(s.python_findings)} Python findings → +{py_score}")
        contributors.append(ScoreContributor(source="Static", reason=f"{len(s.python_findings)} Python static analysis findings", points=py_score))

    return min(100, score), reasoning, contributors


def _score_runtime(envelope: EvidenceEnvelope) -> Tuple[int, List[str], List[ScoreContributor]]:
    """Layer 2: Runtime capability risk (0–100) with diminishing returns."""
    if not envelope.capabilities:
        return 0, [], []

    score = 0
    reasoning = []
    contributors = []

    severity_weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 10,
        "Low": 5,
    }

    # Sort capabilities by severity (highest first) to give full weight
    # to the most dangerous signals before diminishing returns kick in
    sorted_caps = sorted(
        envelope.capabilities,
        key=lambda c: severity_weights.get(c.severity, 5),
        reverse=True,
    )

    for i, cap in enumerate(sorted_caps):
        weight = severity_weights.get(cap.severity, 5)

        # Diminishing returns: first 3 at full, next 3 at 75%, rest at 50%
        if i < 3:
            effective_weight = weight
        elif i < 6:
            effective_weight = int(weight * 0.75)
        else:
            effective_weight = int(weight * 0.50)

        score += effective_weight
        reasoning.append(f"Runtime: {cap.capability} [{cap.severity}] → +{effective_weight}")
        contributors.append(ScoreContributor(
            source="Runtime",
            reason=f"{cap.capability} [{cap.severity}]",
            points=effective_weight,
        ))

    return min(100, score), reasoning, contributors


def _score_behavior(envelope: EvidenceEnvelope) -> Tuple[int, List[str], List[ScoreContributor]]:
    """Layer 5: Behavior chain risk (0–100)."""
    if not envelope.behavior_chains:
        return 0, [], []

    score = 0
    reasoning = []
    contributors = []

    severity_weights = {
        "Critical": 40,
        "High": 25,
        "Medium": 15,
    }

    for chain in envelope.behavior_chains:
        weight = severity_weights.get(chain.severity, 10)
        score += weight
        reasoning.append(f"Behavior: {chain.chain_name} [{chain.severity}] → +{weight}")
        contributors.append(ScoreContributor(
            source="Behavior",
            reason=f"{chain.chain_name} [{chain.severity}]",
            points=weight,
        ))

    return min(100, score), reasoning, contributors


def _score_threat(envelope: EvidenceEnvelope) -> Tuple[int, List[str], List[ScoreContributor]]:
    """Layer 6: Threat family classification confidence (0–100)."""
    threat = envelope.detections.threat_classification
    if not threat or threat.family == "Unknown":
        return 0, [], []

    # Confidence is already 0–100
    score = threat.confidence
    reasoning = [f"Threat: Classified as {threat.family} (confidence {threat.confidence}%) → {score}"]
    contributors = [ScoreContributor(
        source="Threat",
        reason=f"Classified as {threat.family} (confidence {threat.confidence}%)",
        points=score,
    )]
    return score, reasoning, contributors
