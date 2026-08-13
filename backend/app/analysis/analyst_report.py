import logging
from app.analysis.models import (
    Capability, BehaviorChain, ThreatClassification, 
    ImpactAssessment, RiskAssessment, AnalystReport
)

logger = logging.getLogger(__name__)

# ── Lazy-loaded singleton for the ThreatExplainer ──────────────────────────
_explainer = None

def _get_explainer():
    """Lazily initialize the ThreatExplainer so the model is only loaded once."""
    global _explainer
    if _explainer is None:
        try:
            from ai_engine.llm.threat_explainer import ThreatExplainer
            _explainer = ThreatExplainer(use_dummy=False)
            logger.info("ThreatExplainer loaded with Transformers LLM (flan-t5-base)")
        except Exception as e:
            logger.warning(f"Failed to load ThreatExplainer LLM, falling back to rule-based: {e}")
            _explainer = None
    return _explainer


class AnalystReportGenerator:
    @staticmethod
    def generate(
        capabilities: list[Capability],
        chains: list[BehaviorChain],
        threat: ThreatClassification,
        mitre: list[str],
        impact: ImpactAssessment,
        risk: RiskAssessment
    ) -> AnalystReport:
        
        # ── Try LLM-powered detailed summary ──────────────────────────────
        summary = None
        explainer = _get_explainer()
        if explainer:
            try:
                cap_names = [cap.capability for cap in capabilities]
                chain_names = [chain.chain_name for chain in chains]
                impact_dict = {
                    "confidentiality": impact.confidentiality,
                    "integrity": impact.integrity,
                    "availability": impact.availability
                }
                
                summary = explainer.generate_explanation(
                    risk_score=risk.score,
                    capabilities=cap_names,
                    chains=chain_names,
                    threat_family=threat.family,
                    mitre_techniques=mitre,
                    impact=impact_dict
                )
                logger.info("Detailed AI Threat Summary generated successfully")
            except Exception as e:
                logger.warning(f"LLM summary generation failed, falling back to rule-based: {e}")
                summary = None

        # ── Fallback to detailed rule-based summary ────────────────────────
        if not summary:
            parts = []
            
            # Verdict
            parts.append(
                f"Dynamic and static analysis of this artifact resulted in a {risk.severity} "
                f"risk score of {risk.score}/100."
            )
            
            # Threat family
            if threat.family != "Unknown":
                parts.append(
                    f"Behavioral pattern matching strongly indicates this payload belongs to the "
                    f"\"{threat.family}\" malware family."
                )
            elif risk.score > 60:
                parts.append(
                    "The payload exhibits highly suspicious behavior patterns consistent with "
                    "known malware families, though an exact classification could not be confirmed."
                )
            else:
                parts.append("No distinctly malicious behavior was confirmed during analysis.")

            # Capabilities
            if capabilities:
                cap_text = ", ".join([c.capability for c in capabilities[:5]])
                parts.append(f"Detected capabilities include: {cap_text}.")
            
            # Chains
            if chains:
                chain_text = ", ".join([c.chain_name for c in chains[:3]])
                parts.append(f"Correlated attack chains identified: {chain_text}.")
            
            # MITRE
            if mitre:
                parts.append(f"Mapped MITRE ATT&CK techniques: {', '.join(mitre[:5])}.")
            
            # Impact
            impact_issues = []
            if impact.availability in ("High", "Critical"):
                impact_issues.append("service availability disruption")
            if impact.confidentiality in ("High", "Critical"):
                impact_issues.append("data exfiltration risk")
            if impact.integrity in ("High", "Critical"):
                impact_issues.append("system integrity compromise")
            if impact_issues:
                parts.append(
                    f"Impact assessment indicates: {'; '.join(impact_issues)}. "
                    f"Immediate containment is recommended."
                )
            
            summary = " ".join(parts)

        # Technical Findings
        findings = []
        for c in chains:
            findings.append(f"Identified {c.chain_name}: {', '.join(c.evidence[:2])}")
        for cap in capabilities:
            findings.append(f"Capability '{cap.capability}': {cap.evidence[0]}")

        # Recommendations
        actions = []
        if impact.availability == "Critical":
            actions.append("Isolate infected hosts immediately to prevent ransomware spread.")
        if impact.confidentiality in ("High", "Critical"):
            actions.append("Rotate potentially exposed credentials and tokens.")
        if not actions:
            if risk.score > 50:
                actions.append("Review telemetry logs for anomalous activity.")
            else:
                actions.append("No immediate action required.")

        return AnalystReport(
            executive_summary=summary,
            technical_findings=list(set(findings)),
            threat_classification=threat,
            mitre_coverage=mitre,
            impact_assessment=impact,
            recommended_actions=actions,
            risk_assessment=risk
        )
