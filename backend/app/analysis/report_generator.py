from app.analysis.models import (
    Capability, BehaviorChain, ThreatClassification, 
    ImpactAssessment, RiskAssessment, AnalystReport
)

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
        
        # Build Executive Summary
        summary = f"Analysis resulted in a {risk.severity} risk score of {risk.score}/100. "
        if threat.family != "Unknown":
            summary += f"The payload exhibits strong indicators of being a {threat.family}. "
        elif risk.score > 60:
            summary += "The payload exhibits highly suspicious behavior patterns. "
        else:
            summary += "No distinctly malicious behavior was confirmed. "

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
