"""
Summary Generator — Concise Threat Analysis Summaries

Generates one-liner and multi-line summaries of analysis results
for use in dashboard cards, notification previews, and API responses.
No external model required — uses structured data interpolation.
"""

import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("summary_generator")


class SummaryGenerator:
    """
    Produces concise threat analysis summaries from pipeline results.
    Designed for dashboard cards, notification previews, and quick-glance views.
    """

    def __init__(self):
        logger.info("SummaryGenerator initialized (rule-based mode)")

    def generate_one_liner(
        self,
        risk_score: float,
        threat_family: str = "Unknown",
        capabilities: Optional[List[str]] = None,
        mitre_count: int = 0,
    ) -> str:
        """
        Generate a single-line summary for dashboard cards and notifications.

        Example outputs:
            "CRITICAL (92/100): Emotet variant — data exfiltration, C2 communication, persistence"
            "LOW (12/100): No malicious behavior detected"
        """
        severity = self._severity_label(risk_score)
        parts = [f"{severity} ({risk_score:.0f}/100)"]

        if threat_family and threat_family != "Unknown":
            parts.append(f"{threat_family} variant")

        if capabilities:
            cap_text = ", ".join(capabilities[:3])
            parts.append(cap_text)
        elif risk_score < 20:
            parts.append("No malicious behavior detected")

        if mitre_count > 0:
            parts.append(f"{mitre_count} ATT&CK techniques")

        return " — ".join(parts)

    def generate_detailed(
        self,
        risk_score: float,
        threat_family: str = "Unknown",
        capabilities: Optional[List[str]] = None,
        chains: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        ioc_count: int = 0,
        telemetry_count: int = 0,
        impact: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Generate a multi-line summary (3-5 lines) for expanded views.

        Returns:
            Multi-line summary string suitable for tooltips or expanded cards.
        """
        capabilities = capabilities or []
        chains = chains or []
        mitre_techniques = mitre_techniques or []
        impact = impact or {}

        severity = self._severity_label(risk_score)
        lines = []

        # Line 1: Verdict
        if threat_family and threat_family != "Unknown":
            lines.append(
                f"Risk: {severity} ({risk_score:.0f}/100) — "
                f"classified as {threat_family}"
            )
        else:
            lines.append(f"Risk: {severity} ({risk_score:.0f}/100)")

        # Line 2: Capabilities
        if capabilities:
            cap_text = ", ".join(capabilities[:5])
            lines.append(f"Capabilities: {cap_text}")

        # Line 3: Attack chains
        if chains:
            chain_text = ", ".join(chains[:3])
            lines.append(f"Attack chains: {chain_text}")

        # Line 4: Coverage stats
        stats = []
        if mitre_techniques:
            stats.append(f"{len(mitre_techniques)} MITRE techniques")
        if ioc_count > 0:
            stats.append(f"{ioc_count} IOCs")
        if telemetry_count > 0:
            stats.append(f"{telemetry_count} telemetry events")
        if stats:
            lines.append(f"Coverage: {', '.join(stats)}")

        # Line 5: Impact
        high_impacts = [
            dim for dim in ("confidentiality", "integrity", "availability")
            if impact.get(dim) in ("High", "Critical")
        ]
        if high_impacts:
            lines.append(f"Impact: {', '.join(dim.title() for dim in high_impacts)} at risk")

        return "\n".join(lines)

    def generate_notification(
        self,
        job_id: str,
        filename: str,
        risk_score: float,
        threat_family: str = "Unknown",
    ) -> Dict[str, str]:
        """
        Generate a notification payload (title + body) for alerting systems.

        Returns:
            Dict with 'title' and 'body' keys.
        """
        severity = self._severity_label(risk_score)

        title = f"[{severity}] ACROS Alert: {filename}"

        if risk_score >= 80:
            body = (
                f"⚠️ Critical threat detected in {filename}. "
                f"Risk score: {risk_score:.0f}/100."
            )
            if threat_family != "Unknown":
                body += f" Classified as {threat_family}."
            body += " Immediate action required."
        elif risk_score >= 50:
            body = (
                f"Suspicious activity detected in {filename}. "
                f"Risk score: {risk_score:.0f}/100. Investigation recommended."
            )
        else:
            body = (
                f"Analysis of {filename} complete. "
                f"Risk score: {risk_score:.0f}/100. No immediate action required."
            )

        return {
            "title": title,
            "body": body,
            "job_id": job_id,
            "severity": severity,
            "risk_score": risk_score,
        }

    @staticmethod
    def _severity_label(score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "INFO"
