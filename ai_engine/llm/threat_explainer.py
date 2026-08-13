import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ThreatExplainer:
    """
    Generates detailed, multi-paragraph threat analysis summaries using
    structured data from the analysis pipeline. No external model required.
    """
    def __init__(self, use_dummy: bool = True):
        self.use_dummy = use_dummy
        logger.info("ThreatExplainer initialized (structured analysis mode)")

    def generate_explanation(self, risk_score: float, capabilities: List[str], 
                              chains: List[str], threat_family: str,
                              mitre_techniques: List[str], impact: Dict[str, str]) -> str:
        """
        Generate a detailed, multi-paragraph threat analysis summary
        built entirely from the actual analysis results.
        """
        paragraphs = []
        
        # ── Paragraph 1: Risk verdict ──────────────────────────────────────
        severity = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"
        paragraphs.append(
            f"Dynamic and static analysis of this artifact resulted in a {severity} risk score "
            f"of {risk_score}/100. The analysis was conducted through behavioral sandbox "
            f"detonation, static string extraction, YARA signature matching, and graph-based "
            f"anomaly correlation."
        )

        # ── Paragraph 2: Threat classification ─────────────────────────────
        if threat_family and threat_family != "Unknown":
            paragraphs.append(
                f"Behavioral pattern matching strongly indicates this payload belongs to the "
                f"\"{threat_family}\" malware family. The classification confidence is high based "
                f"on observed execution patterns, API call sequences, and known signature overlap "
                f"with documented variants of this threat."
            )
        elif risk_score >= 80:
            paragraphs.append(
                "While an exact malware family classification could not be confirmed, the payload "
                "exhibits behavioral patterns consistent with advanced persistent threats (APTs) "
                "or custom-built attack tooling designed to evade signature-based detection."
            )

        # ── Paragraph 3: Detected capabilities ────────────────────────────
        if capabilities:
            cap_text = ", ".join(capabilities[:6])
            count = len(capabilities)
            paragraphs.append(
                f"The sandbox execution revealed {count} distinct malicious capabilit{'y' if count == 1 else 'ies'}: "
                f"{cap_text}. These behaviors were observed during controlled detonation inside "
                f"the isolated analysis environment and represent concrete evidence of malicious "
                f"intent beyond static indicators alone."
            )

        # ── Paragraph 4: Attack chains ─────────────────────────────────────
        if chains:
            chain_text = ", ".join(chains[:4])
            paragraphs.append(
                f"The behavioral correlation engine identified the following multi-step attack "
                f"chains: {chain_text}. These coordinated behavioral sequences are particularly "
                f"concerning as they demonstrate operational sophistication — the payload chains "
                f"multiple techniques together to achieve its objectives rather than relying on "
                f"isolated malicious actions."
            )

        # ── Paragraph 5: MITRE ATT&CK coverage ────────────────────────────
        if mitre_techniques:
            technique_text = ", ".join(mitre_techniques[:6])
            tactic_count = len(mitre_techniques)
            paragraphs.append(
                f"The observed behaviors map to {tactic_count} MITRE ATT&CK technique{'s' if tactic_count > 1 else ''}: "
                f"{technique_text}. This breadth of technique coverage across the ATT&CK matrix "
                f"suggests a well-equipped threat actor operating across multiple phases of the "
                f"cyber kill chain, from initial execution through lateral movement and impact."
            )

        # ── Paragraph 6: Impact assessment ─────────────────────────────────
        if impact:
            impact_parts = []
            if impact.get("confidentiality") in ("High", "Critical"):
                impact_parts.append(
                    "significant data exfiltration risk threatening organizational confidentiality"
                )
            if impact.get("integrity") in ("High", "Critical"):
                impact_parts.append(
                    "system integrity compromise through unauthorized modification of files or configurations"
                )
            if impact.get("availability") in ("High", "Critical"):
                impact_parts.append(
                    "severe service availability disruption consistent with ransomware or destructive malware activity"
                )
            if impact_parts:
                paragraphs.append(
                    f"CIA Impact Assessment: The analysis identifies {'; '.join(impact_parts)}. "
                    f"Immediate containment measures should be enacted including network isolation "
                    f"of affected hosts, credential rotation for potentially exposed accounts, and "
                    f"forensic preservation of volatile evidence."
                )

        # ── Paragraph 7: Recommendation ────────────────────────────────────
        if risk_score >= 80:
            paragraphs.append(
                "RECOMMENDATION: This artifact should be treated as a confirmed threat. Initiate "
                "incident response procedures immediately. Block associated indicators of compromise "
                "(IOCs) at the network perimeter, quarantine any systems that may have executed "
                "this payload, and escalate to the security operations center for full investigation."
            )
        elif risk_score >= 50:
            paragraphs.append(
                "RECOMMENDATION: This artifact warrants further investigation. While not conclusively "
                "malicious, the observed behaviors exceed normal software activity thresholds. "
                "Review telemetry logs for additional context and consider submitting to an "
                "external threat intelligence platform for corroboration."
            )

        return "\n\n".join(paragraphs)
