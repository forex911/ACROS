"""
Report Writer — Structured Markdown Threat Report Generator

Generates detailed, professional threat analysis reports in Markdown format
from pipeline analysis results. No external model required — uses template-based
generation with structured data interpolation.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("report_writer")


class ReportWriter:
    """
    Generates structured Markdown threat reports from analysis results.
    Follows the same initialization pattern as ThreatExplainer.
    """

    def __init__(self):
        logger.info("ReportWriter initialized (template-based generation)")

    def generate_report(
        self,
        job_id: str,
        filename: str,
        risk_score: float,
        severity: str,
        static_results: Dict[str, Any],
        capabilities: List[str],
        chains: List[str],
        threat_family: str,
        mitre_techniques: List[str],
        iocs: List[Dict[str, Any]],
        yara_matches: List[str],
        impact: Dict[str, str],
        telemetry_count: int = 0,
        ai_summary: str = "",
    ) -> str:
        """
        Generate a full Markdown threat report.

        Returns:
            Formatted Markdown string with all analysis sections.
        """
        sections = []

        # ── Header ──────────────────────────────────────────────────────
        sections.append(self._header(job_id, filename, risk_score, severity))

        # ── Executive Summary ───────────────────────────────────────────
        sections.append(self._executive_summary(ai_summary, risk_score, severity, threat_family))

        # ── File Metadata ───────────────────────────────────────────────
        sections.append(self._file_metadata(static_results, filename))

        # ── YARA Matches ────────────────────────────────────────────────
        if yara_matches:
            sections.append(self._yara_section(yara_matches))

        # ── Capabilities ────────────────────────────────────────────────
        if capabilities:
            sections.append(self._capabilities_section(capabilities))

        # ── Attack Chains ───────────────────────────────────────────────
        if chains:
            sections.append(self._chains_section(chains))

        # ── MITRE ATT&CK Matrix ─────────────────────────────────────────
        if mitre_techniques:
            sections.append(self._mitre_section(mitre_techniques))

        # ── IOC Table ───────────────────────────────────────────────────
        if iocs:
            sections.append(self._ioc_table(iocs))

        # ── Impact Assessment ───────────────────────────────────────────
        if impact:
            sections.append(self._impact_section(impact))

        # ── Recommendations ─────────────────────────────────────────────
        sections.append(self._recommendations(risk_score, severity, capabilities))

        # ── Footer ──────────────────────────────────────────────────────
        sections.append(self._footer(job_id, telemetry_count))

        report = "\n\n".join(sections)
        logger.info("Generated threat report for job %s (%d chars)", job_id, len(report))
        return report

    def _header(self, job_id: str, filename: str, risk_score: float, severity: str) -> str:
        severity_emoji = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"
        }.get(severity, "⚪")

        return (
            f"# {severity_emoji} ACROS Threat Analysis Report\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **Job ID** | `{job_id}` |\n"
            f"| **Filename** | `{filename}` |\n"
            f"| **Risk Score** | **{risk_score}/100** |\n"
            f"| **Severity** | **{severity}** |\n"
            f"| **Generated** | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |"
        )

    def _executive_summary(self, ai_summary: str, risk_score: float, severity: str, threat_family: str) -> str:
        lines = ["## Executive Summary"]
        if ai_summary:
            lines.append(ai_summary)
        else:
            lines.append(
                f"Analysis of this artifact resulted in a **{severity}** risk score of "
                f"**{risk_score}/100**."
            )
            if threat_family and threat_family != "Unknown":
                lines.append(
                    f"The payload has been classified as belonging to the **{threat_family}** malware family."
                )
        return "\n\n".join(lines)

    def _file_metadata(self, static_results: Dict[str, Any], filename: str) -> str:
        hash_info = static_results.get("hash", {})
        lines = [
            "## File Metadata\n",
            "| Hash Type | Value |",
            "|-----------|-------|",
        ]
        for algo in ("md5", "sha1", "sha256"):
            value = hash_info.get(algo, "N/A")
            lines.append(f"| **{algo.upper()}** | `{value}` |")

        file_size = hash_info.get("file_size", "N/A")
        lines.append(f"| **File Size** | {file_size} bytes |")
        lines.append(f"| **File Name** | `{filename}` |")

        return "\n".join(lines)

    def _yara_section(self, yara_matches: List[str]) -> str:
        lines = ["## YARA Signature Matches\n"]
        for match in yara_matches:
            lines.append(f"- 🎯 `{match}`")
        return "\n".join(lines)

    def _capabilities_section(self, capabilities: List[str]) -> str:
        lines = ["## Detected Capabilities\n"]
        for cap in capabilities:
            lines.append(f"- ⚡ {cap}")
        return "\n".join(lines)

    def _chains_section(self, chains: List[str]) -> str:
        lines = ["## Attack Chains\n"]
        for i, chain in enumerate(chains, 1):
            lines.append(f"{i}. 🔗 **{chain}**")
        return "\n".join(lines)

    def _mitre_section(self, techniques: List[str]) -> str:
        lines = [
            "## MITRE ATT&CK Coverage\n",
            "| Technique | Status |",
            "|-----------|--------|",
        ]
        for tech in techniques:
            lines.append(f"| {tech} | ✅ Observed |")
        return "\n".join(lines)

    def _ioc_table(self, iocs: List[Dict[str, Any]]) -> str:
        lines = [
            "## Indicators of Compromise (IOCs)\n",
            "| Type | Value | Context |",
            "|------|-------|---------|",
        ]
        for ioc in iocs[:30]:  # Cap at 30 rows
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "N/A")
            context = ioc.get("context", ioc.get("source", ""))
            lines.append(f"| `{ioc_type}` | `{value}` | {context} |")
        if len(iocs) > 30:
            lines.append(f"\n*... and {len(iocs) - 30} additional IOCs*")
        return "\n".join(lines)

    def _impact_section(self, impact: Dict[str, str]) -> str:
        cia_emojis = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "None": "⚪"}
        lines = [
            "## CIA Impact Assessment\n",
            "| Dimension | Rating |",
            "|-----------|--------|",
        ]
        for dim in ("confidentiality", "integrity", "availability"):
            rating = impact.get(dim, "None")
            emoji = cia_emojis.get(rating, "⚪")
            lines.append(f"| **{dim.title()}** | {emoji} {rating} |")
        return "\n".join(lines)

    def _recommendations(self, risk_score: float, severity: str, capabilities: List[str]) -> str:
        lines = ["## Recommendations\n"]

        if risk_score >= 80:
            lines.extend([
                "1. 🚨 **Immediate Containment**: Isolate affected hosts from the network",
                "2. 🔑 **Credential Rotation**: Rotate all potentially exposed credentials",
                "3. 🔍 **Forensic Investigation**: Preserve volatile evidence and initiate IR",
                "4. 🛡️ **IOC Blocking**: Deploy extracted IOCs to perimeter defenses",
                "5. 📢 **Escalation**: Notify SOC and incident response team",
            ])
        elif risk_score >= 50:
            lines.extend([
                "1. 🔍 **Investigation**: Review telemetry logs for additional context",
                "2. 📊 **Monitoring**: Increase monitoring on affected systems",
                "3. 🧪 **Correlation**: Submit to external threat intelligence platforms",
                "4. 📋 **Documentation**: Document findings for threat hunting",
            ])
        else:
            lines.extend([
                "1. 📋 **Log Review**: Periodically review associated logs",
                "2. ✅ **No immediate action required**",
            ])

        return "\n".join(lines)

    def _footer(self, job_id: str, telemetry_count: int) -> str:
        return (
            "---\n\n"
            f"*Report generated by ACROS Threat Analysis Platform*\n"
            f"*Job ID: {job_id} | Telemetry Events Analyzed: {telemetry_count}*"
        )
