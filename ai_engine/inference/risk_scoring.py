"""
AI Engine Risk Scorer — Multi-Signal Weighted Risk Assessment

Computes a composite risk score from multiple analysis signals:
static analysis, telemetry behavior, IOCs, MITRE mappings, and anomaly scores.
Complementary to the backend's RiskEngineV3 — this is the AI-engine-side scorer
for use in standalone or batch analysis modes.
"""

import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("risk_scoring")

# ── Signal weights (must sum to 1.0) ────────────────────────────────────────
SIGNAL_WEIGHTS = {
    "static_indicators": 0.15,
    "behavioral_telemetry": 0.30,
    "ioc_severity": 0.20,
    "mitre_coverage": 0.15,
    "anomaly_score": 0.10,
    "yara_matches": 0.10,
}

# ── IOC severity scores ─────────────────────────────────────────────────────
IOC_SEVERITY_MAP = {
    "c2_server": 90,
    "malware_hash": 95,
    "phishing_domain": 75,
    "suspicious_ip": 60,
    "tor_exit_node": 70,
    "crypto_wallet": 65,
    "url": 40,
    "domain": 35,
    "ip": 30,
    "email": 20,
}

# ── Telemetry event severity scores ──────────────────────────────────────────
EVENT_SEVERITY = {
    "MEMORY_INJECTION": 95,
    "PERSISTENCE_EVENT": 90,
    "EXECUTION_TIMEOUT": 70,
    "PROCESS_CREATE": 40,
    "SOCKET_CONNECT": 50,
    "NETWORK_CONNECT": 50,
    "DNS_QUERY": 30,
    "FILE_WRITE": 35,
    "FILE_CREATE": 30,
    "FILE_DROP_DETECTED": 75,
    "REGISTRY_MODIFY": 65,
    "REGISTRY_CREATE": 55,
    "HIDDEN_FILE_CREATED": 70,
    "SUSPICIOUS_PROCESS": 80,
    "HTTP_REQUEST": 45,
    "EXECUTION": 50,
    "EXECUTION_ERROR": 25,
    "EXECUTION_OUTPUT": 10,
    "STATUS_CHANGE": 5,
}


class RiskScorer:
    """
    Computes a composite risk score (0-100) from multiple signal sources.

    Designed for use in the AI engine's standalone analysis mode or
    batch processing pipelines where the backend's RiskEngineV3 is not available.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or SIGNAL_WEIGHTS
        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}
        logger.info("RiskScorer initialized with %d signal weights", len(self.weights))

    def _score_static_indicators(self, static_results: Dict[str, Any]) -> float:
        """Score based on static analysis findings."""
        score = 0.0

        strings = static_results.get("strings", {})
        ips = strings.get("ips", [])
        urls = strings.get("urls", [])
        domains = strings.get("domains", [])

        # Suspicious string indicators
        if ips:
            score += min(len(ips) * 10, 40)
        if urls:
            score += min(len(urls) * 8, 35)
        if domains:
            score += min(len(domains) * 5, 25)

        # Python-specific indicators
        python_analysis = static_results.get("python", {})
        if python_analysis:
            suspicious_imports = python_analysis.get("suspicious_imports", [])
            score += min(len(suspicious_imports) * 12, 50)
            dangerous_calls = python_analysis.get("dangerous_calls", [])
            score += min(len(dangerous_calls) * 15, 50)

        # PE-specific indicators
        pe_analysis = static_results.get("pe", {})
        if pe_analysis:
            if pe_analysis.get("is_packed"):
                score += 30
            suspicious_sections = pe_analysis.get("suspicious_sections", [])
            score += min(len(suspicious_sections) * 15, 40)

        return min(score, 100.0)

    def _score_behavioral_telemetry(self, telemetry_events: List[Dict[str, Any]]) -> float:
        """Score based on runtime behavioral telemetry."""
        if not telemetry_events:
            return 0.0

        total_severity = 0.0
        event_count = 0

        for event in telemetry_events:
            evt_type = event.get("type", "")
            severity = EVENT_SEVERITY.get(evt_type, 10)
            total_severity += severity
            event_count += 1

        if event_count == 0:
            return 0.0

        # Average severity weighted by event count (more events = higher risk)
        avg_severity = total_severity / event_count
        count_bonus = min(event_count * 2, 30)  # Up to 30 bonus for high event count

        return min(avg_severity + count_bonus, 100.0)

    def _score_iocs(self, iocs: List[Dict[str, Any]]) -> float:
        """Score based on extracted IOCs and their severity."""
        if not iocs:
            return 0.0

        max_severity = 0
        total_severity = 0

        for ioc in iocs:
            ioc_type = ioc.get("type", "").lower()
            severity = IOC_SEVERITY_MAP.get(ioc_type, 20)
            max_severity = max(max_severity, severity)
            total_severity += severity

        # Blend of max severity and average severity
        avg_severity = total_severity / len(iocs) if iocs else 0
        return min((max_severity * 0.6 + avg_severity * 0.4), 100.0)

    def _score_mitre_coverage(self, mitre_mappings: List[Dict[str, Any]]) -> float:
        """Score based on breadth of MITRE ATT&CK technique coverage."""
        if not mitre_mappings:
            return 0.0

        # Unique tactics indicate sophistication
        tactics = set()
        for mapping in mitre_mappings:
            tactic = mapping.get("tactic", mapping.get("evidence", ""))
            if tactic:
                tactics.add(tactic)

        technique_count = len(mitre_mappings)
        tactic_count = len(tactics)

        # Score: each technique adds 10, each unique tactic adds 15
        score = (technique_count * 10) + (tactic_count * 15)
        return min(score, 100.0)

    def _score_yara_matches(self, yara_matches: List[Any]) -> float:
        """Score based on YARA rule matches."""
        if not yara_matches:
            return 0.0

        # Each YARA match is significant
        return min(len(yara_matches) * 25, 100.0)

    def calculate_risk(
        self,
        static_results: Dict[str, Any],
        telemetry_events: List[Dict[str, Any]],
        iocs: Optional[List[Dict[str, Any]]] = None,
        mitre_mappings: Optional[List[Dict[str, Any]]] = None,
        anomaly_score: float = 0.0,
        yara_matches: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate composite risk score from all available signals.

        Returns:
            Dict with: score (0-100), confidence (0-1), severity, contributing_factors
        """
        iocs = iocs or []
        mitre_mappings = mitre_mappings or []
        yara_matches = yara_matches or []

        # ── Score each signal ────────────────────────────────────────────
        scores = {
            "static_indicators": self._score_static_indicators(static_results),
            "behavioral_telemetry": self._score_behavioral_telemetry(telemetry_events),
            "ioc_severity": self._score_iocs(iocs),
            "mitre_coverage": self._score_mitre_coverage(mitre_mappings),
            "anomaly_score": min(anomaly_score, 100.0),
            "yara_matches": self._score_yara_matches(yara_matches),
        }

        # ── Compute weighted composite ──────────────────────────────────
        composite = sum(
            scores[signal] * self.weights.get(signal, 0)
            for signal in scores
        )
        composite = round(min(composite, 100.0), 1)

        # ── Confidence: based on how many signals contributed ───────────
        active_signals = sum(1 for s in scores.values() if s > 0)
        confidence = round(active_signals / len(scores), 2)

        # ── Severity label ──────────────────────────────────────────────
        if composite >= 80:
            severity = "CRITICAL"
        elif composite >= 60:
            severity = "HIGH"
        elif composite >= 40:
            severity = "MEDIUM"
        elif composite >= 20:
            severity = "LOW"
        else:
            severity = "INFO"

        # ── Contributing factors (sorted by impact) ─────────────────────
        contributing_factors = sorted(
            [
                {
                    "signal": signal,
                    "raw_score": round(score, 1),
                    "weight": round(self.weights.get(signal, 0), 3),
                    "weighted_contribution": round(score * self.weights.get(signal, 0), 1),
                }
                for signal, score in scores.items()
                if score > 0
            ],
            key=lambda x: x["weighted_contribution"],
            reverse=True,
        )

        result = {
            "score": composite,
            "severity": severity,
            "confidence": confidence,
            "contributing_factors": contributing_factors,
            "signal_scores": {k: round(v, 1) for k, v in scores.items()},
        }

        logger.info(
            "Risk assessment: score=%s, severity=%s, confidence=%s, signals=%d",
            composite, severity, confidence, active_signals
        )
        return result
