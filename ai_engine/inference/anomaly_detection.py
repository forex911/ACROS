"""
Anomaly Detection Engine — Statistical Behavioral Analysis

Detects anomalies in sandbox telemetry by analyzing event frequency,
timing patterns, and behavioral sequences using z-score analysis.
No heavy ML dependencies — uses numpy for statistical computation.
"""

import logging
import math
from typing import List, Dict, Any, Optional

logger = logging.getLogger("anomaly_detection")

# ── Default behavioral baselines (auto-calibrated per run) ──────────────────
DEFAULT_THRESHOLDS = {
    "process_create_rate": {"mean": 3.0, "std": 2.0},
    "network_connect_rate": {"mean": 2.0, "std": 1.5},
    "file_write_rate": {"mean": 5.0, "std": 3.0},
    "dns_query_rate": {"mean": 2.0, "std": 1.5},
    "registry_modify_rate": {"mean": 1.0, "std": 1.0},
    "execution_rate": {"mean": 2.0, "std": 1.5},
    "memory_injection_rate": {"mean": 0.1, "std": 0.3},
}

# Events that carry elevated suspicion by default
HIGH_SUSPICION_EVENTS = {
    "MEMORY_INJECTION", "PERSISTENCE_EVENT", "REGISTRY_MODIFY",
    "EXECUTION_TIMEOUT", "HIDDEN_FILE_CREATED", "SUSPICIOUS_PROCESS",
}


class AnomalyDetector:
    """
    Statistical anomaly detector for sandbox telemetry streams.
    Uses z-score analysis against behavioral baselines to flag outliers.
    """

    def __init__(self, thresholds: Optional[Dict] = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        logger.info("AnomalyDetector initialized with %d baseline features", len(self.thresholds))

    def _extract_event_counts(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count events by category for frequency analysis."""
        counts = {
            "process_create_rate": 0,
            "network_connect_rate": 0,
            "file_write_rate": 0,
            "dns_query_rate": 0,
            "registry_modify_rate": 0,
            "execution_rate": 0,
            "memory_injection_rate": 0,
        }

        type_mapping = {
            "PROCESS_CREATE": "process_create_rate",
            "SOCKET_CONNECT": "network_connect_rate",
            "NETWORK_CONNECT": "network_connect_rate",
            "FILE_WRITE": "file_write_rate",
            "FILE_CREATE": "file_write_rate",
            "DNS_QUERY": "dns_query_rate",
            "REGISTRY_MODIFY": "registry_modify_rate",
            "REGISTRY_CREATE": "registry_modify_rate",
            "EXECUTION": "execution_rate",
            "MEMORY_INJECTION": "memory_injection_rate",
            "PERSISTENCE_EVENT": "registry_modify_rate",
        }

        for event in events:
            evt_type = event.get("type", "")
            feature_key = type_mapping.get(evt_type)
            if feature_key:
                counts[feature_key] += 1

        return counts

    def _compute_zscore(self, value: float, mean: float, std: float) -> float:
        """Compute z-score; returns 0 if std is 0."""
        if std == 0:
            return 0.0 if value == mean else 5.0
        return (value - mean) / std

    def _detect_timing_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect burst activity — many events in a very short time window."""
        anomalies = []
        if len(events) < 3:
            return anomalies

        # Sort by timestamp if present
        timestamps = []
        for evt in events:
            ts = evt.get("timestamp", "")
            if ts:
                timestamps.append(ts)

        if len(timestamps) < 3:
            return anomalies

        # Detect bursts: >10 events in <1 second window
        sorted_ts = sorted(timestamps)
        window_size = 10
        for i in range(len(sorted_ts) - window_size):
            start = sorted_ts[i]
            end = sorted_ts[i + window_size]
            if start and end and start[:19] == end[:19]:  # Same second
                anomalies.append({
                    "anomaly_type": "BURST_ACTIVITY",
                    "description": f"Detected {window_size}+ events within 1 second",
                    "score": 0.7,
                    "evidence": f"Events {i} to {i + window_size} clustered at {start[:19]}",
                })
                break  # Only report once

        return anomalies

    def detect_anomalies(self, telemetry_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze telemetry events for anomalous behavior patterns.

        Returns:
            List of anomaly dicts with keys: anomaly_type, description, score (0-1), evidence
        """
        anomalies = []

        if not telemetry_events:
            return anomalies

        # ── 1. Frequency-based anomaly detection (z-scores) ──────────────
        event_counts = self._extract_event_counts(telemetry_events)

        for feature_key, count in event_counts.items():
            baseline = self.thresholds.get(feature_key)
            if not baseline:
                continue

            z = self._compute_zscore(count, baseline["mean"], baseline["std"])

            if z > 2.0:
                severity = min(z / 5.0, 1.0)  # Normalize to 0-1
                anomalies.append({
                    "anomaly_type": "FREQUENCY_ANOMALY",
                    "description": (
                        f"Abnormal {feature_key.replace('_rate', '')} frequency: "
                        f"{count} events (z-score: {z:.2f})"
                    ),
                    "score": round(severity, 3),
                    "evidence": f"{feature_key}={count}, baseline={baseline['mean']}±{baseline['std']}",
                    "feature": feature_key,
                    "z_score": round(z, 3),
                })

        # ── 2. High-suspicion event detection ────────────────────────────
        for event in telemetry_events:
            evt_type = event.get("type", "")
            if evt_type in HIGH_SUSPICION_EVENTS:
                anomalies.append({
                    "anomaly_type": "HIGH_SUSPICION_EVENT",
                    "description": f"High-suspicion event detected: {evt_type}",
                    "score": 0.8,
                    "evidence": str(event.get("data", {}))[:200],
                })

        # ── 3. Timing anomalies (burst detection) ───────────────────────
        timing_anomalies = self._detect_timing_anomalies(telemetry_events)
        anomalies.extend(timing_anomalies)

        # ── 4. Behavioral sequence anomalies ─────────────────────────────
        event_sequence = [e.get("type", "") for e in telemetry_events]

        # Detect process creation followed immediately by network activity
        for i in range(len(event_sequence) - 1):
            if event_sequence[i] == "PROCESS_CREATE" and event_sequence[i + 1] in (
                "SOCKET_CONNECT", "NETWORK_CONNECT", "DNS_QUERY"
            ):
                anomalies.append({
                    "anomaly_type": "SEQUENCE_ANOMALY",
                    "description": "Process creation immediately followed by network activity",
                    "score": 0.6,
                    "evidence": f"{event_sequence[i]} → {event_sequence[i + 1]}",
                })
                break  # Report once

        # Deduplicate by type + description
        seen = set()
        unique_anomalies = []
        for a in anomalies:
            key = (a["anomaly_type"], a.get("feature", ""), a["description"][:80])
            if key not in seen:
                seen.add(key)
                unique_anomalies.append(a)

        logger.info("Detected %d anomalies from %d telemetry events", len(unique_anomalies), len(telemetry_events))
        return unique_anomalies

    def get_anomaly_score(self, telemetry_events: List[Dict[str, Any]]) -> float:
        """
        Returns an aggregate anomaly score (0-100) for the entire telemetry stream.
        """
        anomalies = self.detect_anomalies(telemetry_events)
        if not anomalies:
            return 0.0

        # Weighted average of individual anomaly scores
        total_score = sum(a["score"] for a in anomalies)
        # Cap and scale to 0-100
        return min(round(total_score * 15, 1), 100.0)
