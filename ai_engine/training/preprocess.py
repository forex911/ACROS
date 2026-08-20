"""
Telemetry Preprocessor — Feature Extraction for Training & Inference

Extracts numerical feature vectors from raw telemetry event streams
for use in both the training pipeline and the inference anomaly detector.
"""

import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("preprocess")

# ── Feature columns (order matters — must match model input) ────────────────
FEATURE_NAMES = [
    "total_events",
    "process_create_count",
    "network_connect_count",
    "dns_query_count",
    "file_write_count",
    "file_create_count",
    "registry_modify_count",
    "persistence_event_count",
    "memory_injection_count",
    "execution_count",
    "execution_error_count",
    "timeout_count",
    "unique_dest_ips",
    "unique_dest_ports",
    "unique_domains",
    "unique_file_paths",
    "high_severity_ratio",
    "event_type_diversity",
    "max_burst_size",
    "has_c2_pattern",
]

# Events that indicate high severity
HIGH_SEVERITY_TYPES = {
    "MEMORY_INJECTION", "PERSISTENCE_EVENT", "EXECUTION_TIMEOUT",
    "FILE_DROP_DETECTED", "SUSPICIOUS_PROCESS", "HIDDEN_FILE_CREATED",
}


class TelemetryPreprocessor:
    """
    Extracts a fixed-length numerical feature vector from raw telemetry events.
    Used by both the training pipeline (to build labeled datasets) and the
    inference anomaly detector (to compute features at analysis time).
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES
        logger.info("TelemetryPreprocessor initialized with %d features", len(FEATURE_NAMES))

    def extract_features(self, events: List[Dict[str, Any]]) -> List[float]:
        """
        Extract a numerical feature vector from a list of telemetry events.

        Returns:
            List of floats with length == len(FEATURE_NAMES)
        """
        if not events:
            return [0.0] * len(FEATURE_NAMES)

        # ── Count events by type ────────────────────────────────────────
        type_counts = {}
        for evt in events:
            t = evt.get("type", "UNKNOWN")
            type_counts[t] = type_counts.get(t, 0) + 1

        # ── Unique destinations ─────────────────────────────────────────
        dest_ips = set()
        dest_ports = set()
        domains = set()
        file_paths = set()

        for evt in events:
            data = evt.get("data", {})
            if data.get("dest_ip"):
                dest_ips.add(data["dest_ip"])
            if data.get("dest_port"):
                dest_ports.add(data["dest_port"])
            if data.get("domain") or data.get("query"):
                domains.add(data.get("domain", data.get("query", "")))
            if data.get("path"):
                file_paths.add(data["path"])

        # ── Severity ratio ──────────────────────────────────────────────
        high_sev_count = sum(
            1 for evt in events if evt.get("type", "") in HIGH_SEVERITY_TYPES
        )
        high_sev_ratio = high_sev_count / len(events) if events else 0.0

        # ── Event type diversity (entropy-like) ─────────────────────────
        unique_types = len(type_counts)
        diversity = unique_types / max(len(events), 1)

        # ── Burst detection ─────────────────────────────────────────────
        max_burst = self._compute_max_burst(events)

        # ── C2 pattern detection ────────────────────────────────────────
        has_c2 = self._detect_c2_pattern(events)

        # ── Assemble feature vector ─────────────────────────────────────
        features = [
            float(len(events)),                                  # total_events
            float(type_counts.get("PROCESS_CREATE", 0)),         # process_create_count
            float(type_counts.get("SOCKET_CONNECT", 0)
                  + type_counts.get("NETWORK_CONNECT", 0)),      # network_connect_count
            float(type_counts.get("DNS_QUERY", 0)),              # dns_query_count
            float(type_counts.get("FILE_WRITE", 0)),             # file_write_count
            float(type_counts.get("FILE_CREATE", 0)),            # file_create_count
            float(type_counts.get("REGISTRY_MODIFY", 0)
                  + type_counts.get("REGISTRY_CREATE", 0)),      # registry_modify_count
            float(type_counts.get("PERSISTENCE_EVENT", 0)),      # persistence_event_count
            float(type_counts.get("MEMORY_INJECTION", 0)),       # memory_injection_count
            float(type_counts.get("EXECUTION", 0)),              # execution_count
            float(type_counts.get("EXECUTION_ERROR", 0)),        # execution_error_count
            float(type_counts.get("EXECUTION_TIMEOUT", 0)),      # timeout_count
            float(len(dest_ips)),                                # unique_dest_ips
            float(len(dest_ports)),                              # unique_dest_ports
            float(len(domains)),                                 # unique_domains
            float(len(file_paths)),                              # unique_file_paths
            round(high_sev_ratio, 4),                            # high_severity_ratio
            round(diversity, 4),                                 # event_type_diversity
            float(max_burst),                                    # max_burst_size
            float(has_c2),                                       # has_c2_pattern
        ]

        return features

    def extract_features_batch(
        self, event_batches: List[List[Dict[str, Any]]]
    ) -> List[List[float]]:
        """
        Extract feature vectors for multiple event streams (batch mode).
        Used during training to process labeled datasets.
        """
        return [self.extract_features(batch) for batch in event_batches]

    def get_feature_names(self) -> List[str]:
        """Return the ordered feature names for labeling."""
        return list(FEATURE_NAMES)

    def _compute_max_burst(self, events: List[Dict[str, Any]], window_ms: int = 1000) -> int:
        """
        Find the maximum number of events within a sliding time window.
        """
        timestamps = []
        for evt in events:
            ts = evt.get("timestamp", "")
            if ts:
                timestamps.append(ts)

        if len(timestamps) < 2:
            return len(events)

        sorted_ts = sorted(timestamps)

        # Simple approach: count events sharing the same second prefix
        second_counts = {}
        for ts in sorted_ts:
            key = ts[:19]  # YYYY-MM-DDTHH:MM:SS
            second_counts[key] = second_counts.get(key, 0) + 1

        return max(second_counts.values()) if second_counts else 1

    def _detect_c2_pattern(self, events: List[Dict[str, Any]]) -> int:
        """
        Heuristic C2 detection: process creation → network connection → file write
        appearing in sequence suggests command-and-control behavior.
        """
        types = [evt.get("type", "") for evt in events]

        # Look for the classic C2 pattern
        saw_proc = False
        saw_net = False
        for t in types:
            if t == "PROCESS_CREATE":
                saw_proc = True
            elif saw_proc and t in ("SOCKET_CONNECT", "NETWORK_CONNECT", "DNS_QUERY"):
                saw_net = True
            elif saw_proc and saw_net and t in ("FILE_WRITE", "FILE_CREATE"):
                return 1

        return 0
