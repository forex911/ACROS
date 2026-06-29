"""
Telemetry Normalizer
=====================
Bridges the gap between:
1. Typed telemetry events (from TelemetryProvider subclasses)
2. Raw dict events (from mock_sandbox / Kubernetes logs)
3. The validated event stream consumed by the pipeline

Ensures ALL telemetry entering the pipeline has a consistent format
regardless of sandbox mode.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
from app.services.telemetry.validator import validate_event_stream

logger = logging.getLogger("telemetry_normalizer")


def normalize_telemetry(
    raw_events: List[Any],
    job_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Normalize raw telemetry from any sandbox mode into validated pipeline events.

    Steps:
        1. Convert typed dataclass events to dicts (if needed)
        2. Validate each event
        3. Enrich with job_id
        4. Deduplicate identical events

    Returns a list of validated, enriched event dicts.
    """
    # Step 1: Convert dataclass events to dicts
    dict_events = []
    for event in raw_events:
        if isinstance(event, dict):
            dict_events.append(event)
        elif hasattr(event, "__dataclass_fields__"):
            # It's a dataclass from TelemetryProvider
            from app.services.telemetry.provider import TelemetryProvider
            converted = TelemetryProvider.event_to_dict(event)
            if converted:
                dict_events.append(converted)
            else:
                logger.warning(f"[Normalizer] Failed to convert event: {type(event).__name__}")
        else:
            logger.warning(f"[Normalizer] Unknown event type: {type(event)}")

    # Step 2: Validate
    validated = validate_event_stream(dict_events)

    # Step 3: Enrich with job_id
    if job_id:
        for event in validated:
            event.setdefault("job_id", job_id)

    # Step 4: Deduplicate (same type + same data = duplicate)
    seen = set()
    deduped = []
    for event in validated:
        # Build a dedup key from type + core data fields
        evt_type = event.get("type", "")
        data = event.get("data", {})
        key_parts = [evt_type]

        # Use the most identifying fields for each type
        if evt_type == "PROCESS_CREATE":
            key_parts.extend([str(data.get("pid", "")), str(data.get("cmdline", ""))])
        elif evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
            key_parts.extend([str(data.get("dest_ip", "")), str(data.get("dest_port", ""))])
        elif evt_type == "DNS_QUERY":
            key_parts.append(str(data.get("query", "")))
        elif evt_type in ("REGISTRY_CREATE", "REGISTRY_MODIFY"):
            key_parts.append(str(data.get("key", "")))
        elif evt_type in ("FILE_WRITE", "FILE_CREATE"):
            key_parts.append(str(data.get("path", data.get("filename", ""))))
        elif evt_type == "MEMORY_INJECTION":
            key_parts.extend([str(data.get("source_pid", "")), str(data.get("target_pid", ""))])
        else:
            # For other types, use a hash of all data
            key_parts.append(str(sorted(data.items())))

        dedup_key = "|".join(key_parts)
        if dedup_key not in seen:
            seen.add(dedup_key)
            deduped.append(event)

    if len(validated) != len(deduped):
        logger.info(
            f"[Normalizer] Deduped {len(validated) - len(deduped)} events "
            f"({len(validated)} → {len(deduped)})"
        )

    return deduped
