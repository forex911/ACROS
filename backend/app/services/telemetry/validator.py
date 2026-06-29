"""
Telemetry Event Validator
==========================
Validates and sanitizes telemetry events before they enter the analysis
pipeline. Rejects malformed events and enforces schema requirements.

This sits between the sandbox output and the pipeline input to guarantee
that downstream consumers always receive well-formed events.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger("telemetry_validator")

# Required top-level keys for all telemetry events
REQUIRED_KEYS = {"type", "data"}

# Valid event types (union of all known types across sandbox modes)
VALID_EVENT_TYPES = {
    # Process lifecycle
    "PROCESS_CREATE", "PROCESS_EXIT",
    # File operations
    "FILE_CREATE", "FILE_WRITE", "FILE_READ", "FILE_DELETE", "FILE_DROP_DETECTED",
    # Network
    "SOCKET_CONNECT", "NETWORK_CONNECT", "DNS_QUERY", "HTTP_REQUEST",
    # Registry
    "REGISTRY_CREATE", "REGISTRY_MODIFY",
    # Execution
    "EXECUTION", "POWERSHELL_EXECUTION", "EXECUTION_OUTPUT", "EXECUTION_TIMEOUT",
    # Advanced behaviors
    "MEMORY_INJECTION", "PERSISTENCE_EVENT", "PRIVILEGE_ESCALATION",
    "SERVICE_CREATE",
    # Sandbox control
    "SANDBOX_START", "SANDBOX_COMPLETE", "STATUS_CHANGE",
}

# Maximum event data payload size (prevent memory exhaustion from malicious telemetry)
MAX_DATA_SIZE = 64 * 1024  # 64 KB per event data payload

# Maximum number of events per job (prevent runaway event floods)
MAX_EVENTS_PER_JOB = 10_000


def validate_event(event: Any) -> Optional[Dict[str, Any]]:
    """
    Validate a single telemetry event.

    Returns the validated event dict, or None if it should be discarded.
    Does NOT raise — invalid events are silently dropped with a warning.
    """
    if not isinstance(event, dict):
        logger.warning(f"[Validator] Dropped non-dict event: {type(event)}")
        return None

    # Check required keys
    missing = REQUIRED_KEYS - set(event.keys())
    if missing:
        logger.warning(f"[Validator] Dropped event missing keys {missing}: {_preview(event)}")
        return None

    event_type = event.get("type", "")
    if not isinstance(event_type, str) or not event_type:
        logger.warning(f"[Validator] Dropped event with invalid type: {_preview(event)}")
        return None

    # Validate event type (warn but don't drop unknown types — future-proofing)
    if event_type not in VALID_EVENT_TYPES:
        logger.debug(f"[Validator] Unknown event type: {event_type}")

    # Validate data is a dict
    data = event.get("data")
    if not isinstance(data, dict):
        logger.warning(f"[Validator] Dropped event with non-dict data: {_preview(event)}")
        return None

    # Size guard
    import json
    try:
        data_size = len(json.dumps(data))
        if data_size > MAX_DATA_SIZE:
            logger.warning(f"[Validator] Dropped oversized event ({data_size} bytes): {event_type}")
            return None
    except (TypeError, ValueError):
        pass  # If we can't serialize it, let it through — downstream will handle it

    # Ensure timestamp exists (add one if missing)
    if "timestamp" not in event or not event["timestamp"]:
        event["timestamp"] = datetime.utcnow().isoformat() + "Z"

    # Ensure severity exists
    if "severity" not in event:
        event["severity"] = "info"

    return event


def validate_event_stream(events: List[Any]) -> List[Dict[str, Any]]:
    """
    Validate a batch of telemetry events.

    - Drops invalid events
    - Caps total count at MAX_EVENTS_PER_JOB
    - Returns only valid events
    """
    if not events:
        return []

    validated = []
    dropped = 0

    for event in events:
        if len(validated) >= MAX_EVENTS_PER_JOB:
            logger.warning(
                f"[Validator] Event cap reached ({MAX_EVENTS_PER_JOB}). "
                f"Dropping remaining {len(events) - len(validated)} events."
            )
            break

        result = validate_event(event)
        if result is not None:
            validated.append(result)
        else:
            dropped += 1

    if dropped > 0:
        logger.info(f"[Validator] Validated {len(validated)} events, dropped {dropped}")

    return validated


def _preview(event: Any) -> str:
    """Truncate event for logging."""
    s = str(event)
    return s[:120] + "..." if len(s) > 120 else s
