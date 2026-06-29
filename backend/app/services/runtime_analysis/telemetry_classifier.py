import logging

logger = logging.getLogger("telemetry_classifier")

ALLOWED_EVENTS = {
    "PROCESS_CREATE",
    "PROCESS_EXIT",
    "DNS_QUERY",
    "SOCKET_CONNECT",
    "HTTP_REQUEST",
    "FILE_CREATE",
    "FILE_WRITE",
    "FILE_DELETE",
    "REGISTRY_CREATE",
    "REGISTRY_MODIFY",
    "POWERSHELL_EXECUTION",
    "SERVICE_CREATE",
    "PERSISTENCE_EVENT",
    "MEMORY_INJECTION",
    "PRIVILEGE_ESCALATION",
    "SANDBOX_START",
    "SANDBOX_COMPLETE"
}

NOISY_STRINGS = {
    "compile",
    "exec",
    "code object",
    "module loader",
    "lambda __cls__",
    "importlib",
    "<module>",
    "<frozen",
    "<built-in",
}

def is_noisy(event_type: str, data: dict) -> bool:
    """Check if the event contains Python internals noise."""
    if event_type == "PROCESS_OUTPUT":
        return True # Process output isn't a structured telemetry event allowed in the final UI list

    # Check for noisy strings in data values
    for v in data.values():
        val_str = str(v).lower()
        if any(noise in val_str for noise in NOISY_STRINGS):
            return True
            
    # Some older sandbox logs map python exec to EXECUTION event types. Filter those.
    if event_type == "EXECUTION":
        action = str(data.get("type", "")).lower()
        if action in ["compile", "exec", "eval", "import"]:
            return True
            
    return False

def classify_event(raw_event: dict) -> dict:
    """
    Takes a raw telemetry event and normalizes it.
    Returns None if the event should be discarded.
    """
    event_type = raw_event.get("type", "UNKNOWN")
    data = raw_event.get("data", {})
    
    # 1. Noise filtering
    if is_noisy(event_type, data):
        return None
        
    # Map old EXECUTION to PROCESS_CREATE if it's actually spawning a process
    if event_type == "EXECUTION" and data.get("type") == "subprocess":
        event_type = "PROCESS_CREATE"
        data["cmdline"] = str(data.get("target", ""))
    # 1b. Normalize legacy event types before allowlisting
    if event_type == "NETWORK_CONNECT":
        event_type = "SOCKET_CONNECT"
        
    # 2. Strict allowlisting
    if event_type not in ALLOWED_EVENTS:
        return None
        
    # 3. Normalization (ensure expected fields exist for frontend graph/tree)
    if event_type == "PROCESS_CREATE":
        if "cmdline" not in data and "filename" in data:
            data["cmdline"] = data["filename"]
    elif event_type in ["SOCKET_CONNECT", "NETWORK_CONNECT"]:
        event_type = "SOCKET_CONNECT" # Normalize
        if "dest_ip" not in data and "ip" in data:
            data["dest_ip"] = data["ip"]
    elif event_type == "DNS_QUERY":
        if "query" not in data and "domain" in data:
            data["query"] = data["domain"]

    # 4. Determine severity
    severity = "info"
    if event_type in ["PROCESS_CREATE", "POWERSHELL_EXECUTION", "SERVICE_CREATE", "PERSISTENCE_EVENT", "MEMORY_INJECTION", "PRIVILEGE_ESCALATION"]:
        severity = "high"
    elif event_type in ["FILE_WRITE", "REGISTRY_MODIFY", "REGISTRY_CREATE", "HTTP_REQUEST", "SOCKET_CONNECT"]:
        severity = "medium"
    
    return {
        "type": event_type,
        "severity": severity,
        "timestamp": raw_event.get("timestamp"),
        "data": data
    }
