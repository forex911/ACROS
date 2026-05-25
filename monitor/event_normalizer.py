import uuid
import time
from typing import List, Dict, Any

class EventNormalizer:
    """
    Converts raw telemetry from various trackers into a unified JSON schema (ECS-like).
    """
    @staticmethod
    def normalize_events(raw_events: List[Dict[str, Any]], sandbox_id: str) -> List[Dict[str, Any]]:
        normalized = []
        for evt in raw_events:
            n_evt = {
                "event_id": str(uuid.uuid4()),
                "sandbox_id": sandbox_id,
                "@timestamp": evt.get("timestamp", time.time()),
                "event": {
                    "kind": "event",
                    "category": evt.get("event_type", "unknown"),
                    "type": ["info"]
                },
                "details": evt.get("details", {})
            }
            
            # Additional ECS mapping based on type
            if evt.get("event_type") == "suspicious_process":
                n_evt["event"]["category"] = "process"
                n_evt["event"]["type"] = ["creation", "suspicious"]
                n_evt["process"] = {
                    "pid": evt["details"].get("pid"),
                    "command_line": " ".join(evt["details"].get("cmdline", [])),
                    "executable": evt["details"].get("exe")
                }
            elif evt.get("event_type") in ["network_flow", "dns_query"]:
                n_evt["event"]["category"] = "network"
                n_evt["event"]["type"] = ["connection"]
                
            normalized.append(n_evt)
            
        return normalized
