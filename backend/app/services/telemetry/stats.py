"""
Telemetry Stats — Event Counting for Observability
====================================================
Collects per-job telemetry statistics for dashboard display
and pipeline observability.
"""

from typing import List, Dict, Any
from collections import Counter


def compute_telemetry_stats(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute summary statistics from a validated telemetry event list.

    Returns::

        {
            "total_events": 42,
            "by_type": {"PROCESS_CREATE": 5, "DNS_QUERY": 12, ...},
            "by_severity": {"high": 8, "medium": 15, "info": 19},
            "unique_pids": 3,
            "unique_ips": 2,
            "unique_domains": 4,
            "has_persistence": True,
            "has_injection": False,
            "has_network": True,
        }
    """
    type_counts = Counter()
    severity_counts = Counter()
    pids = set()
    ips = set()
    domains = set()
    has_persistence = False
    has_injection = False
    has_network = False

    for event in events:
        evt_type = event.get("type", "UNKNOWN")
        data = event.get("data", {})

        type_counts[evt_type] += 1
        severity_counts[event.get("severity", "info")] += 1

        # Collect unique identifiers
        pid = data.get("pid")
        if pid is not None:
            pids.add(pid)

        dest_ip = data.get("dest_ip")
        if dest_ip:
            ips.add(dest_ip)

        query = data.get("query")
        if query:
            domains.add(query)

        # Behavioral flags
        if evt_type == "PERSISTENCE_EVENT":
            has_persistence = True
        elif evt_type == "MEMORY_INJECTION":
            has_injection = True
        elif evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT", "DNS_QUERY", "HTTP_REQUEST"):
            has_network = True

    return {
        "total_events": len(events),
        "by_type": dict(type_counts),
        "by_severity": dict(severity_counts),
        "unique_pids": len(pids),
        "unique_ips": len(ips),
        "unique_domains": len(domains),
        "has_persistence": has_persistence,
        "has_injection": has_injection,
        "has_network": has_network,
    }
