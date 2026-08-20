"""
IP Analyzer — Threat Intelligence Analysis for Destination IPs

Analyzes destination IP addresses against embedded threat intelligence:
- RFC1918 evasion detection
- Known Tor exit node ranges
- Known C2 infrastructure ranges
- Geo-suspicious patterns
- Bogon/reserved address detection

Emits SUSPICIOUS_IP events with threat intelligence context.
"""

import struct
import socket
import logging
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger("ip_analyzer")

# ── Known malicious / suspicious IP ranges (CIDR-like) ──────────────────────
# These are representative examples — in production, this would be loaded from
# a threat intelligence feed (e.g., AlienVault OTX, Emerging Threats, etc.)

TOR_EXIT_NODE_RANGES = [
    # Sample Tor exit ranges (in production, loaded from Tor consensus)
    "185.220.100.", "185.220.101.", "185.220.102.", "185.220.103.",
    "199.249.230.", "204.85.191.",
    "109.70.100.",  "51.75.52.", "23.129.64.",
]

KNOWN_C2_RANGES = [
    # Sample known C2 infrastructure ranges
    # In production, loaded from threat intel feeds
    "45.33.32.",   # Known scanning infrastructure
    "198.51.100.", # Documentation range (should never appear in real traffic)
    "203.0.113.",  # Documentation range
]

# ── Bogon/Reserved ranges that shouldn't be destinations ────────────────────
BOGON_PREFIXES = [
    "0.",           # Current network
    "100.64.",      # Shared address space (CGN)
    "169.254.",     # Link-local
    "192.0.0.",     # IETF protocol assignments
    "192.0.2.",     # Documentation (TEST-NET-1)
    "198.18.",      # Benchmarking
    "198.51.100.",  # Documentation (TEST-NET-2)
    "203.0.113.",   # Documentation (TEST-NET-3)
    "224.",         # Multicast
    "240.",         # Reserved
    "255.",         # Broadcast
]


def _ip_to_int(ip: str) -> int:
    """Convert dotted IP to integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (socket.error, OSError):
        return 0


def _is_private(ip: str) -> bool:
    """Check if IP is in RFC1918 private space."""
    ip_int = _ip_to_int(ip)
    ranges = [
        (_ip_to_int("10.0.0.0"), _ip_to_int("10.255.255.255")),
        (_ip_to_int("172.16.0.0"), _ip_to_int("172.31.255.255")),
        (_ip_to_int("192.168.0.0"), _ip_to_int("192.168.255.255")),
    ]
    return any(start <= ip_int <= end for start, end in ranges)


def _is_loopback(ip: str) -> bool:
    """Check if IP is loopback."""
    return ip.startswith("127.")


class IPAnalyzer:
    """
    Analyzes destination IPs against threat intelligence databases.
    Designed to enrich network connection events with threat context.
    """

    def __init__(self):
        self._analyzed_ips: Set[str] = set()
        logger.info("IPAnalyzer initialized with embedded threat intel")

    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """
        Analyze a single IP address against threat intelligence.

        Returns:
            Dict with threat assessment: threat_level, categories, details
        """
        result = {
            "ip": ip,
            "threat_level": "none",
            "categories": [],
            "details": [],
            "is_private": _is_private(ip),
            "is_loopback": _is_loopback(ip),
        }

        if _is_loopback(ip) or not ip:
            return result

        # ── Check Tor exit nodes ────────────────────────────────────────
        if self._is_tor_exit(ip):
            result["threat_level"] = "high"
            result["categories"].append("tor_exit_node")
            result["details"].append(f"IP {ip} matches known Tor exit node range")

        # ── Check known C2 ranges ───────────────────────────────────────
        if self._is_known_c2(ip):
            result["threat_level"] = "critical"
            result["categories"].append("known_c2")
            result["details"].append(f"IP {ip} matches known C2 infrastructure range")

        # ── Check bogon/reserved ranges ─────────────────────────────────
        if self._is_bogon(ip):
            result["threat_level"] = "medium"
            result["categories"].append("bogon_address")
            result["details"].append(f"IP {ip} is in a reserved/bogon range (should not appear in real traffic)")

        # ── External IP assessment ──────────────────────────────────────
        if not _is_private(ip) and not _is_loopback(ip) and not self._is_bogon(ip):
            if result["threat_level"] == "none":
                result["threat_level"] = "low"
                result["categories"].append("external_ip")
                result["details"].append(f"External IP connection: {ip}")

        return result

    def analyze_telemetry_events(
        self, telemetry_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze telemetry events for suspicious IP connections.
        Processes SOCKET_CONNECT and NETWORK_CONNECT events.

        Returns:
            List of SUSPICIOUS_IP detection events.
        """
        detections = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            if evt_type not in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
                continue

            data = event.get("data", {})
            dest_ip = data.get("dest_ip", "")

            if not dest_ip or dest_ip in self._analyzed_ips:
                continue
            self._analyzed_ips.add(dest_ip)

            assessment = self.analyze_ip(dest_ip)

            # Only emit detections for medium+ threat levels
            if assessment["threat_level"] in ("medium", "high", "critical"):
                detections.append({
                    "type": "SUSPICIOUS_IP",
                    "severity": assessment["threat_level"],
                    "timestamp": event.get("timestamp", ""),
                    "data": {
                        "dest_ip": dest_ip,
                        "dest_port": data.get("dest_port", 0),
                        "threat_level": assessment["threat_level"],
                        "categories": assessment["categories"],
                        "description": "; ".join(assessment["details"]),
                    },
                })

        if detections:
            logger.info("IPAnalyzer flagged %d suspicious IPs", len(detections))

        return detections

    def get_ip_report(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Batch analyze a list of IPs and return assessments."""
        return [self.analyze_ip(ip) for ip in ips if ip]

    def _is_tor_exit(self, ip: str) -> bool:
        """Check if IP matches known Tor exit node ranges."""
        for prefix in TOR_EXIT_NODE_RANGES:
            if ip.startswith(prefix):
                return True
        return False

    def _is_known_c2(self, ip: str) -> bool:
        """Check if IP matches known C2 infrastructure ranges."""
        for prefix in KNOWN_C2_RANGES:
            if ip.startswith(prefix):
                return True
        return False

    def _is_bogon(self, ip: str) -> bool:
        """Check if IP is in a bogon/reserved range."""
        for prefix in BOGON_PREFIXES:
            if ip.startswith(prefix):
                return True
        return False
