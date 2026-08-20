"""
Connection Logger — Outbound Network Connection Monitor

Logs all outbound TCP/UDP connections from the sandboxed process.
Reads from /proc/net/tcp and /proc/net/udp on Linux.
Emits SOCKET_CONNECT events consumed by the analysis pipeline.
"""

import os
import re
import socket
import struct
import logging
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger("connection_logger")

# ── Well-known suspicious ports ─────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 9999,  # Common reverse shell ports
    1337, 31337,                           # Hacker lore ports
    6667, 6697,                            # IRC (C2 communication)
    9050, 9150,                            # Tor SOCKS proxy
    3389,                                  # RDP
    445, 139,                              # SMB
    1433, 3306, 5432, 27017,               # Database ports
}

# Local/private IP ranges to exclude from suspicious detections
PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
]


def _ip_to_int(ip: str) -> int:
    """Convert dotted IP to integer for range comparison."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (OSError, socket.error):
        return 0


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    ip_int = _ip_to_int(ip)
    for start, end in PRIVATE_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


def _hex_to_ip(hex_ip: str) -> str:
    """Convert hex IP address from /proc/net/tcp to dotted notation."""
    try:
        ip_int = int(hex_ip, 16)
        # /proc/net/tcp stores IPs in little-endian on x86
        ip_bytes = struct.pack("<I", ip_int)
        return socket.inet_ntoa(ip_bytes)
    except (ValueError, struct.error, OSError):
        return "0.0.0.0"  # nosec B104


def _hex_to_port(hex_port: str) -> int:
    """Convert hex port from /proc/net/tcp to integer."""
    try:
        return int(hex_port, 16)
    except ValueError:
        return 0


class ConnectionLogger:
    """
    Monitors outbound network connections from sandboxed processes.
    Reads Linux /proc/net/tcp and /proc/net/udp for connection state.
    """

    def __init__(self, target_pid: Optional[int] = None):
        self.target_pid = target_pid
        self._seen_connections: Set[str] = set()
        logger.info("ConnectionLogger initialized (pid=%s)", target_pid or "all")

    def scan_connections(self) -> List[Dict[str, Any]]:
        """
        Scan /proc/net/tcp and /proc/net/udp for active connections.
        Returns new connections not previously seen.
        """
        events = []

        # Scan TCP connections
        tcp_conns = self._read_proc_net("/proc/net/tcp", "TCP")
        events.extend(tcp_conns)

        # Scan UDP connections
        udp_conns = self._read_proc_net("/proc/net/udp", "UDP")
        events.extend(udp_conns)

        return events

    def _read_proc_net(self, path: str, protocol: str) -> List[Dict[str, Any]]:
        """Parse /proc/net/tcp or /proc/net/udp and return connection events."""
        events = []

        if not os.path.exists(path):
            return events

        try:
            with open(path, "r") as f:
                lines = f.readlines()
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read %s: %s", path, e)
            return events

        for line in lines[1:]:  # Skip header
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            try:
                # Parse remote address (column 2)
                remote = parts[2]
                remote_ip_hex, remote_port_hex = remote.split(":")
                dest_ip = _hex_to_ip(remote_ip_hex)
                dest_port = _hex_to_port(remote_port_hex)

                # Parse local address (column 1)
                local = parts[1]
                local_ip_hex, local_port_hex = local.split(":")
                local_port = _hex_to_port(local_port_hex)

                # Skip listening sockets and zero addresses
                if dest_ip == "0.0.0.0" or dest_port == 0:  # nosec B104
                    continue

                # Dedup key
                conn_key = f"{protocol}:{dest_ip}:{dest_port}"
                if conn_key in self._seen_connections:
                    continue
                self._seen_connections.add(conn_key)

                event = {
                    "type": "SOCKET_CONNECT",
                    "severity": "medium",
                    "timestamp": "",
                    "data": {
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "local_port": local_port,
                        "protocol": protocol,
                        "is_private": _is_private_ip(dest_ip),
                    },
                }

                # Elevate severity for suspicious ports or public IPs
                if dest_port in SUSPICIOUS_PORTS:
                    event["severity"] = "high"
                    event["data"]["suspicious_port"] = True
                if not _is_private_ip(dest_ip):
                    event["severity"] = "high"
                    event["data"]["is_external"] = True

                events.append(event)

            except (ValueError, IndexError):
                continue

        if events:
            logger.info(
                "ConnectionLogger found %d new %s connections",
                len(events), protocol,
            )

        return events

    def analyze_telemetry_connections(
        self, telemetry_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze existing telemetry events for suspicious connection patterns.
        Enriches SOCKET_CONNECT/NETWORK_CONNECT events with threat context.
        """
        detections = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            if evt_type not in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
                continue

            data = event.get("data", {})
            dest_ip = data.get("dest_ip", "")
            dest_port = data.get("dest_port", 0)

            # Flag suspicious ports
            if dest_port in SUSPICIOUS_PORTS:
                detections.append({
                    "type": "SUSPICIOUS_CONNECTION",
                    "severity": "high",
                    "timestamp": event.get("timestamp", ""),
                    "data": {
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "reason": f"Connection to suspicious port {dest_port}",
                        "protocol": data.get("protocol", "TCP"),
                    },
                })

            # Flag connections to external IPs
            if dest_ip and not _is_private_ip(dest_ip):
                detections.append({
                    "type": "EXTERNAL_CONNECTION",
                    "severity": "medium",
                    "timestamp": event.get("timestamp", ""),
                    "data": {
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "reason": "Connection to external IP address",
                        "protocol": data.get("protocol", "TCP"),
                    },
                })

        return detections
