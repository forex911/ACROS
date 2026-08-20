"""
DNS Tracker — DNS Query Monitoring and Analysis

Monitors DNS queries from sandboxed processes for suspicious domain resolution.
Supports multiple collection methods:
- Telemetry event analysis (primary — works cross-platform)
- /var/log/syslog parsing (Linux, if available)
- Passive DNS monitoring via captured events

Emits DNS_QUERY events consumed by the analysis pipeline.
"""

import re
import os
import logging
from typing import List, Dict, Any, Set, Optional

logger = logging.getLogger("dns_tracker")

# ── Suspicious TLD patterns ─────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",      # Free TLDs abused by malware
    ".xyz", ".top", ".pw", ".ws", ".cc",     # Commonly abused TLDs
    ".onion",                                 # Tor hidden services
    ".bit",                                   # Blockchain DNS
}

# ── Known DGA (Domain Generation Algorithm) patterns ────────────────────────
DGA_CONSONANT_RATIO_THRESHOLD = 0.7
DGA_MIN_LENGTH = 8
DGA_MAX_LABEL_LENGTH = 63

# ── Suspicious domain keywords ──────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "pastebin", "paste.ee", "hastebin",       # Paste sites (C2 staging)
    "ngrok", "serveo", "localtunnel",          # Tunneling services
    "discord", "telegram",                     # Messaging API abuse
    "raw.githubusercontent",                    # GitHub raw (payload hosting)
    "transfer.sh", "file.io",                  # File sharing (exfiltration)
]


class DNSTracker:
    """
    Tracks and analyzes DNS queries from sandboxed processes.
    Identifies suspicious domain lookups, DGA-generated domains,
    and known malicious infrastructure.
    """

    def __init__(self):
        self._seen_domains: Set[str] = set()
        logger.info("DNSTracker initialized")

    def analyze_telemetry_events(
        self, telemetry_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze telemetry DNS_QUERY events for suspicious patterns.

        Returns:
            List of enriched/detection events to append to the stream.
        """
        detections = []

        for event in telemetry_events:
            if event.get("type") != "DNS_QUERY":
                continue

            data = event.get("data", {})
            domain = data.get("domain", data.get("query", "")).strip().lower()
            if not domain:
                continue

            if domain in self._seen_domains:
                continue
            self._seen_domains.add(domain)

            # ── Check for suspicious TLDs ───────────────────────────────
            if self._has_suspicious_tld(domain):
                detections.append(self._make_detection(
                    domain=domain,
                    reason="suspicious_tld",
                    description=f"DNS query to suspicious TLD: {domain}",
                    severity="high",
                ))

            # ── Check for DGA-generated domains ─────────────────────────
            if self._is_dga_domain(domain):
                detections.append(self._make_detection(
                    domain=domain,
                    reason="dga_detected",
                    description=f"Possible DGA-generated domain: {domain}",
                    severity="critical",
                ))

            # ── Check for suspicious keywords ───────────────────────────
            keyword = self._check_suspicious_keywords(domain)
            if keyword:
                detections.append(self._make_detection(
                    domain=domain,
                    reason="suspicious_service",
                    description=f"DNS query to suspicious service ({keyword}): {domain}",
                    severity="high",
                ))

            # ── Check for IP-like domains (hex/numeric) ─────────────────
            if self._is_ip_like_domain(domain):
                detections.append(self._make_detection(
                    domain=domain,
                    reason="ip_like_domain",
                    description=f"DNS query with IP-like/numeric domain: {domain}",
                    severity="medium",
                ))

        if detections:
            logger.info("DNSTracker flagged %d suspicious domains", len(detections))

        return detections

    def parse_syslog_dns(self, log_path: str = "/var/log/syslog") -> List[Dict[str, Any]]:
        """
        Parse DNS queries from system log (Linux dnsmasq/systemd-resolved).
        Fallback method when eBPF DNS hooks are unavailable.
        """
        events = []

        if not os.path.exists(log_path):
            return events

        dns_pattern = re.compile(
            r'query\[A(?:AAA)?\]\s+(\S+)\s+from\s+(\S+)',
            re.IGNORECASE,
        )

        try:
            with open(log_path, "r") as f:
                for line in f:
                    match = dns_pattern.search(line)
                    if match:
                        domain = match.group(1).lower().rstrip(".")
                        if domain not in self._seen_domains:
                            self._seen_domains.add(domain)
                            events.append({
                                "type": "DNS_QUERY",
                                "severity": "info",
                                "timestamp": "",
                                "data": {
                                    "domain": domain,
                                    "source": "syslog",
                                },
                            })
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read %s: %s", log_path, e)

        return events

    def get_domain_summary(self) -> Dict[str, Any]:
        """Return a summary of all observed DNS queries."""
        suspicious = [d for d in self._seen_domains if self._has_suspicious_tld(d)]
        dga = [d for d in self._seen_domains if self._is_dga_domain(d)]

        return {
            "total_domains": len(self._seen_domains),
            "suspicious_tld_count": len(suspicious),
            "dga_count": len(dga),
            "domains": list(self._seen_domains),
        }

    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain uses a suspicious TLD."""
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        return False

    def _is_dga_domain(self, domain: str) -> bool:
        """
        Heuristic DGA detection based on:
        - High consonant ratio in the domain label
        - Length of the label
        - Lack of recognizable words
        """
        # Extract the main label (first part before TLD)
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        label = parts[0]
        if len(label) < DGA_MIN_LENGTH:
            return False

        # Count consonants vs vowels
        vowels = set("aeiou")
        consonants = sum(1 for c in label if c.isalpha() and c not in vowels)
        total_alpha = sum(1 for c in label if c.isalpha())

        if total_alpha == 0:
            return False

        consonant_ratio = consonants / total_alpha

        # High consonant ratio + long label = likely DGA
        if consonant_ratio > DGA_CONSONANT_RATIO_THRESHOLD and len(label) > 12:
            return True

        # Many digits mixed with letters
        digit_count = sum(1 for c in label if c.isdigit())
        if digit_count > 3 and total_alpha > 3 and len(label) > 10:
            return True

        return False

    def _check_suspicious_keywords(self, domain: str) -> Optional[str]:
        """Check if domain contains known suspicious service keywords."""
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in domain:
                return keyword
        return None

    def _is_ip_like_domain(self, domain: str) -> bool:
        """Check if domain looks like an IP address or hex-encoded."""
        label = domain.split(".")[0]
        # All digits
        if label.isdigit() and len(label) > 4:
            return True
        # All hex characters
        if re.match(r'^[0-9a-f]+$', label) and len(label) >= 8:
            return True
        return False

    @staticmethod
    def _make_detection(
        domain: str, reason: str, description: str, severity: str
    ) -> Dict[str, Any]:
        """Create a suspicious DNS detection event."""
        return {
            "type": "SUSPICIOUS_DNS",
            "severity": severity,
            "timestamp": "",
            "data": {
                "domain": domain,
                "reason": reason,
                "description": description,
            },
        }
