"""
Suspicious Process Detector — Heuristic Process Behavior Analysis

Detects suspicious process behaviors from telemetry:
- Reverse shell patterns
- Crypto miner indicators
- Known malicious binary names
- Process name masquerading (typosquatting system binaries)
- Suspicious command-line patterns

Emits SUSPICIOUS_PROCESS events with confidence scores.
"""

import re
import os
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("suspicious_process")

# ── Reverse shell detection patterns ────────────────────────────────────────
REVERSE_SHELL_PATTERNS = [
    re.compile(r'bash\s+-i\s+>.*?/dev/tcp/', re.IGNORECASE),
    re.compile(r'/bin/sh\s+-i.*?/dev/tcp/', re.IGNORECASE),
    re.compile(r'nc\s+(-e\s+|--exec\s+)', re.IGNORECASE),
    re.compile(r'ncat\s+(-e\s+|--exec\s+)', re.IGNORECASE),
    re.compile(r'socat\s+.*?exec:', re.IGNORECASE),
    re.compile(r'python.*?socket.*?subprocess', re.IGNORECASE),
    re.compile(r'perl\s+-e\s+.*?socket', re.IGNORECASE),
    re.compile(r'ruby\s+-rsocket', re.IGNORECASE),
    re.compile(r'mkfifo\s+.*?/bin/sh', re.IGNORECASE),
    re.compile(r'php\s+-r\s+.*?fsockopen', re.IGNORECASE),
    re.compile(r'powershell.*?Net\.Sockets\.TCPClient', re.IGNORECASE),
    re.compile(r'powershell.*?Invoke-Expression.*?downloadstring', re.IGNORECASE),
]

# ── Crypto miner indicators ─────────────────────────────────────────────────
MINER_PATTERNS = [
    re.compile(r'(xmrig|cpuminer|minerd|ethminer|cgminer|bfgminer)', re.IGNORECASE),
    re.compile(r'stratum\+tcp://', re.IGNORECASE),
    re.compile(r'--coin\s+', re.IGNORECASE),
    re.compile(r'-o\s+pool\.|--url.*?pool\.', re.IGNORECASE),
    re.compile(r'--donate-level', re.IGNORECASE),
    re.compile(r'cryptonight|randomx|kawpow', re.IGNORECASE),
]

# ── Known malicious binary names ────────────────────────────────────────────
KNOWN_MALICIOUS = {
    "mimikatz", "lazagne", "procdump", "rubeus", "sharphound",
    "bloodhound", "psexec", "wce", "pwdump", "fgdump",
    "gsecdump", "lsadump", "secretsdump", "crackmapexec",
    "impacket", "chisel", "ligolo", "plink",
}

# ── System binaries for masquerading detection ──────────────────────────────
SYSTEM_BINARIES = {
    "svchost", "explorer", "lsass", "csrss", "winlogon",
    "services", "smss", "wininit", "dwm", "taskhost",
    "spoolsv", "searchindexer", "wuauclt",
    # Linux
    "init", "systemd", "kthreadd", "sshd", "cron",
}

# ── Suspicious command-line patterns ────────────────────────────────────────
SUSPICIOUS_CMDLINE_PATTERNS = [
    (re.compile(r'base64\s+-d', re.IGNORECASE), "Base64 decode execution", "high"),
    (re.compile(r'eval\s*\(', re.IGNORECASE), "Dynamic code evaluation", "high"),
    (re.compile(r'exec\s*\(', re.IGNORECASE), "Dynamic code execution", "medium"),
    (re.compile(r'chmod\s+\+x\s+/tmp/', re.IGNORECASE), "Making temp file executable", "high"),
    (re.compile(r'curl.*?\|\s*(bash|sh)', re.IGNORECASE), "Curl pipe to shell", "critical"),
    (re.compile(r'wget.*?\|\s*(bash|sh)', re.IGNORECASE), "Wget pipe to shell", "critical"),
    (re.compile(r'/etc/passwd', re.IGNORECASE), "Password file access", "high"),
    (re.compile(r'/etc/shadow', re.IGNORECASE), "Shadow file access", "critical"),
    (re.compile(r'iptables\s+-F', re.IGNORECASE), "Firewall rules flush", "critical"),
    (re.compile(r'ufw\s+disable', re.IGNORECASE), "Firewall disable", "critical"),
    (re.compile(r'setenforce\s+0', re.IGNORECASE), "SELinux disable", "critical"),
    (re.compile(r'history\s+-c', re.IGNORECASE), "Command history clearing", "high"),
    (re.compile(r'rm\s+-rf\s+/', re.IGNORECASE), "Recursive root deletion", "critical"),
    (re.compile(r'dd\s+if=/dev/(zero|random)\s+of=/', re.IGNORECASE), "Disk wipe attempt", "critical"),
]


class SuspiciousProcessDetector:
    """
    Heuristic-based detection of suspicious process behaviors.
    Analyzes command lines, process names, and execution patterns.
    """

    def __init__(self):
        logger.info("SuspiciousProcessDetector initialized")

    def analyze_events(self, telemetry_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze telemetry events for suspicious process activity.

        Returns:
            List of SUSPICIOUS_PROCESS detection events with confidence scores.
        """
        detections = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            if evt_type not in ("PROCESS_CREATE", "EXECUTION"):
                continue

            data = event.get("data", {})
            cmdline = data.get("cmdline", data.get("target", ""))
            executable = data.get("executable", data.get("name", ""))

            if not cmdline and not executable:
                continue

            # ── Reverse shell detection ─────────────────────────────────
            detection = self._check_reverse_shell(cmdline)
            if detection:
                detections.append(detection)

            # ── Crypto miner detection ──────────────────────────────────
            detection = self._check_crypto_miner(cmdline, executable)
            if detection:
                detections.append(detection)

            # ── Known malicious binary ──────────────────────────────────
            detection = self._check_known_malicious(executable, cmdline)
            if detection:
                detections.append(detection)

            # ── Process masquerading ────────────────────────────────────
            detection = self._check_masquerading(executable)
            if detection:
                detections.append(detection)

            # ── Suspicious command-line patterns ────────────────────────
            pattern_detections = self._check_suspicious_cmdline(cmdline)
            detections.extend(pattern_detections)

        # Deduplicate
        seen = set()
        unique = []
        for d in detections:
            key = d["data"].get("description", "")[:80]
            if key not in seen:
                seen.add(key)
                unique.append(d)

        if unique:
            logger.info("SuspiciousProcessDetector found %d detections", len(unique))

        return unique

    def _check_reverse_shell(self, cmdline: str) -> Optional[Dict[str, Any]]:
        """Check command line for reverse shell patterns."""
        if not cmdline:
            return None

        for pattern in REVERSE_SHELL_PATTERNS:
            if pattern.search(cmdline):
                return self._make_event(
                    description=f"Reverse shell detected: {cmdline[:200]}",
                    severity="critical",
                    confidence=0.95,
                    category="reverse_shell",
                    cmdline=cmdline,
                )
        return None

    def _check_crypto_miner(self, cmdline: str, executable: str) -> Optional[Dict[str, Any]]:
        """Check for crypto mining indicators."""
        check_text = f"{cmdline} {executable}".lower()

        for pattern in MINER_PATTERNS:
            if pattern.search(check_text):
                return self._make_event(
                    description=f"Crypto miner detected: {cmdline[:200]}",
                    severity="high",
                    confidence=0.90,
                    category="crypto_miner",
                    cmdline=cmdline,
                )
        return None

    def _check_known_malicious(self, executable: str, cmdline: str) -> Optional[Dict[str, Any]]:
        """Check for known malicious tool names."""
        basename = os.path.basename(executable).lower() if executable else ""
        check_text = f"{basename} {cmdline}".lower()

        for malware_name in KNOWN_MALICIOUS:
            if malware_name in check_text:
                return self._make_event(
                    description=f"Known malicious tool detected: {malware_name}",
                    severity="critical",
                    confidence=0.92,
                    category="known_malicious_tool",
                    cmdline=cmdline or executable,
                )
        return None

    def _check_masquerading(self, executable: str) -> Optional[Dict[str, Any]]:
        """
        Detect process name masquerading — binaries named similar to
        system processes but running from unusual paths.
        """
        if not executable:
            return None

        basename = os.path.basename(executable).lower().replace(".exe", "")
        dirpath = os.path.dirname(executable).lower()

        if basename in SYSTEM_BINARIES:
            # System binaries should run from system directories
            system_dirs = [
                "/usr/sbin", "/usr/bin", "/sbin", "/bin",
                "\\windows\\system32", "\\windows\\syswow64",
                "c:\\windows\\system32",
            ]
            normalized_dir = dirpath.replace("\\", "/")
            is_from_system = any(
                normalized_dir.endswith(sd.replace("\\", "/"))
                for sd in system_dirs
            )

            if not is_from_system and dirpath:
                return self._make_event(
                    description=(
                        f"Process masquerading: {basename} running from "
                        f"non-system path: {dirpath}"
                    ),
                    severity="high",
                    confidence=0.75,
                    category="process_masquerading",
                    cmdline=executable,
                )

        return None

    def _check_suspicious_cmdline(self, cmdline: str) -> List[Dict[str, Any]]:
        """Check command line against suspicious patterns."""
        detections = []

        if not cmdline:
            return detections

        for pattern, description, severity in SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern.search(cmdline):
                detections.append(self._make_event(
                    description=f"{description}: {cmdline[:200]}",
                    severity=severity,
                    confidence=0.80,
                    category="suspicious_cmdline",
                    cmdline=cmdline,
                ))

        return detections

    @staticmethod
    def _make_event(
        description: str,
        severity: str,
        confidence: float,
        category: str,
        cmdline: str,
    ) -> Dict[str, Any]:
        """Create a SUSPICIOUS_PROCESS detection event."""
        return {
            "type": "SUSPICIOUS_PROCESS",
            "severity": severity,
            "timestamp": "",
            "data": {
                "description": description,
                "confidence": confidence,
                "category": category,
                "cmdline": cmdline[:500],
            },
        }
