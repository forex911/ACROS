"""
Persistence Detector — Identifies Malware Persistence Mechanisms

Detects persistence mechanisms from telemetry events:
- Crontab modifications
- Systemd service creation
- Shell profile injection (.bashrc, .profile)
- Windows Run key registry modifications
- Startup folder file drops
- SSH authorized_keys injection

Emits PERSISTENCE_EVENT telemetry (matches the type already handled in analysis_pipeline.py).
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("persistence_detector")

# ── Persistence indicator patterns ──────────────────────────────────────────
CRON_PATHS = [
    "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/",
    "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
    "/var/spool/cron/",
]

SYSTEMD_PATHS = [
    "/etc/systemd/system/", "/usr/lib/systemd/system/",
    "/lib/systemd/system/", "/.config/systemd/user/",
]

SHELL_PROFILE_FILES = [
    ".bashrc", ".bash_profile", ".profile", ".zshrc",
    ".bash_login", ".bash_logout",
]

WINDOWS_STARTUP_PATHS = [
    "Start Menu\\Programs\\Startup",
    "Start Menu/Programs/Startup",
]

WINDOWS_RUN_KEYS = [
    "currentversion\\run",
    "currentversion\\runonce",
    "currentversion\\runservices",
    "currentversion\\runservicesonce",
    "currentversion\\explorer\\shell folders",
]

SSH_AUTH_PATHS = [
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
]

# Commands that install persistence
PERSISTENCE_COMMANDS = [
    "crontab", "systemctl enable", "systemctl start",
    "schtasks", "at ", "reg add",
    "launchctl load", "chkconfig",
]


class PersistenceDetector:
    """
    Analyzes telemetry events for persistence mechanism installation.
    Returns detection events compatible with the ACROS pipeline.
    """

    def __init__(self):
        logger.info("PersistenceDetector initialized")

    def analyze_events(self, telemetry_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan telemetry events for persistence indicators.

        Returns:
            List of PERSISTENCE_EVENT dicts to append to the telemetry stream.
        """
        detections = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            data = event.get("data", {})

            # ── File-based persistence ──────────────────────────────────
            if evt_type in ("FILE_WRITE", "FILE_CREATE", "FILE_DROP_DETECTED"):
                file_path = data.get("path", "")
                detection = self._check_file_persistence(file_path)
                if detection:
                    detections.append(detection)

            # ── Command-based persistence ───────────────────────────────
            if evt_type in ("PROCESS_CREATE", "EXECUTION"):
                cmdline = data.get("cmdline", data.get("target", ""))
                detection = self._check_command_persistence(cmdline)
                if detection:
                    detections.append(detection)

            # ── Registry-based persistence (Windows) ────────────────────
            if evt_type in ("REGISTRY_MODIFY", "REGISTRY_CREATE"):
                key = data.get("key", "")
                detection = self._check_registry_persistence(key, data)
                if detection:
                    detections.append(detection)

        # Deduplicate by mechanism + target
        seen = set()
        unique = []
        for d in detections:
            key = (d["data"]["mechanism"], d["data"].get("target", ""))
            if key not in seen:
                seen.add(key)
                unique.append(d)

        if unique:
            logger.info("PersistenceDetector found %d persistence mechanisms", len(unique))

        return unique

    def _check_file_persistence(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Check if a file write targets a persistence location."""
        if not file_path:
            return None

        normalized = file_path.replace("\\", "/").lower()

        # Crontab modification
        for cron_path in CRON_PATHS:
            if normalized.startswith(cron_path.lower()) or normalized.endswith("crontab"):
                return self._make_event(
                    mechanism="crontab",
                    target=file_path,
                    description=f"Crontab persistence: file written to {file_path}",
                )

        # Systemd service creation
        for systemd_path in SYSTEMD_PATHS:
            if normalized.startswith(systemd_path.lower()):
                return self._make_event(
                    mechanism="systemd_service",
                    target=file_path,
                    description=f"Systemd service installed: {file_path}",
                )

        # Shell profile injection
        basename = os.path.basename(file_path)
        if basename in SHELL_PROFILE_FILES:
            return self._make_event(
                mechanism="shell_profile_injection",
                target=file_path,
                description=f"Shell profile modified: {basename}",
            )

        # Windows startup folder
        for startup_path in WINDOWS_STARTUP_PATHS:
            if startup_path.lower().replace("\\", "/") in normalized:
                return self._make_event(
                    mechanism="startup_folder",
                    target=file_path,
                    description=f"File dropped in Windows Startup folder: {file_path}",
                )

        # SSH authorized_keys injection
        for ssh_path in SSH_AUTH_PATHS:
            if normalized.endswith(ssh_path):
                return self._make_event(
                    mechanism="ssh_authorized_keys",
                    target=file_path,
                    description=f"SSH authorized_keys modified: {file_path}",
                )

        return None

    def _check_command_persistence(self, cmdline: str) -> Optional[Dict[str, Any]]:
        """Check if a command installs persistence."""
        if not cmdline:
            return None

        cmdline_lower = cmdline.lower()

        for cmd in PERSISTENCE_COMMANDS:
            if cmd in cmdline_lower:
                return self._make_event(
                    mechanism=f"command_{cmd.strip().replace(' ', '_')}",
                    target=cmdline,
                    description=f"Persistence command executed: {cmdline[:200]}",
                )

        return None

    def _check_registry_persistence(self, key: str, data: Dict) -> Optional[Dict[str, Any]]:
        """Check if a registry modification targets persistence keys."""
        if not key:
            return None

        key_lower = key.lower()

        for run_key in WINDOWS_RUN_KEYS:
            if run_key in key_lower:
                value_name = data.get("value_name", "")
                value_data = data.get("value_data", "")
                return self._make_event(
                    mechanism="registry_run_key",
                    target=f"{key}\\{value_name}" if value_name else key,
                    description=(
                        f"Registry Run key persistence: {key} "
                        f"(value: {value_data[:100]})"
                    ),
                )

        return None

    @staticmethod
    def _make_event(mechanism: str, target: str, description: str) -> Dict[str, Any]:
        """Create a PERSISTENCE_EVENT telemetry dict."""
        return {
            "type": "PERSISTENCE_EVENT",
            "severity": "critical",
            "timestamp": "",
            "data": {
                "mechanism": mechanism,
                "target": target,
                "description": description,
            },
        }
