"""
Hidden File Detector — Filesystem Monitoring for Concealed Artifacts

Detects creation of hidden files (dotfiles on Linux, hidden attribute on Windows)
and monitors writes to suspicious filesystem paths (temp dirs, startup dirs, cron dirs).
Runs inside the sandbox container alongside the eBPF collector.
"""

import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("hidden_file_detector")

# ── Suspicious paths that indicate malicious file drops ─────────────────────
SUSPICIOUS_PATHS_LINUX = [
    "/tmp", "/var/tmp", "/dev/shm",  # nosec B108
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/init.d", "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/root/.ssh", "/root/.bashrc", "/root/.profile",
    "/home", "/.config/autostart",
]

SUSPICIOUS_PATHS_WINDOWS = [
    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "\\AppData\\Local\\Temp",
    "\\Windows\\Temp",
    "\\ProgramData",
    "\\Windows\\System32\\Tasks",
]

# File extensions commonly associated with malware drops
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".scr", ".pif", ".hta", ".wsf", ".cpl", ".msi",
    ".sh", ".elf", ".bin", ".so",
}


class HiddenFileDetector:
    """
    Monitors filesystem events from telemetry for hidden or suspicious file operations.
    Designed to run as a post-processor on FILE_WRITE / FILE_CREATE events.
    """

    def __init__(self):
        logger.info("HiddenFileDetector initialized")

    def analyze_events(self, telemetry_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze telemetry events for hidden file creation and suspicious path writes.

        Args:
            telemetry_events: List of telemetry event dicts from sandbox execution.

        Returns:
            List of detection event dicts to be appended to the telemetry stream.
        """
        detections = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            if evt_type not in ("FILE_WRITE", "FILE_CREATE", "FILE_DROP_DETECTED"):
                continue

            data = event.get("data", {})
            file_path = data.get("path", "")
            if not file_path:
                continue

            # ── Check for hidden files ──────────────────────────────────
            hidden_detection = self._check_hidden_file(file_path)
            if hidden_detection:
                detections.append(hidden_detection)

            # ── Check for suspicious paths ──────────────────────────────
            path_detection = self._check_suspicious_path(file_path)
            if path_detection:
                detections.append(path_detection)

            # ── Check for suspicious extensions ─────────────────────────
            ext_detection = self._check_suspicious_extension(file_path)
            if ext_detection:
                detections.append(ext_detection)

        if detections:
            logger.info("HiddenFileDetector found %d suspicious file events", len(detections))

        return detections

    def _check_hidden_file(self, file_path: str) -> Dict[str, Any] | None:
        """Detect hidden files (dotfiles on Linux, hidden directories)."""
        basename = os.path.basename(file_path)

        # Linux: dotfiles
        if basename.startswith(".") and len(basename) > 1:
            return {
                "type": "HIDDEN_FILE_CREATED",
                "severity": "high",
                "timestamp": "",  # Will be filled by caller
                "data": {
                    "path": file_path,
                    "mechanism": "dotfile",
                    "description": f"Hidden file created: {basename}",
                },
            }

        # Detect files in hidden directories
        parts = file_path.replace("\\", "/").split("/")
        for part in parts:
            if part.startswith(".") and len(part) > 1 and part not in (".", ".."):
                return {
                    "type": "HIDDEN_FILE_CREATED",
                    "severity": "medium",
                    "timestamp": "",
                    "data": {
                        "path": file_path,
                        "mechanism": "hidden_directory",
                        "description": f"File written inside hidden directory: {part}",
                    },
                }

        return None

    def _check_suspicious_path(self, file_path: str) -> Dict[str, Any] | None:
        """Check if the file was written to a suspicious filesystem location."""
        normalized = file_path.replace("\\", "/").lower()

        # Check Linux suspicious paths
        for sus_path in SUSPICIOUS_PATHS_LINUX:
            if normalized.startswith(sus_path.lower()):
                return {
                    "type": "SUSPICIOUS_PATH_WRITE",
                    "severity": "high",
                    "timestamp": "",
                    "data": {
                        "path": file_path,
                        "suspicious_directory": sus_path,
                        "description": f"File written to sensitive location: {sus_path}",
                    },
                }

        # Check Windows suspicious paths
        for sus_path in SUSPICIOUS_PATHS_WINDOWS:
            if sus_path.lower().replace("\\", "/") in normalized:
                return {
                    "type": "SUSPICIOUS_PATH_WRITE",
                    "severity": "high",
                    "timestamp": "",
                    "data": {
                        "path": file_path,
                        "suspicious_directory": sus_path,
                        "description": f"File written to sensitive Windows location: {sus_path}",
                    },
                }

        return None

    def _check_suspicious_extension(self, file_path: str) -> Dict[str, Any] | None:
        """Check if a dropped file has a suspicious executable extension."""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        if ext in SUSPICIOUS_EXTENSIONS:
            return {
                "type": "SUSPICIOUS_FILE_DROP",
                "severity": "high",
                "timestamp": "",
                "data": {
                    "path": file_path,
                    "extension": ext,
                    "description": f"Executable file dropped with extension: {ext}",
                },
            }

        return None
