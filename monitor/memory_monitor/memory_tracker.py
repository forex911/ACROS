"""
Memory Tracker — Process Memory Analysis for Injection Detection

Monitors process memory regions for suspicious patterns:
- RWX (Read-Write-Execute) memory pages
- Process hollowing indicators
- Injected code regions
- Unusual memory allocations

Reads from /proc/<pid>/maps on Linux.
Emits MEMORY_INJECTION events consumed by the graph ingestion pipeline.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("memory_tracker")

# ── Suspicious memory patterns ──────────────────────────────────────────────
# RWX permissions indicate self-modifying or injected code
RWX_PATTERN = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+rwxp', re.MULTILINE)

# Anonymous memory regions with execute permission
ANON_EXEC_PATTERN = re.compile(
    r'^([0-9a-f]+)-([0-9a-f]+)\s+r.xp\s+\d+\s+\d+:\d+\s+0\s*$',
    re.MULTILINE,
)

# Known injection-related API calls (for telemetry analysis)
INJECTION_APIS = {
    "virtualallocex", "writeprocessmemory", "createremotethread",
    "ntwritevirtualmemory", "rtlcreateuserthread", "setthreadcontext",
    "ntmapviewofsection", "queueuserapc", "ntqueueapcthread",
    "ptrace", "process_vm_writev",
}

# Minimum size of suspicious memory region (bytes)
MIN_SUSPICIOUS_REGION_SIZE = 4096


class MemoryTracker:
    """
    Tracks process memory regions and detects suspicious patterns
    indicative of code injection or process hollowing.
    """

    def __init__(self, target_pid: Optional[int] = None):
        self.target_pid = target_pid
        self._known_regions = {}
        logger.info("MemoryTracker initialized (pid=%s)", target_pid or "all")

    def scan_process_memory(self, pid: int) -> List[Dict[str, Any]]:
        """
        Scan a process's memory maps for suspicious regions.
        Linux only — reads from /proc/<pid>/maps.

        Returns:
            List of detection events.
        """
        maps_path = f"/proc/{pid}/maps"
        detections = []

        if not os.path.exists(maps_path):
            logger.debug("Cannot access %s (process may have exited)", maps_path)
            return detections

        try:
            with open(maps_path, "r") as f:
                maps_content = f.read()
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read %s: %s", maps_path, e)
            return detections

        # ── Detect RWX regions ──────────────────────────────────────────
        for match in RWX_PATTERN.finditer(maps_content):
            start_addr = int(match.group(1), 16)
            end_addr = int(match.group(2), 16)
            region_size = end_addr - start_addr

            if region_size >= MIN_SUSPICIOUS_REGION_SIZE:
                detections.append({
                    "type": "MEMORY_INJECTION",
                    "severity": "critical",
                    "timestamp": "",
                    "data": {
                        "source_pid": 0,
                        "target_pid": pid,
                        "api_call": "rwx_memory_region",
                        "start_address": hex(start_addr),
                        "end_address": hex(end_addr),
                        "region_size": region_size,
                        "description": (
                            f"RWX memory region detected in PID {pid}: "
                            f"{hex(start_addr)}-{hex(end_addr)} ({region_size} bytes)"
                        ),
                    },
                })

        # ── Detect anonymous executable regions ─────────────────────────
        for match in ANON_EXEC_PATTERN.finditer(maps_content):
            start_addr = int(match.group(1), 16)
            end_addr = int(match.group(2), 16)
            region_size = end_addr - start_addr

            if region_size >= MIN_SUSPICIOUS_REGION_SIZE:
                detections.append({
                    "type": "MEMORY_INJECTION",
                    "severity": "high",
                    "timestamp": "",
                    "data": {
                        "source_pid": 0,
                        "target_pid": pid,
                        "api_call": "anonymous_exec_region",
                        "start_address": hex(start_addr),
                        "end_address": hex(end_addr),
                        "region_size": region_size,
                        "description": (
                            f"Anonymous executable memory region in PID {pid}: "
                            f"{hex(start_addr)}-{hex(end_addr)} ({region_size} bytes)"
                        ),
                    },
                })

        if detections:
            logger.info(
                "MemoryTracker found %d suspicious regions in PID %d",
                len(detections), pid,
            )

        return detections

    def analyze_telemetry_events(
        self, telemetry_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze telemetry events for memory injection patterns
        (API-call-based detection, complements /proc/maps scanning).
        """
        detections = []

        for event in telemetry_events:
            evt_type = event.get("type", "")
            data = event.get("data", {})

            # Check for ctypes/dlsym calls to injection APIs
            if evt_type in ("EXECUTION", "PROCESS_CREATE"):
                target = data.get("target", data.get("cmdline", "")).lower()
                for api in INJECTION_APIS:
                    if api in target:
                        detections.append({
                            "type": "MEMORY_INJECTION",
                            "severity": "critical",
                            "timestamp": event.get("timestamp", ""),
                            "data": {
                                "source_pid": data.get("pid", os.getpid()),
                                "target_pid": data.get("target_pid", 0),
                                "api_call": api,
                                "description": f"Injection API call detected: {api}",
                            },
                        })
                        break

        return detections

    def get_memory_summary(self, pid: int) -> Dict[str, Any]:
        """
        Get a summary of a process's memory layout.
        Useful for inclusion in analysis reports.
        """
        maps_path = f"/proc/{pid}/maps"
        summary = {
            "pid": pid,
            "total_regions": 0,
            "rwx_regions": 0,
            "anonymous_exec_regions": 0,
            "total_mapped_size": 0,
        }

        if not os.path.exists(maps_path):
            return summary

        try:
            with open(maps_path, "r") as f:
                for line in f:
                    summary["total_regions"] += 1
                    parts = line.split()
                    if len(parts) >= 2:
                        addr_range = parts[0].split("-")
                        if len(addr_range) == 2:
                            try:
                                size = int(addr_range[1], 16) - int(addr_range[0], 16)
                                summary["total_mapped_size"] += size
                            except ValueError:
                                pass

                        perms = parts[1]
                        if "rwx" in perms:
                            summary["rwx_regions"] += 1
                        if "x" in perms and len(parts) <= 5:
                            summary["anonymous_exec_regions"] += 1
        except (PermissionError, OSError):
            pass

        return summary
