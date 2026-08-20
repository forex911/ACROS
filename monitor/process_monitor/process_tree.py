"""
Process Tree — Hierarchical Process Tracking and Analysis

Builds and maintains a process tree from exec/fork/clone events.
Detects suspicious parent-child relationships that indicate:
- Shell injection chains (python → bash → curl)
- Privilege escalation attempts
- Living-off-the-land binary (LOLBin) usage
- Unusual process ancestry

Emits SUSPICIOUS_PROCESS_TREE events with relationship context.
"""

import os
import logging
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger("process_tree")

# ── Suspicious process chains ───────────────────────────────────────────────
# Format: (parent_pattern, child_pattern, description, severity)
SUSPICIOUS_CHAINS = [
    ("python", "bash", "Script interpreter spawned shell", "high"),
    ("python", "sh", "Script interpreter spawned shell", "high"),
    ("python", "curl", "Script interpreter spawned download tool", "high"),
    ("python", "wget", "Script interpreter spawned download tool", "high"),
    ("python", "powershell", "Script interpreter spawned PowerShell", "critical"),
    ("python", "cmd", "Script interpreter spawned command prompt", "high"),
    ("node", "bash", "Node.js spawned shell", "high"),
    ("node", "sh", "Node.js spawned shell", "high"),
    ("node", "curl", "Node.js spawned download tool", "high"),
    ("bash", "python", "Shell spawned script interpreter", "medium"),
    ("bash", "nc", "Shell spawned netcat (potential reverse shell)", "critical"),
    ("bash", "ncat", "Shell spawned ncat (potential reverse shell)", "critical"),
    ("bash", "socat", "Shell spawned socat (potential reverse shell)", "critical"),
    ("sh", "nc", "Shell spawned netcat", "critical"),
    ("cmd", "powershell", "CMD spawned PowerShell", "high"),
    ("powershell", "cmd", "PowerShell spawned CMD", "medium"),
    ("excel", "cmd", "Office app spawned command prompt", "critical"),
    ("winword", "cmd", "Office app spawned command prompt", "critical"),
    ("winword", "powershell", "Office app spawned PowerShell", "critical"),
]

# ── LOLBins (Living Off the Land Binaries) ──────────────────────────────────
LOLBINS = {
    "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
    "cscript", "wscript", "msiexec", "forfiles", "pcalua",
    "cmstp", "esentutl", "expand", "extrac32", "findstr",
    "hh", "ie4uinit", "ieexec", "infdefaultinstall",
    "installutil", "mavinject", "msdeploy", "msdt",
    "msiexec", "netsh", "odbcconf", "presentationhost",
    # Linux LOLBins
    "curl", "wget", "nc", "ncat", "socat", "openssl",
    "base64", "xxd", "dd", "perl", "ruby", "lua",
}


class ProcessTree:
    """
    Builds a hierarchical process tree from telemetry events and detects
    suspicious parent-child process relationships.
    """

    def __init__(self):
        # pid -> process info dict
        self._processes: Dict[int, Dict[str, Any]] = {}
        # pid -> set of child pids
        self._children: Dict[int, Set[int]] = {}
        logger.info("ProcessTree initialized")

    def add_process(self, pid: int, ppid: int, executable: str, cmdline: str = "") -> None:
        """Register a new process in the tree."""
        self._processes[pid] = {
            "pid": pid,
            "ppid": ppid,
            "executable": executable,
            "cmdline": cmdline,
            "basename": os.path.basename(executable).lower() if executable else "",
        }

        if ppid not in self._children:
            self._children[ppid] = set()
        self._children[ppid].add(pid)

    def build_from_telemetry(self, telemetry_events: List[Dict[str, Any]]) -> None:
        """Populate the process tree from telemetry PROCESS_CREATE events."""
        for event in telemetry_events:
            if event.get("type") != "PROCESS_CREATE":
                continue

            data = event.get("data", {})
            pid = data.get("pid", 0)
            ppid = data.get("ppid", 0)
            executable = data.get("executable", data.get("name", ""))
            cmdline = data.get("cmdline", "")

            # Extract executable from cmdline if not provided
            if not executable and cmdline:
                parts = cmdline.split()
                executable = parts[0] if parts else ""

            if pid or cmdline:
                self.add_process(pid, ppid, executable, cmdline)

    def detect_suspicious_chains(self) -> List[Dict[str, Any]]:
        """
        Analyze the process tree for suspicious parent-child relationships.

        Returns:
            List of SUSPICIOUS_PROCESS_TREE detection events.
        """
        detections = []

        for pid, proc_info in self._processes.items():
            ppid = proc_info["ppid"]
            parent_info = self._processes.get(ppid)

            if not parent_info:
                continue

            parent_name = parent_info["basename"]
            child_name = proc_info["basename"]

            # ── Check known suspicious chains ───────────────────────────
            for parent_pat, child_pat, description, severity in SUSPICIOUS_CHAINS:
                if parent_pat in parent_name and child_pat in child_name:
                    detections.append({
                        "type": "SUSPICIOUS_PROCESS_TREE",
                        "severity": severity,
                        "timestamp": "",
                        "data": {
                            "parent_pid": ppid,
                            "parent_executable": parent_info["executable"],
                            "child_pid": pid,
                            "child_executable": proc_info["executable"],
                            "chain": f"{parent_name} → {child_name}",
                            "description": description,
                        },
                    })

            # ── Check LOLBin usage ──────────────────────────────────────
            if child_name in LOLBINS:
                detections.append({
                    "type": "SUSPICIOUS_PROCESS_TREE",
                    "severity": "high",
                    "timestamp": "",
                    "data": {
                        "parent_pid": ppid,
                        "parent_executable": parent_info["executable"],
                        "child_pid": pid,
                        "child_executable": proc_info["executable"],
                        "chain": f"{parent_name} → {child_name}",
                        "description": f"LOLBin usage detected: {child_name}",
                        "lolbin": child_name,
                    },
                })

        # Deduplicate
        seen = set()
        unique = []
        for d in detections:
            key = d["data"]["chain"]
            if key not in seen:
                seen.add(key)
                unique.append(d)

        if unique:
            logger.info("ProcessTree detected %d suspicious chains", len(unique))

        return unique

    def get_tree_dict(self) -> Dict[int, Dict[str, Any]]:
        """Return the full process tree as a dict."""
        result = {}
        for pid, info in self._processes.items():
            entry = dict(info)
            entry["children"] = list(self._children.get(pid, set()))
            result[pid] = entry
        return result

    def get_ancestry(self, pid: int, max_depth: int = 10) -> List[Dict[str, Any]]:
        """Walk up the process tree to get the full ancestry of a PID."""
        ancestry = []
        current = pid
        depth = 0

        while current in self._processes and depth < max_depth:
            ancestry.append(self._processes[current])
            current = self._processes[current]["ppid"]
            depth += 1

        return list(reversed(ancestry))

    def get_depth(self) -> int:
        """Return the maximum depth of the process tree."""
        if not self._processes:
            return 0

        def _depth(pid, visited=None):
            if visited is None:
                visited = set()
            if pid in visited:
                return 0
            visited.add(pid)
            children = self._children.get(pid, set())
            if not children:
                return 1
            return 1 + max(_depth(c, visited) for c in children)

        # Find root processes (ppid not in tree)
        roots = [
            pid for pid, info in self._processes.items()
            if info["ppid"] not in self._processes
        ]

        if not roots:
            return 1

        return max(_depth(r) for r in roots)
