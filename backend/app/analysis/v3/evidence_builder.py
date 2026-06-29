"""
Evidence Builder — Transforms EvidenceEnvelope into EvidenceGraph
=================================================================
This is the bridge between the unchanged pipeline (which produces an
EvidenceEnvelope) and V3 (which reasons over an EvidenceGraph).

The builder does NOT score anything.  It only:
  1. Converts raw observations into typed EvidenceNode objects
  2. Links nodes by causal / temporal / corroborative relationships
  3. Computes initial per-node confidence from source reliability
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from app.analysis.evidence_envelope import EvidenceEnvelope
from app.analysis.v3.evidence_node import (
    EvidenceCategory,
    EvidenceNode,
    EvidenceSource,
)
from app.analysis.v3.evidence_graph import EdgeRelation, EvidenceGraph


# ═══════════════════════════════════════════════════════════════════════
# Observation quality heuristics
# ═══════════════════════════════════════════════════════════════════════
# These are NOT scores.  They describe how specific/unambiguous an
# individual observation is, on a [0, 1] scale.

_RUNTIME_QUALITY: Dict[str, float] = {
    "PROCESS_CREATE": 0.80,
    "MEMORY_INJECTION": 0.95,
    "PERSISTENCE_EVENT": 0.90,
    "PRIVILEGE_ESCALATION": 0.90,
    "FILE_WRITE": 0.65,
    "FILE_READ": 0.50,
    "REGISTRY_CREATE": 0.75,
    "REGISTRY_MODIFY": 0.75,
    "SOCKET_CONNECT": 0.85,
    "NETWORK_CONNECT": 0.85,
    "DNS_QUERY": 0.70,
    "HTTP_REQUEST": 0.80,
}

_CATEGORY_FROM_EVENT: Dict[str, EvidenceCategory] = {
    "PROCESS_CREATE": EvidenceCategory.PROCESS_SPAWN,
    "MEMORY_INJECTION": EvidenceCategory.MEMORY_INJECTION,
    "PERSISTENCE_EVENT": EvidenceCategory.PERSISTENCE,
    "PRIVILEGE_ESCALATION": EvidenceCategory.PRIVILEGE_ESCALATION,
    "FILE_WRITE": EvidenceCategory.FILE_OPERATION,
    "FILE_READ": EvidenceCategory.FILE_OPERATION,
    "FILE_CREATE": EvidenceCategory.FILE_OPERATION,
    "FILE_DELETE": EvidenceCategory.FILE_OPERATION,
    "REGISTRY_CREATE": EvidenceCategory.REGISTRY_OPERATION,
    "REGISTRY_MODIFY": EvidenceCategory.REGISTRY_OPERATION,
    "SOCKET_CONNECT": EvidenceCategory.NETWORK_CONNECTION,
    "NETWORK_CONNECT": EvidenceCategory.NETWORK_CONNECTION,
    "DNS_QUERY": EvidenceCategory.DNS_QUERY,
    "HTTP_REQUEST": EvidenceCategory.DATA_EXFILTRATION,
}


class EvidenceBuilder:
    """
    Factory that builds an EvidenceGraph from an EvidenceEnvelope.

    Usage::

        graph = EvidenceBuilder.build(envelope)
        # graph is now a frozen EvidenceGraph ready for inference
    """

    @staticmethod
    def build(envelope: EvidenceEnvelope) -> EvidenceGraph:
        graph = EvidenceGraph()
        builder = _Builder(graph, envelope)

        builder.add_static_evidence()
        builder.add_runtime_evidence()
        builder.add_yara_evidence()
        builder.add_ioc_evidence()
        builder.add_mitre_evidence()
        builder.add_graph_evidence()
        builder.add_capability_evidence()

        builder.link_corroborations()

        # Compute initial confidence for every node
        for node in graph.nodes.values():
            node.compute_initial_confidence()

        graph.freeze()
        return graph


class _Builder:
    """Internal stateful builder (not exposed externally)."""

    def __init__(self, graph: EvidenceGraph, envelope: EvidenceEnvelope) -> None:
        self.graph = graph
        self.env = envelope
        self._process_nodes: Dict[int, str] = {}   # pid → node_id
        self._last_runtime_id: Optional[str] = None

    # ── 1. Static Evidence ─────────────────────────────────────────

    def add_static_evidence(self) -> None:
        s = self.env.static

        if s.is_packed:
            self._add(EvidenceSource.STATIC, EvidenceCategory.STRUCTURAL,
                      "PE binary is packed (high entropy / UPX)", quality=0.85)

        if s.suspicious_apis:
            quality = min(1.0, 0.5 + len(s.suspicious_apis) * 0.08)
            self._add(EvidenceSource.STATIC, EvidenceCategory.STRUCTURAL,
                      f"{len(s.suspicious_apis)} suspicious API imports detected",
                      quality=quality,
                      raw_data={"apis": s.suspicious_apis[:10]})

        if s.max_section_entropy > 7.0 and not s.is_packed:
            self._add(EvidenceSource.STATIC, EvidenceCategory.OBFUSCATION,
                      f"High section entropy ({s.max_section_entropy:.1f})",
                      quality=0.70)

        # String IOCs
        ioc_count = (
            len(s.string_iocs.get("ips", [])) +
            len(s.string_iocs.get("urls", [])) +
            len(s.string_iocs.get("domains", []))
        )
        if ioc_count > 0:
            quality = min(1.0, 0.4 + ioc_count * 0.1)
            self._add(EvidenceSource.STATIC, EvidenceCategory.INDICATOR,
                      f"{ioc_count} IOCs found in binary strings",
                      quality=quality)

        # Python static findings
        for finding in s.python_findings:
            quality = _python_finding_quality(finding)
            self._add(EvidenceSource.STATIC, EvidenceCategory.STRUCTURAL,
                      f"Python static finding: {finding}",
                      quality=quality)

    # ── 2. Runtime Telemetry ───────────────────────────────────────

    def add_runtime_evidence(self) -> None:
        prev_node_id = None

        for event in self._sorted_events():
            evt_type = event.get("type", "")
            data = event.get("data", {})
            timestamp = event.get("timestamp")

            category = _CATEGORY_FROM_EVENT.get(evt_type)
            if category is None:
                continue

            quality = _RUNTIME_QUALITY.get(evt_type, 0.50)
            description = _describe_runtime_event(evt_type, data)

            # Build the node
            node = self._add(
                EvidenceSource.RUNTIME, category, description,
                quality=quality, timestamp=timestamp,
                raw_data={"type": evt_type, **{k: v for k, v in data.items() if k != "raw_bytes"}},
                mitre=_mitre_from_event(evt_type, data),
            )

            # Temporal chaining
            if prev_node_id and node:
                self.graph.add_edge(prev_node_id, node.id, EdgeRelation.TEMPORAL)
            if node:
                prev_node_id = node.id

                # Process tree edges
                pid = data.get("pid")
                ppid = data.get("ppid")
                if pid is not None:
                    self._process_nodes[pid] = node.id
                if ppid is not None and ppid in self._process_nodes:
                    self.graph.add_edge(
                        self._process_nodes[ppid], node.id, EdgeRelation.PARENT_OF
                    )

    # ── 3. YARA Evidence ───────────────────────────────────────────

    def add_yara_evidence(self) -> None:
        for match in self.env.detections.yara_matches:
            rule = match.get("rule", "unknown")
            meta = match.get("meta", {})
            tags = match.get("tags", [])

            quality = _yara_quality(rule, meta, tags)
            self._add(
                EvidenceSource.YARA, EvidenceCategory.SIGNATURE_MATCH,
                f"YARA rule matched: {rule}",
                quality=quality,
                raw_data={"rule": rule, "meta": meta, "tags": tags},
            )

    # ── 4. IOC Evidence ────────────────────────────────────────────

    def add_ioc_evidence(self) -> None:
        seen: Set[str] = set()

        for ioc in self.env.iocs.iocs:
            value = ioc.get("value", "")
            ioc_type = ioc.get("type", "")
            confidence_label = ioc.get("confidence", "Low")
            source_str = ioc.get("source", "")

            if not value or value in seen:
                continue
            seen.add(value)

            # Skip sample's own hash
            if ioc_type in ("sha256", "md5") and "Static Analysis (Hash)" in source_str:
                continue

            quality = {"High": 0.90, "Medium": 0.60, "Low": 0.30}.get(confidence_label, 0.30)

            self._add(
                EvidenceSource.IOC, EvidenceCategory.INDICATOR,
                f"IOC [{ioc_type}]: {value[:60]}",
                quality=quality,
                raw_data={"type": ioc_type, "value": value, "confidence": confidence_label},
            )

    # ── 5. MITRE Evidence ──────────────────────────────────────────

    def add_mitre_evidence(self) -> None:
        seen: Set[str] = set()

        for tech in self.env.detections.mitre_techniques:
            tech_id = tech.get("id", "")
            if tech_id in seen:
                continue
            seen.add(tech_id)

            tech_name = tech.get("name", tech_id)
            tactic = tech.get("tactic", tech.get("evidence", ""))

            quality = _mitre_technique_quality(tech_id, tactic)
            self._add(
                EvidenceSource.MITRE, EvidenceCategory.TECHNIQUE,
                f"MITRE {tech_id}: {tech_name}",
                quality=quality,
                raw_data=tech,
                mitre=[tech_id],
            )

    # ── 6. Graph Evidence ──────────────────────────────────────────

    def add_graph_evidence(self) -> None:
        g = self.env.graph

        if g.chain_length > 0:
            # Quality increases with chain length (more complex = more suspicious)
            quality = min(1.0, 0.5 + g.chain_length * 0.1)
            self._add(
                EvidenceSource.GRAPH, EvidenceCategory.GRAPH_METRIC,
                f"Attack chain length: {g.chain_length} stages",
                quality=quality,
                raw_data={"chain_length": g.chain_length},
            )

        if g.has_c2_persistence:
            self._add(
                EvidenceSource.GRAPH, EvidenceCategory.GRAPH_METRIC,
                "Graph shows C2 + Persistence co-occurrence",
                quality=0.90,
                raw_data={"has_c2_persistence": True},
            )

    # ── 7. Capability Evidence ─────────────────────────────────────

    def add_capability_evidence(self) -> None:
        """
        Convert V2 capabilities into evidence nodes.  This bridges the
        existing CapabilityEngine output into the V3 graph.
        """
        for cap in self.env.capabilities:
            category = _category_from_capability(cap.capability)
            quality = cap.confidence / 100.0   # V2 confidence is 0–100

            node = self._add(
                EvidenceSource.RUNTIME, category,
                f"Capability: {cap.capability} ({cap.attack_goal})",
                quality=quality,
                raw_data={"capability": cap.capability, "severity": cap.severity},
                mitre=cap.mitre_mapping,
            )

    # ── 8. Cross-source corroboration ──────────────────────────────

    def link_corroborations(self) -> None:
        """
        Find nodes from different sources that describe the same
        observation and link them with CORROBORATES edges.
        """
        nodes = list(self.graph.nodes.values())

        # Group nodes by category
        by_category: Dict[EvidenceCategory, List[EvidenceNode]] = {}
        for n in nodes:
            by_category.setdefault(n.category, []).append(n)

        # Within each category, link nodes from different sources
        for cat, cat_nodes in by_category.items():
            sources_seen: Dict[EvidenceSource, List[EvidenceNode]] = {}
            for n in cat_nodes:
                sources_seen.setdefault(n.source, []).append(n)

            if len(sources_seen) < 2:
                continue  # No cross-source corroboration possible

            # Link each pair of different-source nodes
            source_groups = list(sources_seen.values())
            for i, group_a in enumerate(source_groups):
                for group_b in source_groups[i + 1:]:
                    for a in group_a[:3]:       # cap to avoid O(n²) explosion
                        for b in group_b[:3]:
                            self.graph.add_edge(a.id, b.id, EdgeRelation.CORROBORATES)
                            a.supporting_observations.append(b.id)
                            b.supporting_observations.append(a.id)

    # ── Helpers ────────────────────────────────────────────────────

    def _add(
        self,
        source: EvidenceSource,
        category: EvidenceCategory,
        description: str,
        quality: float = 0.50,
        raw_data: Optional[Dict] = None,
        timestamp: Optional[str] = None,
        mitre: Optional[List[str]] = None,
    ) -> Optional[EvidenceNode]:
        node = EvidenceNode(
            source=source,
            category=category,
            description=description,
            observation_quality=quality,
            raw_data=raw_data or {},
            timestamp=timestamp,
            mitre_techniques=mitre or [],
        )
        self.graph.add_node(node)
        return node

    def _sorted_events(self) -> list:
        return sorted(
            [e for e in [
                *self.env.runtime.process_events,
                *self.env.runtime.network_events,
                *self.env.runtime.dns_events,
                *self.env.runtime.file_events,
                *self.env.runtime.registry_events,
                *self.env.runtime.memory_injection_events,
                *self.env.runtime.persistence_events,
                *self.env.runtime.privilege_escalation_events,
            ] if e],
            key=lambda e: e.get("timestamp", ""),
        )


# ═══════════════════════════════════════════════════════════════════════
# Quality heuristics (pure functions)
# ═══════════════════════════════════════════════════════════════════════

def _python_finding_quality(finding: str) -> float:
    """Quality of a Python static analysis finding."""
    high = {"EXEC_USAGE", "SUBPROCESS_USAGE", "POWERSHELL_USAGE", "REGISTRY_USAGE"}
    medium = {"NETWORK_USAGE", "BASE64_USAGE", "SOCKET_USAGE"}
    if finding in high:
        return 0.80
    if finding in medium:
        return 0.65
    return 0.50


def _describe_runtime_event(evt_type: str, data: dict) -> str:
    """Human-readable description of a telemetry event."""
    if evt_type == "PROCESS_CREATE":
        cmd = data.get("cmdline", data.get("target", ""))
        name = data.get("name", data.get("executable", ""))
        return f"Process spawned: {name} {str(cmd)[:80]}"
    elif evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
        return f"Network connection to {data.get('dest_ip', '')}:{data.get('dest_port', '')}"
    elif evt_type == "DNS_QUERY":
        return f"DNS query: {data.get('query', '')}"
    elif evt_type in ("FILE_WRITE", "FILE_CREATE"):
        return f"File written: {data.get('path', data.get('filename', ''))}"
    elif evt_type in ("REGISTRY_CREATE", "REGISTRY_MODIFY"):
        return f"Registry modified: {data.get('key', '')}"
    elif evt_type == "MEMORY_INJECTION":
        return f"Memory injection via {data.get('api_call', 'unknown')}"
    elif evt_type == "PERSISTENCE_EVENT":
        return f"Persistence established: {data.get('mechanism', '')} → {data.get('target', '')}"
    elif evt_type == "PRIVILEGE_ESCALATION":
        return f"Privilege escalation: {data.get('technique', '')}"
    elif evt_type == "HTTP_REQUEST":
        return f"HTTP {data.get('method', '?')} {data.get('url', '')[:60]}"
    return f"{evt_type}: {str(data)[:60]}"


def _mitre_from_event(evt_type: str, data: dict) -> List[str]:
    """Extract likely MITRE techniques from a telemetry event."""
    cmd = str(data.get("cmdline", "") or data.get("target", "")).lower()
    techniques = []

    if evt_type == "PROCESS_CREATE":
        if "powershell" in cmd:
            techniques.append("T1059.001")
        if "cmd.exe" in cmd or "cmd /c" in cmd:
            techniques.append("T1059.003")
        if "schtasks" in cmd and "/create" in cmd:
            techniques.append("T1053.005")
        if "vssadmin" in cmd and "delete" in cmd:
            techniques.append("T1490")
    elif evt_type == "MEMORY_INJECTION":
        techniques.append("T1055")
    elif evt_type == "PERSISTENCE_EVENT":
        techniques.append("T1547.001")
    elif evt_type == "PRIVILEGE_ESCALATION":
        techniques.append("T1548")

    return techniques


def _yara_quality(rule: str, meta: dict, tags: list) -> float:
    """
    Quality of a YARA match.  High-confidence, specific rules get high quality.
    Generic or noisy rules get lower quality.
    """
    rule_lower = rule.lower()

    # APT / highly specific rules
    if any(kw in rule_lower for kw in ["apt", "ransomware", "cobalt", "lockbit", "emotet"]):
        return 0.95
    # Malware family rules
    if any(kw in rule_lower for kw in ["trojan", "backdoor", "rat", "stealer", "miner"]):
        return 0.85
    # Suspicious indicators
    if any(kw in rule_lower for kw in ["suspicious", "packed", "obfuscated"]):
        return 0.65
    # Generic / catch-all
    return 0.50


def _mitre_technique_quality(tech_id: str, tactic: str) -> float:
    """
    Quality of a MITRE technique observation.
    Impact / Exfiltration tactics are more definitive than Discovery / Execution.
    """
    high_impact = {"Impact", "Exfiltration", "Credential Access", "Lateral Movement"}
    medium_impact = {"Command and Control", "Defense Evasion", "Persistence", "Privilege Escalation"}
    if tactic in high_impact:
        return 0.90
    if tactic in medium_impact:
        return 0.75
    return 0.60


def _category_from_capability(cap_name: str) -> EvidenceCategory:
    """Map V2 capability name to V3 evidence category."""
    mapping = {
        "Process Injection": EvidenceCategory.MEMORY_INJECTION,
        "Obfuscation": EvidenceCategory.OBFUSCATION,
        "Obfuscated Execution": EvidenceCategory.OBFUSCATION,
        "Dynamic API Resolution": EvidenceCategory.DEFENSE_EVASION,
        "Input Capture": EvidenceCategory.CREDENTIAL_ACCESS,
        "PowerShell Invocation": EvidenceCategory.PROCESS_SPAWN,
        "Encoded Script Execution": EvidenceCategory.OBFUSCATION,
        "Command Shell Execution": EvidenceCategory.PROCESS_SPAWN,
        "Script Host Execution": EvidenceCategory.PROCESS_SPAWN,
        "Subprocess Execution": EvidenceCategory.PROCESS_SPAWN,
        "Persistence": EvidenceCategory.PERSISTENCE,
        "System Information Discovery": EvidenceCategory.DISCOVERY,
        "Ingress Tool Transfer": EvidenceCategory.NETWORK_CONNECTION,
        "Suspicious Script Execution": EvidenceCategory.PROCESS_SPAWN,
        "Shadow Copy Deletion": EvidenceCategory.ENCRYPTION,
        "File Encryption": EvidenceCategory.ENCRYPTION,
        "Credential Access": EvidenceCategory.CREDENTIAL_ACCESS,
        "Session Theft": EvidenceCategory.CREDENTIAL_ACCESS,
        "Token Theft": EvidenceCategory.CREDENTIAL_ACCESS,
        "Cryptocurrency Theft": EvidenceCategory.CREDENTIAL_ACCESS,
        "Screen Capture": EvidenceCategory.COLLECTION,
        "Webcam Capture": EvidenceCategory.COLLECTION,
        "Data Staging": EvidenceCategory.COLLECTION,
        "Defense Evasion": EvidenceCategory.DEFENSE_EVASION,
        "Data Exfiltration": EvidenceCategory.DATA_EXFILTRATION,
        "Network Communication": EvidenceCategory.NETWORK_CONNECTION,
        "Registry Access": EvidenceCategory.REGISTRY_OPERATION,
        "Privilege Escalation": EvidenceCategory.PRIVILEGE_ESCALATION,
    }
    return mapping.get(cap_name, EvidenceCategory.STRUCTURAL)
