"""
Evidence Graph — Immutable Directed Graph of Evidence Nodes
============================================================
The single data structure that V3 reasoning operates on.  Every
subsystem contributes evidence nodes; edges represent causal,
temporal, or corroborative relationships.

The graph is append-only during construction (via EvidenceBuilder)
and read-only once passed to the inference layers.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from app.analysis.v3.evidence_node import EvidenceCategory, EvidenceNode, EvidenceSource


# ═══════════════════════════════════════════════════════════════════════
# Edge types
# ═══════════════════════════════════════════════════════════════════════

class EdgeRelation:
    """Semantic edge labels linking evidence nodes."""
    CAUSED = "caused"               # A directly caused B
    TEMPORAL = "temporal"           # A happened before B
    CORROBORATES = "corroborates"   # A supports the same conclusion as B
    DEPENDS_ON = "depends_on"       # A requires B to be meaningful
    PARENT_OF = "parent_of"         # Process tree ancestry


@dataclass(frozen=True)
class EvidenceEdge:
    """Directed edge between two evidence nodes."""
    from_id: str
    to_id: str
    relation: str


# ═══════════════════════════════════════════════════════════════════════
# Evidence Graph
# ═══════════════════════════════════════════════════════════════════════

class EvidenceGraph:
    """
    Directed graph of evidence nodes with structural query methods.

    Construction pattern::

        graph = EvidenceGraph()
        graph.add_node(node_a)
        graph.add_node(node_b)
        graph.add_edge(node_a.id, node_b.id, EdgeRelation.CAUSED)
        graph.freeze()   # optional — signals end of construction
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, EvidenceNode] = {}
        self._edges: List[EvidenceEdge] = []
        self._adj: Dict[str, List[str]] = defaultdict(list)      # forward adjacency
        self._rev_adj: Dict[str, List[str]] = defaultdict(list)   # reverse adjacency
        self._frozen = False

    # ── Construction ───────────────────────────────────────────────

    def add_node(self, node: EvidenceNode) -> None:
        if self._frozen:
            raise RuntimeError("Cannot add to a frozen EvidenceGraph")
        self._nodes[node.id] = node

    def add_edge(self, from_id: str, to_id: str, relation: str) -> None:
        if self._frozen:
            raise RuntimeError("Cannot add to a frozen EvidenceGraph")
        edge = EvidenceEdge(from_id=from_id, to_id=to_id, relation=relation)
        self._edges.append(edge)
        self._adj[from_id].append(to_id)
        self._rev_adj[to_id].append(from_id)

    def freeze(self) -> None:
        self._frozen = True

    # ── Node access ────────────────────────────────────────────────

    @property
    def nodes(self) -> Dict[str, EvidenceNode]:
        return self._nodes

    @property
    def edges(self) -> List[EvidenceEdge]:
        return self._edges

    def get_node(self, node_id: str) -> Optional[EvidenceNode]:
        return self._nodes.get(node_id)

    def get_children(self, node_id: str) -> List[EvidenceNode]:
        """Get all nodes that this node points to (forward edges)."""
        return [self._nodes[cid] for cid in self._adj.get(node_id, []) if cid in self._nodes]

    def get_parents(self, node_id: str) -> List[EvidenceNode]:
        """Get all nodes that point to this node (reverse edges)."""
        return [self._nodes[pid] for pid in self._rev_adj.get(node_id, []) if pid in self._nodes]

    # ── Filtered queries ───────────────────────────────────────────

    def get_nodes_by_source(self, source: EvidenceSource) -> List[EvidenceNode]:
        return [n for n in self._nodes.values() if n.source == source]

    def get_nodes_by_category(self, category: EvidenceCategory) -> List[EvidenceNode]:
        return [n for n in self._nodes.values() if n.category == category]

    def get_leaf_nodes(self) -> List[EvidenceNode]:
        """Nodes with no outgoing edges (terminal observations)."""
        return [n for nid, n in self._nodes.items() if not self._adj.get(nid)]

    def get_root_nodes(self) -> List[EvidenceNode]:
        """Nodes with no incoming edges (initial observations)."""
        return [n for nid, n in self._nodes.items() if not self._rev_adj.get(nid)]

    # ── Graph metrics ──────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def depth(self) -> int:
        """Longest path length in the graph (via BFS from each root)."""
        if not self._nodes:
            return 0
        max_depth = 0
        for root in self.get_root_nodes():
            visited: Set[str] = set()
            queue: deque = deque([(root.id, 0)])
            while queue:
                nid, d = queue.popleft()
                if nid in visited:
                    continue
                visited.add(nid)
                max_depth = max(max_depth, d)
                for child_id in self._adj.get(nid, []):
                    if child_id not in visited:
                        queue.append((child_id, d + 1))
        return max_depth

    def width(self) -> int:
        """Max number of nodes at any single depth level."""
        if not self._nodes:
            return 0
        level_counts: Dict[int, int] = defaultdict(int)
        for root in self.get_root_nodes():
            visited: Set[str] = set()
            queue: deque = deque([(root.id, 0)])
            while queue:
                nid, d = queue.popleft()
                if nid in visited:
                    continue
                visited.add(nid)
                level_counts[d] += 1
                for child_id in self._adj.get(nid, []):
                    if child_id not in visited:
                        queue.append((child_id, d + 1))
        return max(level_counts.values()) if level_counts else 0

    def branching_factor(self) -> float:
        """Average out-degree of nodes that have at least one child."""
        parents = [nid for nid in self._nodes if self._adj.get(nid)]
        if not parents:
            return 0.0
        return sum(len(self._adj[nid]) for nid in parents) / len(parents)

    def connected_components(self) -> int:
        """Number of weakly connected components (treating edges as undirected)."""
        visited: Set[str] = set()
        components = 0
        for nid in self._nodes:
            if nid in visited:
                continue
            components += 1
            queue: deque = deque([nid])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                for neighbor in self._adj.get(current, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
                for neighbor in self._rev_adj.get(current, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
        return components

    def edge_density(self) -> float:
        """Ratio of actual edges to maximum possible edges."""
        n = len(self._nodes)
        if n <= 1:
            return 0.0
        max_edges = n * (n - 1)
        return len(self._edges) / max_edges

    def source_diversity(self) -> int:
        """Number of distinct evidence sources contributing nodes."""
        return len({n.source for n in self._nodes.values()})

    def tactic_diversity(self) -> int:
        """Number of distinct MITRE tactic categories across all nodes."""
        tactics: Set[str] = set()
        for node in self._nodes.values():
            for tech in node.mitre_techniques:
                # Extract tactic from the category mapping
                tactics.add(node.category.value)
        return len(tactics)

    # ── Causal chain discovery ─────────────────────────────────────

    def find_all_maximal_paths(self) -> List[List[str]]:
        """
        Find all maximal directed paths (from roots to leaves).
        A maximal path is one that cannot be extended in either direction.
        """
        paths: List[List[str]] = []
        roots = self.get_root_nodes()

        if not roots:
            # Fallback: start from all nodes with no parents
            roots = [n for nid, n in self._nodes.items() if not self._rev_adj.get(nid)]
            if not roots:
                roots = list(self._nodes.values())[:1]

        for root in roots:
            self._dfs_paths(root.id, [root.id], set(), paths)

        return paths

    def _dfs_paths(
        self,
        current: str,
        path: List[str],
        visited: Set[str],
        results: List[List[str]],
    ) -> None:
        """DFS to collect maximal paths."""
        children = [cid for cid in self._adj.get(current, []) if cid not in visited]
        if not children:
            # Maximal path (leaf or all children visited)
            if len(path) >= 2:
                results.append(list(path))
            return

        for child_id in children:
            visited.add(child_id)
            path.append(child_id)
            self._dfs_paths(child_id, path, visited, results)
            path.pop()
            visited.discard(child_id)

    def get_causal_chain(self, from_id: str, to_id: str) -> Optional[List[str]]:
        """BFS shortest path between two nodes."""
        if from_id not in self._nodes or to_id not in self._nodes:
            return None
        visited: Set[str] = set()
        queue: deque = deque([(from_id, [from_id])])
        while queue:
            current, path = queue.popleft()
            if current == to_id:
                return path
            if current in visited:
                continue
            visited.add(current)
            for child_id in self._adj.get(current, []):
                if child_id not in visited:
                    queue.append((child_id, path + [child_id]))
        return None

    # ── Serialization ──────────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [
                {"from": e.from_id, "to": e.to_id, "relation": e.relation}
                for e in self._edges
            ],
            "metrics": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "depth": self.depth(),
                "width": self.width(),
                "branching_factor": round(self.branching_factor(), 2),
                "connected_components": self.connected_components(),
                "edge_density": round(self.edge_density(), 4),
                "source_diversity": self.source_diversity(),
            },
        }
