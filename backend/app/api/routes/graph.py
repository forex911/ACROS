"""
Graph API Routes — Hardened with resilience
=============================================
Returns graph data for the frontend visualization layer.
All routes handle Neo4j unavailability gracefully.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from app.database.neo4j import get_neo4j_async_session
from app.api.dependencies.auth import get_current_user
from app.models.graph_schema import RelType, ARTIFACT_RELS
from app.services.graph_resilience import is_neo4j_available
from app.services.cross_job_correlation import (
    find_related_samples,
    find_technique_overlap,
    find_infrastructure_clusters,
    get_job_graph_summary,
)
import logging

logger = logging.getLogger("graph_routes")

router = APIRouter()


@router.get("/graph/health")
async def graph_health():
    """Check if the graph database is reachable."""
    available = await is_neo4j_available()
    return {
        "neo4j_available": available,
        "status": "healthy" if available else "degraded",
        "message": "Graph features are available" if available else "Graph features are offline — analysis continues without graph correlation",
    }


@router.get("/graph/job/{job_id}", response_model=Dict[str, Any])
async def get_job_graph(job_id: str, user=Depends(get_current_user)):
    """
    Returns the complete execution graph (Process Tree, Files, IPs, ATT&CK) for a given sandbox job.
    Designed to feed directly into Cytoscape.js or D3.js.
    """
    if not await is_neo4j_available():
        return {"nodes": [], "edges": [], "status": "neo4j_unavailable"}

    artifact_rels_str = "|".join(ARTIFACT_RELS)

    query = f"""
    MATCH (j:SandboxJob {{job_id: $job_id}})
    OPTIONAL MATCH (j)-[r1:{RelType.ANALYZES}]->(f:File)
    OPTIONAL MATCH (j)-[r2:{RelType.SPAWNED_PROCESS}]->(p:Process)
    OPTIONAL MATCH (p1:Process {{job_id: $job_id}})-[r3:{RelType.SPAWNED}]->(p2:Process {{job_id: $job_id}})
    OPTIONAL MATCH (p3:Process {{job_id: $job_id}})-[r4:{RelType.CONNECTED_TO}]->(ip:IPAddress)
    OPTIONAL MATCH (j)-[r5:{RelType.EXHIBITS_TECHNIQUE}]->(t:AttackTechnique)

    // Find all files connected through artifact relationships starting from the initially analyzed file
    OPTIONAL MATCH path=(f)-[:{artifact_rels_str}*1..5]->(f_desc:File)

    RETURN
        collect(DISTINCT j) as jobs,
        collect(DISTINCT f) + collect(DISTINCT f_desc) as files,
        collect(DISTINCT p) as processes,
        collect(DISTINCT ip) as ips,
        collect(DISTINCT t) as techniques,
        collect(DISTINCT r1) as r_analyzes,
        collect(DISTINCT r2) as r_spawned_process,
        collect(DISTINCT r3) as r_spawned,
        collect(DISTINCT r4) as r_connected,
        collect(DISTINCT r5) as r_technique,
        collect(path) as artifact_paths
    """

    try:
        async with get_neo4j_async_session() as session:
            result = await session.run(query, job_id=job_id)
            record = await result.single()

            if not record:
                raise HTTPException(status_code=404, detail="Graph not found for job")

            nodes = []
            edges = []

            def process_node(n, group):
                if n is not None:
                    nodes.append({"data": {"id": str(n.element_id), "group": group, **dict(n)}})

            def process_edge(r, label):
                if r is not None:
                    edges.append({"data": {"id": str(r.element_id), "source": str(r.start_node.element_id), "target": str(r.end_node.element_id), "label": label, **dict(r)}})

            for n in record["jobs"]: process_node(n, "SandboxJob")

            files = []
            for item in record["files"]:
                if isinstance(item, list):
                    files.extend(item)
                elif item:
                    files.append(item)

            for n in files: process_node(n, "File")
            for n in record["processes"]: process_node(n, "Process")
            for n in record["ips"]: process_node(n, "IPAddress")
            for n in record["techniques"]: process_node(n, "AttackTechnique")

            for r in record["r_analyzes"]: process_edge(r, RelType.ANALYZES)
            for r in record["r_spawned_process"]: process_edge(r, RelType.SPAWNED_PROCESS)
            for r in record["r_spawned"]: process_edge(r, RelType.SPAWNED)
            for r in record["r_connected"]: process_edge(r, RelType.CONNECTED_TO)
            for r in record["r_technique"]: process_edge(r, RelType.EXHIBITS_TECHNIQUE)

            for path in record["artifact_paths"]:
                if path:
                    for r in path.relationships:
                        process_edge(r, getattr(r, 'type', 'RELATED_TO'))

            return {"nodes": nodes, "edges": edges}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[GraphRoutes] Failed to get job graph: {e}", exc_info=True)
        return {"nodes": [], "edges": [], "error": str(e)}


@router.get("/graph/threat-actor/{actor_name}", response_model=Dict[str, Any])
async def get_threat_actor_graph(actor_name: str, user=Depends(get_current_user)):
    """Finds all IPs and Techniques associated with a threat actor based on YARA tags."""
    if not await is_neo4j_available():
        return {"associated_files": [], "techniques": [], "c2_ips": [], "status": "neo4j_unavailable"}

    query = f"""
    MATCH (y:YARARule {{category: $actor_name}})<-[:{RelType.MATCHES_YARA}]-(f:File)<-[:{RelType.ANALYZES}]-(j:SandboxJob)
    OPTIONAL MATCH (j)-[:{RelType.EXHIBITS_TECHNIQUE}]->(t:AttackTechnique)
    OPTIONAL MATCH (j)-[:{RelType.SPAWNED_PROCESS}]->(p:Process)-[:{RelType.CONNECTED_TO}]->(ip:IPAddress)
    RETURN
        collect(DISTINCT y) as yara,
        collect(DISTINCT f) as files,
        collect(DISTINCT t) as techniques,
        collect(DISTINCT ip) as ips
    """

    try:
        async with get_neo4j_async_session() as session:
            result = await session.run(query, actor_name=actor_name)
            record = await result.single()
            return {
                "associated_files": [dict(n) for n in record["files"]],
                "techniques": [dict(n) for n in record["techniques"]],
                "c2_ips": [dict(n) for n in record["ips"]]
            }
    except Exception as e:
        logger.error(f"[GraphRoutes] Threat actor query failed: {e}", exc_info=True)
        return {"associated_files": [], "techniques": [], "c2_ips": [], "error": str(e)}


# ── Cross-Job Correlation Routes ──────────────────────────────────────────────

@router.get("/graph/related/{job_id}")
async def get_related_samples(job_id: str, user=Depends(get_current_user)):
    """Find other jobs that share IOCs with this job."""
    return {"related": await find_related_samples(job_id)}


@router.get("/graph/technique-overlap/{job_id}")
async def get_technique_overlap(job_id: str, user=Depends(get_current_user)):
    """Find other jobs that share MITRE techniques with this job."""
    return {"overlapping": await find_technique_overlap(job_id)}


@router.get("/graph/clusters")
async def get_infrastructure_clusters(user=Depends(get_current_user)):
    """Find clusters of samples sharing C2 infrastructure."""
    return {"clusters": await find_infrastructure_clusters()}


@router.get("/graph/summary/{job_id}")
async def get_graph_summary(job_id: str, user=Depends(get_current_user)):
    """Graph metrics summary for a specific job."""
    return await get_job_graph_summary(job_id)
