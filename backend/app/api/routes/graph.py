from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from app.database.neo4j import get_neo4j_async_session
from app.api.dependencies.auth import get_current_user

router = APIRouter()

@router.get("/graph/job/{job_id}", response_model=Dict[str, Any])
async def get_job_graph(job_id: str, user=Depends(get_current_user)):
    """
    Returns the complete execution graph (Process Tree, Files, IPs, ATT&CK) for a given sandbox job.
    Designed to feed directly into Cytoscape.js or D3.js.
    """
    query = """
    MATCH (j:SandboxJob {job_id: $job_id})
    OPTIONAL MATCH (j)-[r1:ANALYZES]->(f:File)
    OPTIONAL MATCH (j)-[r2:SPAWNED_PROCESS]->(p:Process)
    OPTIONAL MATCH (p1:Process {job_id: $job_id})-[r3:SPAWNED]->(p2:Process {job_id: $job_id})
    OPTIONAL MATCH (p3:Process {job_id: $job_id})-[r4:CONNECTED_TO]->(ip:IPAddress)
    OPTIONAL MATCH (j)-[r5:EXHIBITS_TECHNIQUE]->(t:AttackTechnique)
    
    RETURN 
        collect(DISTINCT j) as jobs,
        collect(DISTINCT f) as files,
        collect(DISTINCT p) as processes,
        collect(DISTINCT ip) as ips,
        collect(DISTINCT t) as techniques,
        collect(DISTINCT r1) as r_analyzes,
        collect(DISTINCT r2) as r_spawned_process,
        collect(DISTINCT r3) as r_spawned,
        collect(DISTINCT r4) as r_connected,
        collect(DISTINCT r5) as r_technique
    """
    
    try:
        async with get_neo4j_async_session() as session:
            result = await session.run(query, job_id=job_id)
            record = await result.single()
            
            if not record:
                raise HTTPException(status_code=404, detail="Graph not found for job")
                
            # Transform Neo4j native types to JSON serializable dicts
            nodes = []
            edges = []
            
            def process_node(n, group):
                if n:
                    nodes.append({"data": {"id": str(n.element_id), "group": group, **dict(n)}})
            
            def process_edge(r, label):
                if r:
                    edges.append({"data": {"id": str(r.element_id), "source": str(r.start_node.element_id), "target": str(r.end_node.element_id), "label": label, **dict(r)}})

            for n in record["jobs"]: process_node(n, "SandboxJob")
            for n in record["files"]: process_node(n, "File")
            for n in record["processes"]: process_node(n, "Process")
            for n in record["ips"]: process_node(n, "IPAddress")
            for n in record["techniques"]: process_node(n, "AttackTechnique")
            
            for r in record["r_analyzes"]: process_edge(r, "ANALYZES")
            for r in record["r_spawned_process"]: process_edge(r, "SPAWNED_PROCESS")
            for r in record["r_spawned"]: process_edge(r, "SPAWNED")
            for r in record["r_connected"]: process_edge(r, "CONNECTED_TO")
            for r in record["r_technique"]: process_edge(r, "EXHIBITS_TECHNIQUE")
            
            return {"nodes": nodes, "edges": edges}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/graph/threat-actor/{actor_name}", response_model=Dict[str, Any])
async def get_threat_actor_graph(actor_name: str, user=Depends(get_current_user)):
    """Finds all IPs and Techniques associated with a threat actor based on YARA tags."""
    query = """
    MATCH (y:YARARule {category: $actor_name})<-[:MATCHES_YARA]-(f:File)<-[:ANALYZES]-(j:SandboxJob)
    OPTIONAL MATCH (j)-[:EXHIBITS_TECHNIQUE]->(t:AttackTechnique)
    OPTIONAL MATCH (j)-[:SPAWNED_PROCESS]->(p:Process)-[:CONNECTED_TO]->(ip:IPAddress)
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
            # Simplified output for dashboard aggregate view
            return {
                "associated_files": [dict(n) for n in record["files"]],
                "techniques": [dict(n) for n in record["techniques"]],
                "c2_ips": [dict(n) for n in record["ips"]]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
