"""
Cross-Job Graph Correlation
=============================
Queries Neo4j for relationships ACROSS analysis jobs to surface:
- Shared IOCs (IPs, domains) between different malware samples
- MITRE technique overlap between samples
- Infrastructure reuse (same C2 across different files)

These queries power the "Related Samples" and "Threat Cluster"
views in the dashboard.
"""

import logging
from typing import List, Dict, Any
from app.database.neo4j import get_neo4j_async_session
from app.services.graph_resilience import neo4j_resilient

logger = logging.getLogger("cross_job_correlation")


@neo4j_resilient(default_return=[])
async def find_related_samples(job_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Find other analysis jobs that share IOCs (IPs, domains) with the given job.
    Returns a list of related jobs with the shared indicators.
    """
    query = """
    MATCH (j1:SandboxJob {job_id: $job_id})-[:PRODUCED_IOC|SPAWNED_PROCESS*1..2]->(shared)
    WHERE shared:IPAddress OR shared:Domain
    MATCH (j2:SandboxJob)-[:PRODUCED_IOC|SPAWNED_PROCESS*1..2]->(shared)
    WHERE j2.job_id <> $job_id
    WITH j2, collect(DISTINCT shared) AS shared_indicators
    RETURN j2.job_id AS related_job_id,
           [s IN shared_indicators | labels(s)[0] + ':' + coalesce(s.address, s.name)] AS shared_iocs,
           size(shared_indicators) AS overlap_count
    ORDER BY overlap_count DESC
    LIMIT $limit
    """
    async with get_neo4j_async_session() as session:
        result = await session.run(query, job_id=job_id, limit=limit)
        records = await result.data()
        return records


@neo4j_resilient(default_return=[])
async def find_technique_overlap(job_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Find other jobs that share MITRE ATT&CK techniques with the given job.
    High technique overlap suggests related malware families.
    """
    query = """
    MATCH (j1:SandboxJob {job_id: $job_id})-[:EXHIBITS_TECHNIQUE]->(t:AttackTechnique)
    WITH j1, collect(t) AS techniques
    MATCH (j2:SandboxJob)-[:EXHIBITS_TECHNIQUE]->(t2:AttackTechnique)
    WHERE j2.job_id <> $job_id AND t2 IN techniques
    WITH j2, collect(DISTINCT t2) AS shared_techniques, size(techniques) AS total
    RETURN j2.job_id AS related_job_id,
           [t IN shared_techniques | t.technique_id] AS shared_technique_ids,
           size(shared_techniques) AS overlap_count,
           total AS source_technique_count,
           toFloat(size(shared_techniques)) / total AS similarity_ratio
    ORDER BY similarity_ratio DESC
    LIMIT $limit
    """
    async with get_neo4j_async_session() as session:
        result = await session.run(query, job_id=job_id, limit=limit)
        records = await result.data()
        return records


@neo4j_resilient(default_return=[])
async def find_infrastructure_clusters(min_shared: int = 2, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Find clusters of samples sharing common network infrastructure.
    Samples using the same C2 IPs or domains are likely from the same
    threat actor or campaign.
    """
    query = """
    MATCH (j1:SandboxJob)-[:PRODUCED_IOC]->(ioc)
    WHERE ioc:IPAddress OR ioc:Domain
    MATCH (j2:SandboxJob)-[:PRODUCED_IOC]->(ioc)
    WHERE j1.job_id < j2.job_id
    WITH j1, j2, collect(DISTINCT ioc) AS shared_infra
    WHERE size(shared_infra) >= $min_shared
    RETURN j1.job_id AS job_a,
           j2.job_id AS job_b,
           [i IN shared_infra | labels(i)[0] + ':' + coalesce(i.address, i.name)] AS shared_infrastructure,
           size(shared_infra) AS shared_count
    ORDER BY shared_count DESC
    LIMIT $limit
    """
    async with get_neo4j_async_session() as session:
        result = await session.run(query, min_shared=min_shared, limit=limit)
        records = await result.data()
        return records


@neo4j_resilient(default_return={})
async def get_job_graph_summary(job_id: str) -> Dict[str, Any]:
    """
    Returns a summary of graph metrics for a job:
    - Node counts by type
    - Relationship counts by type
    - Attack chain length
    """
    query = """
    MATCH (j:SandboxJob {job_id: $job_id})
    OPTIONAL MATCH (j)-[:SPAWNED_PROCESS]->(p:Process)
    OPTIONAL MATCH (j)-[:EXHIBITS_TECHNIQUE]->(t:AttackTechnique)
    OPTIONAL MATCH (j)-[:PRODUCED_IOC]->(ioc)
    OPTIONAL MATCH (j)-[:ANALYZES]->(f:File)
    OPTIONAL MATCH path = (s1:TimelineStage {job_id: $job_id})-[:FOLLOWED_BY*]->(s2:TimelineStage {job_id: $job_id})
    WITH j,
         count(DISTINCT p) AS process_count,
         count(DISTINCT t) AS technique_count,
         count(DISTINCT ioc) AS ioc_count,
         count(DISTINCT f) AS file_count,
         max(length(path)) AS max_chain
    RETURN process_count, technique_count, ioc_count, file_count,
           COALESCE(max_chain + 1, 0) AS chain_length
    """
    async with get_neo4j_async_session() as session:
        result = await session.run(query, job_id=job_id)
        record = await result.single()
        if not record:
            return {}
        return dict(record)
