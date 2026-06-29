"""
Graph-Assisted Correlation Scorer
==================================
Queries Neo4j for attack chain topology to generate a correlation bonus.
Complex attack chains (Process → DNS → Network → File Drop → Persistence)
increase scoring confidence.
"""

import logging
from typing import Tuple, List
from app.database.neo4j import get_neo4j_async_session
from app.services.graph_resilience import neo4j_resilient

logger = logging.getLogger("graph_scorer")

# Chain length → bonus points
CHAIN_BONUS = {
    3: 5,
    4: 8,
    5: 12,
}

# Extra bonus if graph contains both C2 and Persistence indicators
C2_PERSISTENCE_BONUS = 15


@neo4j_resilient(default_return=(0, 0, False, ["Graph scoring skipped: Neo4j unavailable"]))
async def score_graph_correlation(job_id: str) -> Tuple[int, int, bool, List[str]]:
    """
    Query Neo4j for attack path metrics and compute a correlation bonus.
    
    Returns:
        (chain_length, bonus_score, has_c2_persistence, reasoning)
    """
    chain_length = 0
    has_c2_persistence = False
    reasoning = []

    try:
        async with get_neo4j_async_session() as session:
            # 1. Find longest FOLLOWED_BY chain for this job
            chain_query = """
            MATCH path = (s1:TimelineStage {job_id: $job_id})-[:FOLLOWED_BY*]->(s2:TimelineStage {job_id: $job_id})
            RETURN length(path) AS chain_len
            ORDER BY chain_len DESC
            LIMIT 1
            """
            result = await session.run(chain_query, job_id=job_id)
            record = await result.single()
            if record:
                chain_length = record["chain_len"] + 1  # +1 for the starting node

            # 2. Check for C2 + Persistence co-occurrence
            c2_query = """
            MATCH (j:SandboxJob {job_id: $job_id})-[:SPAWNED_PROCESS]->(p:Process)-[:CONNECTED_TO]->(ip:IPAddress)
            WITH j, count(ip) AS c2_count
            OPTIONAL MATCH (j)-[:EXHIBITS_TECHNIQUE]->(t:AttackTechnique)
            WHERE t.technique_id IN ['T1547.001', 'T1053.005', 'T1543.003', 'T1053']
            WITH c2_count, count(t) AS persist_count
            RETURN c2_count > 0 AND persist_count > 0 AS has_both
            """
            result2 = await session.run(c2_query, job_id=job_id)
            record2 = await result2.single()
            if record2 and record2["has_both"]:
                has_c2_persistence = True

    except Exception as e:
        logger.warning(f"[GraphScorer] Neo4j query failed for {job_id} (non-fatal): {e}")
        return 0, 0, False, [f"Graph scoring skipped: {e}"]

    # Calculate bonus
    bonus = 0

    if chain_length >= 5:
        bonus += CHAIN_BONUS[5]
        reasoning.append(f"Graph: Attack chain length {chain_length} (5+ nodes) → +{CHAIN_BONUS[5]}")
    elif chain_length >= 4:
        bonus += CHAIN_BONUS[4]
        reasoning.append(f"Graph: Attack chain length {chain_length} (4 nodes) → +{CHAIN_BONUS[4]}")
    elif chain_length >= 3:
        bonus += CHAIN_BONUS[3]
        reasoning.append(f"Graph: Attack chain length {chain_length} (3 nodes) → +{CHAIN_BONUS[3]}")

    if has_c2_persistence:
        bonus += C2_PERSISTENCE_BONUS
        reasoning.append(f"Graph: C2 + Persistence co-occurrence detected → +{C2_PERSISTENCE_BONUS}")

    return chain_length, bonus, has_c2_persistence, reasoning
