"""
Graph Ingester — Batched Neo4j Ingestion
=========================================
Ingests telemetry, IOCs, MITRE mappings, YARA matches, and artifact
provenance into the Neo4j graph database.

Key improvements over v1:
- Single session per batch operation (not one session per query)
- @neo4j_resilient decorator for graceful degradation
- Centralized query execution with logging
"""

import logging
from typing import Dict, Any, List
from app.database.neo4j import get_neo4j_async_session
from app.models.graph_schema import RelType, ARTIFACT_RELS
from app.services.graph_resilience import neo4j_resilient

logger = logging.getLogger("graph_ingester")


async def _run_query(session, query, **kwargs):
    """Execute a Cypher query and consume the result."""
    res = await session.run(query, **kwargs)
    await res.consume()


class GraphIngester:

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_job_execution(job_id: str, sha256: str, filename: str):
        """Creates the initial SandboxJob and File nodes."""
        query = f"""
        MERGE (f:File {{sha256: $sha256}})
        ON CREATE SET f.name = $filename
        MERGE (j:SandboxJob {{job_id: $job_id}})
        MERGE (j)-[:{RelType.ANALYZES}]->(f)
        """
        async with get_neo4j_async_session() as session:
            await _run_query(session, query, sha256=sha256, filename=filename, job_id=job_id)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_process_event(job_id: str, pid: int, ppid: int, executable: str, command: str):
        """Maps process ancestry and ties it to the sandbox job."""
        query = f"""
        MATCH (j:SandboxJob {{job_id: $job_id}})
        MERGE (p:Process {{pid: $pid, job_id: $job_id}})
        ON CREATE SET p.executable = $executable, p.command = $command
        MERGE (j)-[:{RelType.SPAWNED_PROCESS}]->(p)
        """
        parent_query = f"""
        MATCH (child:Process {{pid: $pid, job_id: $job_id}})
        MERGE (parent:Process {{pid: $ppid, job_id: $job_id}})
        MERGE (parent)-[:{RelType.SPAWNED}]->(child)
        """
        async with get_neo4j_async_session() as session:
            await _run_query(session, query, job_id=job_id, pid=pid, executable=executable, command=command)
            if ppid and ppid > 0:
                await _run_query(session, parent_query, job_id=job_id, pid=pid, ppid=ppid)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_network_event(job_id: str, pid: int, ip_address: str, port: int, protocol: str = "TCP"):
        """Links a process to a network destination (IP)."""
        query = f"""
        MATCH (p:Process {{pid: $pid, job_id: $job_id}})
        MERGE (ip:IPAddress {{address: $ip_address}})
        MERGE (p)-[:{RelType.CONNECTED_TO} {{port: $port, protocol: $protocol}}]->(ip)
        """
        async with get_neo4j_async_session() as session:
            await _run_query(session, query, job_id=job_id, pid=pid, ip_address=ip_address, port=port, protocol=protocol)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_yara_match(sha256: str, rule_name: str, category: str):
        """Links a file to a YARA rule/threat classification."""
        query = f"""
        MATCH (f:File {{sha256: $sha256}})
        MERGE (y:YARARule {{rule_name: $rule_name}})
        ON CREATE SET y.category = $category
        MERGE (f)-[:{RelType.MATCHES_YARA}]->(y)
        """
        async with get_neo4j_async_session() as session:
            await _run_query(session, query, sha256=sha256, rule_name=rule_name, category=category)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_attack_technique(job_id: str, technique_id: str, technique_name: str, tactic: str):
        """Maps a sandbox job to a MITRE ATT&CK technique."""
        query = f"""
        MATCH (j:SandboxJob {{job_id: $job_id}})
        MERGE (t:AttackTechnique {{technique_id: $technique_id}})
        ON CREATE SET t.name = $technique_name, t.tactic = $tactic
        MERGE (j)-[:{RelType.EXHIBITS_TECHNIQUE}]->(t)
        """
        async with get_neo4j_async_session() as session:
            await _run_query(session, query, job_id=job_id, technique_id=technique_id, technique_name=technique_name, tactic=tactic)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_dns_event(job_id: str, pid: int, domain: str):
        """Links a process to a resolved domain."""
        query = f"""
        MATCH (p:Process {{pid: $pid, job_id: $job_id}})
        MERGE (d:Domain {{name: $domain}})
        MERGE (p)-[:{RelType.RESOLVED}]->(d)
        """
        fallback_query = f"""
        MATCH (j:SandboxJob {{job_id: $job_id}})
        MERGE (d:Domain {{name: $domain}})
        MERGE (j)-[:{RelType.QUERIED_DNS}]->(d)
        """
        async with get_neo4j_async_session() as session:
            if pid and pid > 0:
                await _run_query(session, query, job_id=job_id, pid=pid, domain=domain)
            else:
                await _run_query(session, fallback_query, job_id=job_id, domain=domain)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_iocs_batch(job_id: str, iocs: list):
        """Batch-ingests IOCs using a SINGLE session (not one session per IOC)."""
        async with get_neo4j_async_session() as session:
            for ioc in iocs:
                ioc_type = ioc.get("type")
                value = ioc.get("value")
                confidence = ioc.get("confidence", "Low")

                if ioc_type == "ip":
                    q = f"""
                    MATCH (j:SandboxJob {{job_id: $job_id}})
                    MERGE (ip:IPAddress {{address: $value}})
                    SET ip.confidence = $confidence
                    MERGE (j)-[:{RelType.PRODUCED_IOC}]->(ip)
                    """
                    await _run_query(session, q, job_id=job_id, value=value, confidence=confidence)
                elif ioc_type == "domain":
                    q = f"""
                    MATCH (j:SandboxJob {{job_id: $job_id}})
                    MERGE (d:Domain {{name: $value}})
                    SET d.confidence = $confidence
                    MERGE (j)-[:{RelType.PRODUCED_IOC}]->(d)
                    """
                    await _run_query(session, q, job_id=job_id, value=value, confidence=confidence)
                elif ioc_type in ("sha256", "md5"):
                    q = f"""
                    MATCH (j:SandboxJob {{job_id: $job_id}})
                    MERGE (h:Hash {{value: $value, type: $ioc_type}})
                    SET h.confidence = $confidence
                    MERGE (j)-[:{RelType.PRODUCED_IOC}]->(h)
                    """
                    await _run_query(session, q, job_id=job_id, value=value, ioc_type=ioc_type, confidence=confidence)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_artifact_tree(job_id: str, edges: List[Dict]):
        """Ingests artifact provenance using a SINGLE session."""
        async with get_neo4j_async_session() as session:
            for edge in edges:
                parent_hash = edge.get("parent_sha256")
                child_hash = edge.get("child_sha256")
                rel = edge.get("relationship", "dropped").upper()

                if not parent_hash or not child_hash:
                    continue

                # Sanitize relationship name to prevent Cypher injection
                if rel not in ARTIFACT_RELS:
                    rel = RelType.CREATED

                q = f"""
                MATCH (p:File {{sha256: $parent_hash}})
                MERGE (c:File {{sha256: $child_hash}})
                ON CREATE SET
                    c.name = $child_filename,
                    c.type = $child_type,
                    c.risk = $child_risk
                MERGE (p)-[:{rel}]->(c)
                """
                await _run_query(session, q,
                    parent_hash=parent_hash,
                    child_hash=child_hash,
                    child_filename=edge.get("child_filename", ""),
                    child_type=edge.get("child_type", "Unknown"),
                    child_risk=edge.get("child_risk", 0),
                )

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_registry_event(job_id: str, pid: int, key: str, operation: str = "MODIFY"):
        """Links a process to a modified registry key."""
        query = f"""
        MATCH (p:Process {{pid: $pid, job_id: $job_id}})
        MERGE (r:RegistryKey {{key: $key}})
        ON CREATE SET r.operation = $operation
        MERGE (p)-[:{RelType.MODIFIED_REGISTRY}]->(r)
        """
        fallback_query = f"""
        MATCH (j:SandboxJob {{job_id: $job_id}})
        MERGE (r:RegistryKey {{key: $key}})
        ON CREATE SET r.operation = $operation
        MERGE (j)-[:{RelType.MODIFIED_REGISTRY}]->(r)
        """
        async with get_neo4j_async_session() as session:
            if pid and pid > 0:
                await _run_query(session, query, job_id=job_id, pid=pid, key=key, operation=operation)
            else:
                await _run_query(session, fallback_query, job_id=job_id, key=key, operation=operation)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_persistence_event(job_id: str, pid: int, mechanism: str, target: str):
        """Links a process to a persistence mechanism."""
        query = f"""
        MATCH (p:Process {{pid: $pid, job_id: $job_id}})
        MERGE (m:PersistenceMechanism {{mechanism: $mechanism, target: $target}})
        MERGE (p)-[:{RelType.PERSISTED_VIA}]->(m)
        """
        fallback_query = f"""
        MATCH (j:SandboxJob {{job_id: $job_id}})
        MERGE (m:PersistenceMechanism {{mechanism: $mechanism, target: $target}})
        MERGE (j)-[:{RelType.PERSISTED_VIA}]->(m)
        """
        async with get_neo4j_async_session() as session:
            if pid and pid > 0:
                await _run_query(session, query, job_id=job_id, pid=pid, mechanism=mechanism, target=target)
            else:
                await _run_query(session, fallback_query, job_id=job_id, mechanism=mechanism, target=target)

    @staticmethod
    @neo4j_resilient(default_return=None)
    async def ingest_memory_injection_event(job_id: str, source_pid: int, target_pid: int, api_call: str):
        """Links a source process injecting into a target process."""
        query = f"""
        MERGE (src:Process {{pid: $source_pid, job_id: $job_id}})
        MERGE (tgt:Process {{pid: $target_pid, job_id: $job_id}})
        MERGE (src)-[:{RelType.INJECTED_INTO} {{api: $api_call}}]->(tgt)
        """
        async with get_neo4j_async_session() as session:
            await _run_query(session, query, job_id=job_id, source_pid=source_pid, target_pid=target_pid, api_call=api_call)
