import logging
from typing import Dict, Any, List
from app.database.neo4j import get_neo4j_async_session

logger = logging.getLogger("graph_ingester")

class GraphIngester:
    
    @staticmethod
    async def ingest_job_execution(job_id: str, sha256: str, filename: str):
        """Creates the initial SandboxJob and File nodes."""
        query = """
        MERGE (f:File {sha256: $sha256})
        ON CREATE SET f.name = $filename
        MERGE (j:SandboxJob {job_id: $job_id})
        MERGE (j)-[:ANALYZES]->(f)
        """
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, sha256=sha256, filename=filename, job_id=job_id)
        except Exception as e:
            logger.error(f"Failed to ingest job to graph: {e}")

    @staticmethod
    async def ingest_process_event(job_id: str, pid: int, ppid: int, executable: str, command: str):
        """Maps process ancestry and ties it to the sandbox job."""
        query = """
        MATCH (j:SandboxJob {job_id: $job_id})
        MERGE (p:Process {pid: $pid, job_id: $job_id})
        ON CREATE SET p.executable = $executable, p.command = $command
        MERGE (j)-[:SPAWNED_PROCESS]->(p)
        """
        
        # If ppid exists, link parent to child
        parent_query = """
        MATCH (child:Process {pid: $pid, job_id: $job_id})
        MERGE (parent:Process {pid: $ppid, job_id: $job_id})
        MERGE (parent)-[:SPAWNED]->(child)
        """
        
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, job_id=job_id, pid=pid, executable=executable, command=command)
                if ppid and ppid > 0:
                    await session.run(parent_query, job_id=job_id, pid=pid, ppid=ppid)
        except Exception as e:
            logger.error(f"Failed to ingest process event to graph: {e}")

    @staticmethod
    async def ingest_network_event(job_id: str, pid: int, ip_address: str, port: int, protocol: str = "TCP"):
        """Links a process to a network destination (IP)."""
        query = """
        MATCH (p:Process {pid: $pid, job_id: $job_id})
        MERGE (ip:IPAddress {address: $ip_address})
        MERGE (p)-[:CONNECTED_TO {port: $port, protocol: $protocol}]->(ip)
        """
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, job_id=job_id, pid=pid, ip_address=ip_address, port=port, protocol=protocol)
        except Exception as e:
            logger.error(f"Failed to ingest network event to graph: {e}")

    @staticmethod
    async def ingest_yara_match(sha256: str, rule_name: str, category: str):
        """Links a file to a YARA rule/threat classification."""
        query = """
        MATCH (f:File {sha256: $sha256})
        MERGE (y:YARARule {rule_name: $rule_name})
        ON CREATE SET y.category = $category
        MERGE (f)-[:MATCHES_YARA]->(y)
        """
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, sha256=sha256, rule_name=rule_name, category=category)
        except Exception as e:
            logger.error(f"Failed to ingest YARA match to graph: {e}")

    @staticmethod
    async def ingest_attack_technique(job_id: str, technique_id: str, technique_name: str, tactic: str):
        """Maps a sandbox job to a MITRE ATT&CK technique."""
        query = """
        MATCH (j:SandboxJob {job_id: $job_id})
        MERGE (t:AttackTechnique {technique_id: $technique_id})
        ON CREATE SET t.name = $technique_name, t.tactic = $tactic
        MERGE (j)-[:EXHIBITS_TECHNIQUE]->(t)
        """
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, job_id=job_id, technique_id=technique_id, technique_name=technique_name, tactic=tactic)
        except Exception as e:
            logger.error(f"Failed to ingest ATT&CK technique to graph: {e}")

    @staticmethod
    async def ingest_dns_event(job_id: str, pid: int, domain: str):
        """Links a process to a resolved domain."""
        query = """
        MATCH (p:Process {pid: $pid, job_id: $job_id})
        MERGE (d:Domain {name: $domain})
        MERGE (p)-[:RESOLVED]->(d)
        """
        # Fallback: if no process node exists yet, link directly to job
        fallback_query = """
        MATCH (j:SandboxJob {job_id: $job_id})
        MERGE (d:Domain {name: $domain})
        MERGE (j)-[:QUERIED_DNS]->(d)
        """
        try:
            async with get_neo4j_async_session() as session:
                if pid and pid > 0:
                    await session.run(query, job_id=job_id, pid=pid, domain=domain)
                else:
                    await session.run(fallback_query, job_id=job_id, domain=domain)
        except Exception as e:
            logger.error(f"Failed to ingest DNS event to graph: {e}")

    @staticmethod
    async def ingest_iocs_batch(job_id: str, iocs: list):
        """Batch-ingests IOCs from ioc_pipeline output into the graph."""
        try:
            async with get_neo4j_async_session() as session:
                for ioc in iocs:
                    ioc_type = ioc.get("type")
                    value = ioc.get("value")
                    confidence = ioc.get("confidence", "Low")

                    if ioc_type == "ip":
                        q = """
                        MATCH (j:SandboxJob {job_id: $job_id})
                        MERGE (ip:IPAddress {address: $value})
                        SET ip.confidence = $confidence
                        MERGE (j)-[:PRODUCED_IOC]->(ip)
                        """
                        await session.run(q, job_id=job_id, value=value, confidence=confidence)
                    elif ioc_type == "domain":
                        q = """
                        MATCH (j:SandboxJob {job_id: $job_id})
                        MERGE (d:Domain {name: $value})
                        SET d.confidence = $confidence
                        MERGE (j)-[:PRODUCED_IOC]->(d)
                        """
                        await session.run(q, job_id=job_id, value=value, confidence=confidence)
                    elif ioc_type in ("sha256", "md5"):
                        q = """
                        MATCH (j:SandboxJob {job_id: $job_id})
                        MERGE (h:Hash {value: $value, type: $ioc_type})
                        SET h.confidence = $confidence
                        MERGE (j)-[:PRODUCED_IOC]->(h)
                        """
                        await session.run(q, job_id=job_id, value=value, ioc_type=ioc_type, confidence=confidence)
        except Exception as e:
            logger.error(f"Failed to batch-ingest IOCs to graph: {e}")

    @staticmethod
    async def ingest_artifact_tree(job_id: str, edges: List[Dict]):
        """Ingests artifact provenance (droppers, downloads, extractions) into the graph."""
        try:
            async with get_neo4j_async_session() as session:
                for edge in edges:
                    parent_hash = edge.get("parent_sha256")
                    child_hash = edge.get("child_sha256")
                    rel = edge.get("relationship", "dropped").upper()
                    
                    if not parent_hash or not child_hash:
                        continue
                        
                    # Sanitize relationship name to prevent Cypher injection
                    if rel not in ("DROPPED", "DOWNLOADED", "EXTRACTED", "CREATED"):
                        rel = "CREATED"
                        
                    q = f"""
                    MATCH (p:File {{sha256: $parent_hash}})
                    MERGE (c:File {{sha256: $child_hash}})
                    ON CREATE SET 
                        c.name = $child_filename,
                        c.type = $child_type,
                        c.risk = $child_risk
                    MERGE (p)-[:{rel}]->(c)
                    """
                    await session.run(
                        q, 
                        parent_hash=parent_hash, 
                        child_hash=child_hash,
                        child_filename=edge.get("child_filename", ""),
                        child_type=edge.get("child_type", "Unknown"),
                        child_risk=edge.get("child_risk", 0)
                    )
        except Exception as e:
            logger.error(f"Failed to ingest artifact tree to graph: {e}")
