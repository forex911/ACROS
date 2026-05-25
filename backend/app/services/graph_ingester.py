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
