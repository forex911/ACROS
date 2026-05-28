import logging
from typing import Dict, Any, List
from app.database.mongodb import db
from app.database.neo4j import get_neo4j_async_session

logger = logging.getLogger("hunting_service")

class HuntingService:
    
    @staticmethod
    async def global_ioc_search(query: str) -> Dict[str, Any]:
        """
        Searches both MongoDB and Neo4j for a given IOC (Hash, IP, Domain, or keyword).
        """
        results = {
            "jobs": [],
            "graph_nodes": [],
            "graph_relationships": []
        }
        
        # 1. Search MongoDB for jobs associated with this hash/keyword
        if db is not None:
            cursor = db["sandbox_jobs"].find({
                "$or": [
                    {"sha256": query},
                    {"filename": {"$regex": query, "$options": "i"}},
                    {"extra.extracted_iocs.ips": query},
                    {"extra.extracted_iocs.domains": query}
                ]
            }).limit(50)
            
            async for document in cursor:
                document["_id"] = str(document["_id"])
                results["jobs"].append(document)

        # 2. Search Neo4j graph for related connections (e.g. what spawned the process that connected to this IP)
        cypher_query = """
        MATCH (n)
        WHERE 
            (n:IPAddress AND n.address = $query) OR
            (n:File AND n.sha256 = $query) OR
            (n:Process AND n.executable CONTAINS $query) OR
            (n:AttackTechnique AND n.technique_id = $query)
        OPTIONAL MATCH (n)-[r]-(m)
        RETURN n, r, m LIMIT 100
        """
        try:
            async with get_neo4j_async_session() as session:
                neo_result = await session.run(cypher_query, query=query)
                async for record in neo_result:
                    if record["n"]:
                        node_data = {"id": str(record["n"].element_id), "labels": list(record["n"].labels), **dict(record["n"])}
                        if node_data not in results["graph_nodes"]:
                            results["graph_nodes"].append(node_data)
                    
                    if record["m"]:
                        node_data = {"id": str(record["m"].element_id), "labels": list(record["m"].labels), **dict(record["m"])}
                        if node_data not in results["graph_nodes"]:
                            results["graph_nodes"].append(node_data)
                            
                    if record["r"]:
                        results["graph_relationships"].append({
                            "id": str(record["r"].element_id),
                            "type": record["r"].type,
                            "source": str(record["r"].start_node.element_id),
                            "target": str(record["r"].end_node.element_id)
                        })
        except Exception as e:
            logger.error(f"Neo4j search failed: {e}")
            
        return results

    @staticmethod
    async def process_ancestry_search(pid: int, job_id: str) -> List[Dict[str, Any]]:
        """
        Uses Neo4j variable-length paths to trace the entire process ancestry tree for a PID.
        """
        cypher_query = """
        MATCH path = (root:Process)-[:SPAWNED*]->(target:Process {pid: $pid, job_id: $job_id})
        WHERE NOT ()-[:SPAWNED]->(root)
        RETURN path
        """
        results = []
        try:
            async with get_neo4j_async_session() as session:
                neo_result = await session.run(cypher_query, pid=pid, job_id=job_id)
                async for record in neo_result:
                    path = record["path"]
                    results.append([dict(node) for node in path.nodes])
        except Exception as e:
            logger.error(f"Neo4j ancestry search failed: {e}")
            
        return results
