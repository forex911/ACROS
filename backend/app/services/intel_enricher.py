import logging
import os
import httpx
from typing import Dict, Any, Optional
from app.database.neo4j import get_neo4j_async_session

logger = logging.getLogger("intel_enricher")

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSE_IPDB_KEY = os.getenv("ABUSE_IPDB_KEY", "")

class IntelEnricher:
    
    @staticmethod
    async def enrich_file_hash(sha256: str) -> Optional[Dict[str, Any]]:
        """
        Queries VirusTotal for file reputation and updates the Neo4j File node with confidence scores.
        """
        if not VT_API_KEY:
            logger.warning("VT_API_KEY not configured, skipping enrichment.")
            return None
            
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VT_API_KEY}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    total_count = sum(stats.values())
                    confidence_score = (malicious_count / total_count * 100) if total_count > 0 else 0
                    
                    # Update graph node
                    await IntelEnricher._update_file_node(sha256, malicious_count, confidence_score)
                    return {"malicious": malicious_count, "confidence": confidence_score}
        except Exception as e:
            logger.error(f"Failed VT enrichment for {sha256}: {e}")
        return None

    @staticmethod
    async def enrich_ip_address(ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Queries AbuseIPDB for IP reputation and updates the Neo4j IPAddress node.
        """
        if not ABUSE_IPDB_KEY:
            logger.warning("ABUSE_IPDB_KEY not configured, skipping enrichment.")
            return None
            
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': ABUSE_IPDB_KEY}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, params=querystring)
                if response.status_code == 200:
                    data = response.json()
                    score = data.get("data", {}).get("abuseConfidenceScore", 0)
                    
                    # Update graph node
                    await IntelEnricher._update_ip_node(ip_address, score)
                    return {"abuse_confidence_score": score}
        except Exception as e:
            logger.error(f"Failed AbuseIPDB enrichment for {ip_address}: {e}")
        return None

    @staticmethod
    async def _update_file_node(sha256: str, malicious_count: int, confidence: float):
        query = """
        MATCH (f:File {sha256: $sha256})
        SET f.vt_malicious_count = $malicious_count,
            f.threat_confidence = $confidence,
            f.last_enriched = timestamp()
        """
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, sha256=sha256, malicious_count=malicious_count, confidence=confidence)
        except Exception as e:
            logger.error(f"Graph update failed for File {sha256}: {e}")

    @staticmethod
    async def _update_ip_node(ip_address: str, confidence: int):
        query = """
        MATCH (ip:IPAddress {address: $ip_address})
        SET ip.abuse_confidence = $confidence,
            ip.last_enriched = timestamp()
        """
        try:
            async with get_neo4j_async_session() as session:
                await session.run(query, ip_address=ip_address, confidence=confidence)
        except Exception as e:
            logger.error(f"Graph update failed for IP {ip_address}: {e}")
