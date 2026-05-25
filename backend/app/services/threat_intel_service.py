import os
import httpx
import asyncio
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ThreatIntelService:
    """
    Integrates with external Threat Intelligence providers (VirusTotal, AbuseIPDB).
    """
    def __init__(self):
        self.vt_api_key = os.getenv("VT_API_KEY", "")
        self.abuse_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        
        # We'd use a real HTTP client with connection pooling in production
        self.client = httpx.AsyncClient(timeout=10.0)

    async def close(self):
        await self.client.aclose()

    async def enrich_iocs(self, iocs: Dict[str, set]) -> Dict[str, Any]:
        """
        Enriches a set of extracted IOCs concurrently.
        """
        results = {
            "ips": {},
            "domains": {},
            "hashes": {}
        }
        
        tasks = []
        # Enrich Hashes via VirusTotal
        for h in list(iocs.get("hashes", []))[:5]: # limit for demo
            tasks.append(self._check_vt_hash(h, results))
            
        # Enrich IPs via AbuseIPDB
        for ip in list(iocs.get("ips", []))[:5]:
            tasks.append(self._check_abuseipdb(ip, results))
            
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            
        return results

    async def _check_vt_hash(self, file_hash: str, results_dict: Dict):
        if not self.vt_api_key:
            results_dict["hashes"][file_hash] = {"error": "API key missing"}
            return
            
        try:
            headers = {"x-apikey": self.vt_api_key}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                stats = data.get("attributes", {}).get("last_analysis_stats", {})
                results_dict["hashes"][file_hash] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0)
                }
            elif response.status_code == 404:
                results_dict["hashes"][file_hash] = {"status": "not_found"}
            else:
                results_dict["hashes"][file_hash] = {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"VT lookup failed for {file_hash}: {e}")
            results_dict["hashes"][file_hash] = {"error": "request_failed"}

    async def _check_abuseipdb(self, ip: str, results_dict: Dict):
        if not self.abuse_api_key:
            results_dict["ips"][ip] = {"error": "API key missing"}
            return
            
        try:
            headers = {
                "Accept": "application/json",
                "Key": self.abuse_api_key
            }
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            url = "https://api.abuseipdb.com/api/v2/check"
            response = await self.client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                results_dict["ips"][ip] = {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "totalReports": data.get("totalReports"),
                    "countryCode": data.get("countryCode")
                }
            else:
                results_dict["ips"][ip] = {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
            results_dict["ips"][ip] = {"error": "request_failed"}
