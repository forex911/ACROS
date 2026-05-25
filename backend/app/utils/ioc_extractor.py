import re
from typing import List, Dict, Any

class IOCExtractor:
    """
    Extracts Indicators of Compromise (IOCs) such as IPs, Domains, and Hashes from telemetry.
    """
    # Simple regex patterns for demonstration
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b', re.IGNORECASE)
    MD5_PATTERN = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
    SHA256_PATTERN = re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)

    @classmethod
    def extract_from_events(cls, events: List[Dict[str, Any]]) -> Dict[str, set]:
        iocs = {
            "ips": set(),
            "domains": set(),
            "hashes": set()
        }
        
        for event in events:
            details = event.get("details", {})
            
            # Extract from network events
            if "src_ip" in details:
                iocs["ips"].add(details["src_ip"])
            if "dst_ip" in details:
                iocs["ips"].add(details["dst_ip"])
            if "query" in details:
                iocs["domains"].add(details["query"])
                
            # Extract from process command lines or files (naive regex scan over strings)
            # In a real system, you'd target specific fields
            for key, value in details.items():
                if isinstance(value, str):
                    cls._scan_string(value, iocs)
                elif isinstance(value, list) and all(isinstance(i, str) for i in value):
                    for item in value:
                        cls._scan_string(item, iocs)
                        
        return iocs

    @classmethod
    def _scan_string(cls, text: str, iocs: Dict[str, set]):
        for ip in cls.IP_PATTERN.findall(text):
            if not ip.startswith(("127.", "10.", "192.168.", "169.254.")): # filter rfc1918 loosely
                iocs["ips"].add(ip)
                
        for domain in cls.DOMAIN_PATTERN.findall(text):
            if domain.lower() != "localhost":
                iocs["domains"].add(domain.lower())
                
        for md5 in cls.MD5_PATTERN.findall(text):
            iocs["hashes"].add(md5.lower())
            
        for sha256 in cls.SHA256_PATTERN.findall(text):
            iocs["hashes"].add(sha256.lower())
