import re
import ipaddress
from app.utils.ioc_extractor import IOCExtractor

# Regex patterns for enhanced IOC extraction
IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
EMAIL_PATTERN = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')

def is_valid_ioc(ioc_type, value):
    if ioc_type in ["ip", "ipv6"]:
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            return False
    return True

def extract_and_store_iocs(static_results, telemetry_events):
    # This combines static and dynamic findings to generate unique IOCs
    iocs_dict = {} # Keyed by value to keep track of sources and elevate confidence
    
    def add_or_update_ioc(ioc_type, value, source, confidence):
        if not value or not is_valid_ioc(ioc_type, value):
            return
            
        if value not in iocs_dict:
            iocs_dict[value] = {
                "type": ioc_type,
                "value": value,
                "sources": {source},
                "confidence": confidence,
                "is_static": "Static" in source,
                "is_dynamic": "Runtime" in source
            }
        else:
            entry = iocs_dict[value]
            entry["sources"].add(source)
            if "Static" in source:
                entry["is_static"] = True
            if "Runtime" in source:
                entry["is_dynamic"] = True
                
            # Confidence elevation logic
            if entry["is_static"] and entry["is_dynamic"]:
                entry["confidence"] = "Medium"
            if confidence == "High" or (entry["is_dynamic"] and ioc_type in ["ip", "url", "domain"]):
                entry["confidence"] = "High"

    # From Static
    if "strings" in static_results:
        for ip in static_results["strings"].get("ips", []):
            add_or_update_ioc("ip", ip, "Static Analysis (Strings)", "Low")
        for url in static_results["strings"].get("urls", []):
            add_or_update_ioc("url", url, "Static Analysis (Strings)", "Low")
        for dom in static_results["strings"].get("domains", []):
            add_or_update_ioc("domain", dom, "Static Analysis (Strings)", "Low")
        # Scan raw strings for IPv6, emails, hashes
        raw_text = " ".join(static_results["strings"].get("interesting", []))
        for ipv6 in IPV6_PATTERN.findall(raw_text):
            add_or_update_ioc("ipv6", ipv6, "Static Analysis (Strings)", "Low")
        for email in EMAIL_PATTERN.findall(raw_text):
            add_or_update_ioc("email", email, "Static Analysis (Strings)", "Low")

    if "hash" in static_results:
        add_or_update_ioc("sha256", static_results["hash"].get("sha256"), "Static Analysis (Hash)", "High")
        add_or_update_ioc("md5", static_results["hash"].get("md5"), "Static Analysis (Hash)", "High")

    # From Runtime
    for event in telemetry_events:
        evt_type = event.get("type")
        data = event.get("data", {})
        
        if evt_type == "SOCKET_CONNECT":
            add_or_update_ioc("ip", data.get("dest_ip"), "Runtime Telemetry", "High")
        elif evt_type == "HTTP_REQUEST":
            url = data.get("url", "")
            add_or_update_ioc("url", url, "Runtime Telemetry", "High")
            # Also extract domain from URL
            domain_match = re.search(r'https?://([^/:]+)', url)
            if domain_match:
                add_or_update_ioc("domain", domain_match.group(1), "Runtime Telemetry (URL)", "High")
        elif evt_type == "DNS_QUERY":
            add_or_update_ioc("domain", data.get("query"), "Runtime Telemetry", "High")
        elif evt_type == "PROCESS_CREATE":
            cmdline = data.get("cmdline", "")
            if "powershell" in cmdline.lower() and "-enc" in cmdline.lower():
                add_or_update_ioc("command", "powershell.exe", "Runtime Telemetry", "High")
            elif "vssadmin" in cmdline.lower() and "delete" in cmdline.lower():
                add_or_update_ioc("command", "vssadmin.exe", "Runtime Telemetry", "High")
            # Extract hashes and IPs from command lines
            for sha in SHA256_PATTERN.findall(cmdline):
                add_or_update_ioc("sha256", sha.lower(), "Runtime Telemetry (cmdline)", "Medium")
            for md5 in MD5_PATTERN.findall(cmdline):
                add_or_update_ioc("md5", md5.lower(), "Runtime Telemetry (cmdline)", "Medium")
            for url in URL_PATTERN.findall(cmdline):
                add_or_update_ioc("url", url, "Runtime Telemetry (cmdline)", "High")

        # Scan stdout/stderr if present in any event
        for field in ("stdout", "stderr", "output"):
            text = data.get(field, "")
            if text:
                for ipv6 in IPV6_PATTERN.findall(text):
                    add_or_update_ioc("ipv6", ipv6, "Runtime Telemetry (output)", "Medium")
                for email in EMAIL_PATTERN.findall(text):
                    add_or_update_ioc("email", email, "Runtime Telemetry (output)", "Medium")

    # Format for output
    final_iocs = []
    for val, details in iocs_dict.items():
        final_iocs.append({
            "type": details["type"],
            "value": val,
            "source": ", ".join(details["sources"]),
            "confidence": details["confidence"]
        })
            
    return final_iocs

