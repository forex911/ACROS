import re
import os

# Regex patterns for IOC extraction
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_PATTERN = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
DOMAIN_PATTERN = re.compile(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')

def extract_strings(file_path: str):
    if not os.path.exists(file_path):
        return {}

    with open(file_path, "rb") as f:
        data = f.read()

    # Extract all printable ASCII strings > 4 chars
    ascii_strings = re.findall(b'[ -~]{4,}', data)
    decoded_strings = [s.decode('ascii', 'ignore') for s in ascii_strings]
    
    # Try UTF-16LE as well (common in Windows)
    utf16_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', data)
    decoded_strings += [s.decode('utf-16le', 'ignore') for s in utf16_strings]

    text_blob = "\n".join(decoded_strings)

    ips = list(set(IP_PATTERN.findall(text_blob)))
    urls = list(set(URL_PATTERN.findall(text_blob)))
    
    # Simple domain extraction from URLs or plain text (filter out false positives like .exe)
    raw_domains = DOMAIN_PATTERN.findall(text_blob)
    
    # Filter aggressively to avoid matching filenames like "app.py" or "main.c" or typical windows file paths
    bad_extensions = (
        '.exe', '.dll', '.sys', '.py', '.c', '.h', '.txt', '.log', '.dat', '.json', '.yaml', '.yml', 
        '.md', '.png', '.jpg', '.jpeg', '.gif', '.zip', '.tar', '.gz', '.rar',
        '.run', '.gethostbyname', '.socket', '.system', '.request', '.urlopen', '.connect'
    )
    domains = list(set([d for d in raw_domains if not d.lower().endswith(bad_extensions) and "/" not in d and "\\" not in d and len(d) > 4]))

    # Filter out common local IPs
    ips = [ip for ip in ips if not ip.startswith('127.') and not ip.startswith('169.254.')]

    return {
        "ips": ips,
        "urls": urls,
        "domains": domains,
        "total_strings_count": len(decoded_strings)
    }
