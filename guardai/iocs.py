import re
from typing import Dict, List, Set

# Basic allowed TLDs to avoid matching filenames like invoice.exe
VALID_TLDS = {'com', 'net', 'org', 'io', 'co', 'us', 'uk', 'ru', 'gov', 'edu', 'info', 'biz'}

def defang_restore(text: str) -> str:
    """Restores defanged indicators (e.g., hxxp -> http, [.] -> .)."""
    text = text.replace('hxxp', 'http')
    text = text.replace('HXXP', 'http')
    text = text.replace('[.]', '.')
    text = text.replace('(.)', '.')
    text = text.replace('[@]', '@')
    return text

def is_valid_ipv4(ip: str) -> bool:
    """Validates that an IPv4 address has valid octet ranges."""
    parts = ip.split('.')
    if len(parts) != 4: return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def extract_iocs(alert_text: str) -> List[Dict[str, str]]:
    """Extracts unique IoCs from alert text using regular expressions."""
    alert_text = defang_restore(alert_text)
    iocs: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def add_ioc(ioc_type: str, value: str):
        if value not in seen:
            seen.add(value)
            iocs.append({"type": ioc_type, "value": value})

    # IPv4 Extraction
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for match in ipv4_pattern.findall(alert_text):
        if is_valid_ipv4(match):
            add_ioc("IPv4", match)

    # File Hashes Extraction
    md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
    sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
    sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    for match in sha256_pattern.findall(alert_text): add_ioc("SHA-256", match)
    for match in sha1_pattern.findall(alert_text): add_ioc("SHA-1", match)
    for match in md5_pattern.findall(alert_text): add_ioc("MD5", match)

    # Email Extraction
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    for match in email_pattern.findall(alert_text):
        add_ioc("Email", match)

    # URL Extraction
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    for match in url_pattern.findall(alert_text):
        add_ioc("URL", match)

    # Domain Extraction (Requires valid TLD to avoid .exe, .dll, etc.)
    domain_pattern = re.compile(r'\b([a-zA-Z0-9.-]+\.([a-zA-Z]{2,}))\b')
    for match in domain_pattern.findall(alert_text):
        domain, tld = match[0], match[1]
        # Only add if it's a valid TLD and not already captured as part of an email or URL
        if tld.lower() in VALID_TLDS and not any(domain in u['value'] for u in iocs if u['type'] in ['Email', 'URL']):
            add_ioc("Domain", domain)

    # CVE Extraction
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    for match in cve_pattern.findall(alert_text):
        add_ioc("CVE", match.upper())

    return iocs