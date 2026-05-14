import re
from typing import List, Dict

def extract_iocs(strings: List[str]) -> Dict[str, List[str]]:
    """
    Runs regex patterns over strings to find and categorize IOCs.
    """
    iocs = {
        "ipv4": set(),
        "domains": set(),
        "urls": set(),
        "registry_keys": set(),
        "file_paths": set(),
        "suspicious_apis": set()
    }

    # Regex patterns
    ipv4_re = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    # Simple domain regex
    domain_re = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b', re.IGNORECASE)
    url_re = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
    reg_key_re = re.compile(r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CLASSES_ROOT|CURRENT_CONFIG)[\\][\w\\]+', re.IGNORECASE)
    # File paths (Windows)
    file_path_re = re.compile(r'[a-zA-Z]:\\[\w\\\.\s-]+')

    suspicious_apis = [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "OpenProcess", "LoadLibrary", "GetProcAddress", "ShellExecute",
        "WinExec", "CreateProcess", "RegSetValue", "InternetOpen", "HttpSendRequest"
    ]

    for s in strings:
        # IPv4
        for match in ipv4_re.findall(s):
            iocs["ipv4"].add(match)

        # URLs (Check URL first as it might contain domains)
        for match in url_re.findall(s):
            iocs["urls"].add(match)

        # Domains (only if not already part of a URL to avoid duplication)
        for match in domain_re.findall(s):
            # Very basic check to avoid common false positives like file names
            if '.' in match and len(match.split('.')[-1]) > 1:
                is_in_url = any(match in url for url in iocs["urls"])
                if not is_in_url:
                    iocs["domains"].add(match)

        # Registry Keys
        for match in reg_key_re.findall(s):
            iocs["registry_keys"].add(match)

        # File Paths
        for match in file_path_re.findall(s):
            if '\\' in match:
                iocs["file_paths"].add(match)

        # Suspicious APIs
        for api in suspicious_apis:
            if api.lower() in s.lower():
                iocs["suspicious_apis"].add(api)

    # Convert sets to sorted lists
    return {k: sorted(list(v)) for k, v in iocs.items()}
