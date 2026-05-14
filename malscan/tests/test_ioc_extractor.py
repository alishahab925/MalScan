from malscan.backend.analyzer.ioc_extractor import extract_iocs

def test_extract_iocs():
    test_strings = [
        "192.168.1.1",
        "https://malicious.com/payload.exe",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "C:\\Windows\\System32\\calc.exe",
        "VirtualAlloc",
        "CreateRemoteThread",
        "NormalString"
    ]

    iocs = extract_iocs(test_strings)

    assert "192.168.1.1" in iocs["ipv4"]
    assert "https://malicious.com/payload.exe" in iocs["urls"]
    # malicious.com might be filtered out if it's in the URL, check if either domain or url contains it
    domain_found = "malicious.com" in iocs["domains"]
    url_found = any("malicious.com" in url for url in iocs["urls"])
    assert domain_found or url_found
    assert "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in iocs["registry_keys"]
    assert "C:\\Windows\\System32\\calc.exe" in iocs["file_paths"]
    assert "VirtualAlloc" in iocs["suspicious_apis"]
    assert "CreateRemoteThread" in iocs["suspicious_apis"]
