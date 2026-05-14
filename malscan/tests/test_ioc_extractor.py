from malscan.backend.analyzer.ioc_extractor import extract_iocs

def test_extract_iocs_comprehensive():
    test_strings = [
        "Connection to 8.8.8.8",
        "Download from http://example.com/malware",
        "Update HKEY_CURRENT_USER\\Software\\Malware",
        "Drop to C:\\Windows\\temp.exe",
        "API: VirtualAllocEx",
        "API: WriteProcessMemory",
        "Something random"
    ]

    iocs = extract_iocs(test_strings)

    assert "8.8.8.8" in iocs["ipv4"]
    assert "http://example.com/malware" in iocs["urls"]
    assert "example.com" in iocs["domains"] or "http://example.com/malware" in iocs["urls"]
    assert "HKEY_CURRENT_USER\\Software\\Malware" in iocs["registry_keys"]
    assert "C:\\Windows\\temp.exe" in iocs["file_paths"]
    assert "VirtualAlloc" in iocs["suspicious_apis"]
    assert "WriteProcessMemory" in iocs["suspicious_apis"]

def test_extract_iocs_empty():
    iocs = extract_iocs([])
    for key in iocs:
        assert len(iocs[key]) == 0
