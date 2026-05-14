import math
from malscan.backend.analyzer.entropy import calculate_entropy, analyze_sections_entropy

def test_calculate_entropy():
    # Constant data should have 0 entropy
    assert calculate_entropy(b"\x00" * 100) == 0.0

    # Random-ish data should have higher entropy
    data = bytes(range(256))
    assert calculate_entropy(data) == 8.0

def test_analyze_sections_entropy_non_pe(tmp_path):
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x00" * 100)
    results = analyze_sections_entropy(str(p))
    assert len(results) == 1
    assert results[0]["section_name"] == "WHOLE_FILE"
    assert results[0]["entropy"] == 0.0
    assert results[0]["is_suspicious"] == False
