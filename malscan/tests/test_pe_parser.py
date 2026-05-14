import pytest
import os
from malscan.backend.analyzer.pe_parser import parse_pe

def test_parse_pe_invalid_file():
    result = parse_pe("nonexistent.exe")
    assert "error" in result

def test_parse_pe_mock_data(tmp_path):
    # This is a bit tricky since pefile expects a real PE structure.
    # We'll just test the error handling or use a tiny valid PE if possible.
    # For simplicity, we verify it handles non-PE files gracefully.
    p = tmp_path / "not_a_pe.txt"
    p.write_text("just some text")
    result = parse_pe(str(p))
    assert "error" in result
