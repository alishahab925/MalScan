import pytest
import os
import pefile
from malscan.backend.analyzer.pe_parser import parse_pe

def create_mock_pe(filepath):
    # Create a very minimal valid PE structure for testing
    # This is complex to do from scratch, so we'll mock the pefile.PE class if needed
    # But for now, let's test with a non-PE and ensure it handles it.
    with open(filepath, 'wb') as f:
        f.write(b"NOT A PE FILE")

def test_parse_pe_invalid(tmp_path):
    file_path = tmp_path / "test.exe"
    create_mock_pe(file_path)
    result = parse_pe(str(file_path))
    assert "error" in result

def test_parse_pe_real_mock(mocker):
    # Use pytest-mock to mock pefile
    mock_pe = mocker.patch('pefile.PE')
    instance = mock_pe.return_value
    instance.FILE_HEADER.Machine = 0x8664 # AMD64
    instance.FILE_HEADER.TimeDateStamp = 1600000000

    mock_section = mocker.Mock()
    mock_section.Name = b".text\x00\x00\x00"
    mock_section.SizeOfRawData = 1024
    mock_section.Misc_VirtualSize = 2048
    instance.sections = [mock_section]

    # Mock imports
    mock_import = mocker.Mock()
    mock_import.dll = b"KERNEL32.dll"
    imp_func = mocker.Mock()
    imp_func.name = b"CreateFileA"
    mock_import.imports = [imp_func]
    instance.DIRECTORY_ENTRY_IMPORT = [mock_import]

    result = parse_pe("mock.exe")

    assert result["architecture"] == "64-bit"
    assert "2020-09-13" in result["compile_timestamp"]
    assert result["sections"][0]["name"] == ".text"
    assert "KERNEL32.dll" in result["imports"]
    assert "CreateFileA" in result["imports"]["KERNEL32.dll"]
