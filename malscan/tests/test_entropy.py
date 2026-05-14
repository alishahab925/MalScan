from malscan.backend.analyzer.entropy import calculate_entropy, analyze_sections_entropy

def test_calculate_entropy_basic():
    # Low entropy
    assert calculate_entropy(b"\x00" * 100) == 0.0
    # High entropy (all byte values present equally)
    data = bytes(range(256))
    assert calculate_entropy(data) == 8.0

def test_analyze_sections_entropy_mock(tmp_path, mocker):
    p = tmp_path / "mock.exe"
    p.write_bytes(b"PE\x00\x00" + b"A" * 100)

    mock_pe = mocker.patch('pefile.PE')
    instance = mock_pe.return_value

    mock_section = mocker.Mock()
    mock_section.Name = b".text\x00"
    mock_section.get_data.return_value = b"random_data_here" * 10
    instance.sections = [mock_section]

    results = analyze_sections_entropy(str(p))
    assert len(results) == 1
    assert results[0]["section_name"] == ".text"
    assert results[0]["entropy"] > 0
