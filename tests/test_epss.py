from src.collect.epss import parse_row


def test_parse_row_converts_types():
    row = {"cve": "CVE-2024-0001", "epss": "0.00043", "percentile": "0.12345", "date": "2025-08-17"}
    parsed = parse_row(row)

    assert parsed == {
        "cve_id": "CVE-2024-0001",
        "score_date": "2025-08-17",
        "epss": 0.00043,
        "percentile": 0.12345,
    }
