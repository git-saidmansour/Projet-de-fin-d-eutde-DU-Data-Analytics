from datetime import datetime

from src.collect.nvd import _date_windows, parse_cve_item

SAMPLE_ITEM = {
    "cve": {
        "id": "CVE-2024-0001",
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-01-05T00:00:00.000",
        "descriptions": [
            {"lang": "fr", "value": "description francaise"},
            {"lang": "en", "value": "A remote code execution vulnerability."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                    },
                    "impactScore": 5.9,
                    "exploitabilityScore": 3.9,
                }
            ]
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79"}]},
            {"description": [{"lang": "en", "value": "CWE-79"}]},
        ],
        "references": [{"url": "https://example.com"}, {"url": "https://example.org"}],
    }
}


def test_parse_cve_item_extracts_expected_fields():
    parsed = parse_cve_item(SAMPLE_ITEM)

    assert parsed["cve_id"] == "CVE-2024-0001"
    assert parsed["description"] == "A remote code execution vulnerability."
    assert parsed["cvss_base_score"] == 9.8
    assert parsed["cvss_attack_vector"] == "NETWORK"
    assert parsed["cwe_ids"] == "CWE-79"
    assert parsed["reference_count"] == 2


def test_parse_cve_item_handles_missing_cvss():
    item = {"cve": {"id": "CVE-2024-0002", "descriptions": [], "references": []}}
    parsed = parse_cve_item(item)

    assert parsed["cvss_base_score"] is None
    assert parsed["cwe_ids"] == ""
    assert parsed["reference_count"] == 0


def test_date_windows_splits_long_ranges():
    start = datetime(2024, 1, 1)
    end = datetime(2024, 6, 1)
    windows = list(_date_windows(start, end))

    assert windows[0][0] == start
    assert windows[-1][1] == end
    for window_start, window_end in windows:
        assert (window_end - window_start).days <= 120


def test_date_windows_single_window_when_short():
    start = datetime(2024, 1, 1)
    end = datetime(2024, 1, 10)
    windows = list(_date_windows(start, end))

    assert windows == [(start, end)]
