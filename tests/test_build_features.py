import sqlite3
from datetime import datetime, timezone

from src.collect.storage import init_db, upsert_cves, upsert_epss, upsert_kev
from src.features.build_features import build_features, compute_days_since_publication
import pandas as pd


def make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def test_compute_days_since_publication():
    published = pd.Series(["2024-01-01T00:00:00.000"])
    reference = datetime(2024, 1, 11, tzinfo=timezone.utc)
    result = compute_days_since_publication(published, reference)
    assert result.iloc[0] == 10


def test_build_features_end_to_end():
    conn = make_conn()
    upsert_cves(
        conn,
        [
            {
                "cve_id": "CVE-2024-0001",
                "description": "A remote code execution vulnerability in a WordPress plugin.",
                "published_date": "2024-01-01T00:00:00.000",
                "last_modified_date": "2024-01-02T00:00:00.000",
                "cwe_ids": "CWE-79",
                "reference_count": 3,
                "cvss_base_score": 9.8,
                "cvss_impact_score": 5.9,
                "cvss_exploitability_score": 3.9,
                "cvss_attack_vector": "NETWORK",
                "cvss_attack_complexity": "LOW",
                "cvss_privileges_required": "NONE",
                "cvss_user_interaction": "NONE",
                "cvss_scope": "UNCHANGED",
            },
            {
                "cve_id": "CVE-2024-0002",
                "description": "A minor local issue.",
                "published_date": "2024-01-05T00:00:00.000",
                "last_modified_date": "2024-01-06T00:00:00.000",
                "cwe_ids": "",
                "reference_count": 0,
                "cvss_base_score": 3.1,
                "cvss_impact_score": 1.4,
                "cvss_exploitability_score": 1.0,
                "cvss_attack_vector": "LOCAL",
                "cvss_attack_complexity": "HIGH",
                "cvss_privileges_required": "HIGH",
                "cvss_user_interaction": "REQUIRED",
                "cvss_scope": "CHANGED",
            },
        ],
    )
    upsert_epss(
        conn,
        [
            {"cve_id": "CVE-2024-0001", "score_date": "2024-06-01", "epss": 0.9, "percentile": 0.99},
            {"cve_id": "CVE-2024-0001", "score_date": "2024-06-02", "epss": 0.95, "percentile": 0.995},
            {"cve_id": "CVE-2024-0002", "score_date": "2024-06-01", "epss": 0.01, "percentile": 0.1},
        ],
    )
    upsert_kev(conn, [{"cve_id": "CVE-2024-0001", "vendor_project": "Acme"}])

    reference_date = datetime(2024, 6, 10, tzinfo=timezone.utc)
    df = build_features(conn, reference_date=reference_date).set_index("cve_id")

    row = df.loc["CVE-2024-0001"]
    assert row["is_exploited"] == 1
    assert row["cvss_attack_vector"] == 0
    assert row["cvss_attack_complexity"] == 0
    assert row["has_cwe"] == True  # noqa: E712
    assert row["cwe_category"] == "injection"
    assert row["vendor_category"] == "web"
    assert row["has_exploit_keyword"] == True  # noqa: E712
    assert row["epss_score"] == 0.95  # latest score_date wins
    assert row["days_since_publication"] == 161

    row2 = df.loc["CVE-2024-0002"]
    assert row2["is_exploited"] == 0
    assert row2["cvss_attack_vector"] == 2
    assert row2["has_cwe"] == False  # noqa: E712
    assert row2["cwe_category"] == "none"
