import sqlite3

from src.collect.storage import get_last_modified_date, init_db, upsert_cves, upsert_epss, upsert_kev


def make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def test_upsert_cves_insert_and_update():
    conn = make_conn()
    upsert_cves(
        conn,
        [{"cve_id": "CVE-2024-0001", "description": "first", "last_modified_date": "2024-01-01T00:00:00"}],
    )
    upsert_cves(
        conn,
        [{"cve_id": "CVE-2024-0001", "description": "updated", "last_modified_date": "2024-02-01T00:00:00"}],
    )

    row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", ("CVE-2024-0001",)).fetchone()
    assert row["description"] == "updated"
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 1


def test_get_last_modified_date():
    conn = make_conn()
    assert get_last_modified_date(conn) is None

    upsert_cves(
        conn,
        [
            {"cve_id": "CVE-2024-0001", "last_modified_date": "2024-01-01T00:00:00"},
            {"cve_id": "CVE-2024-0002", "last_modified_date": "2024-03-01T00:00:00"},
        ],
    )
    assert get_last_modified_date(conn) == "2024-03-01T00:00:00"


def test_upsert_epss():
    conn = make_conn()
    upsert_epss(
        conn,
        [{"cve_id": "CVE-2024-0001", "score_date": "2024-06-01", "epss": 0.5, "percentile": 0.9}],
    )
    row = conn.execute("SELECT * FROM epss_scores").fetchone()
    assert row["epss"] == 0.5


def test_upsert_kev():
    conn = make_conn()
    upsert_kev(
        conn,
        [{"cve_id": "CVE-2024-0001", "vendor_project": "Acme", "date_added": "2024-06-01"}],
    )
    row = conn.execute("SELECT * FROM kev").fetchone()
    assert row["vendor_project"] == "Acme"
