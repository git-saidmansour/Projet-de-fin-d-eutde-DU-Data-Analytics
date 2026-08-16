import sqlite3
from datetime import datetime, timezone

from src.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published_date TEXT,
    last_modified_date TEXT,
    cvss_base_score REAL,
    cvss_impact_score REAL,
    cvss_exploitability_score REAL,
    cvss_attack_vector TEXT,
    cvss_attack_complexity TEXT,
    cvss_privileges_required TEXT,
    cvss_user_interaction TEXT,
    cvss_scope TEXT,
    cwe_ids TEXT,
    reference_count INTEGER,
    raw_json TEXT,
    collected_at TEXT
);

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id TEXT,
    score_date TEXT,
    epss REAL,
    percentile REAL,
    collected_at TEXT,
    PRIMARY KEY (cve_id, score_date)
);

CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added TEXT,
    short_description TEXT,
    required_action TEXT,
    due_date TEXT,
    known_ransomware_campaign_use TEXT,
    collected_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_epss_cve_id ON epss_scores (cve_id);
"""


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_cves(conn: sqlite3.Connection, cves: list[dict]) -> None:
    if not cves:
        return
    now = _now()
    rows = [
        (
            c["cve_id"],
            c.get("description"),
            c.get("published_date"),
            c.get("last_modified_date"),
            c.get("cvss_base_score"),
            c.get("cvss_impact_score"),
            c.get("cvss_exploitability_score"),
            c.get("cvss_attack_vector"),
            c.get("cvss_attack_complexity"),
            c.get("cvss_privileges_required"),
            c.get("cvss_user_interaction"),
            c.get("cvss_scope"),
            c.get("cwe_ids"),
            c.get("reference_count"),
            c.get("raw_json"),
            now,
        )
        for c in cves
    ]
    conn.executemany(
        """
        INSERT INTO cves (
            cve_id, description, published_date, last_modified_date,
            cvss_base_score, cvss_impact_score, cvss_exploitability_score,
            cvss_attack_vector, cvss_attack_complexity, cvss_privileges_required,
            cvss_user_interaction, cvss_scope, cwe_ids, reference_count,
            raw_json, collected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            description=excluded.description,
            published_date=excluded.published_date,
            last_modified_date=excluded.last_modified_date,
            cvss_base_score=excluded.cvss_base_score,
            cvss_impact_score=excluded.cvss_impact_score,
            cvss_exploitability_score=excluded.cvss_exploitability_score,
            cvss_attack_vector=excluded.cvss_attack_vector,
            cvss_attack_complexity=excluded.cvss_attack_complexity,
            cvss_privileges_required=excluded.cvss_privileges_required,
            cvss_user_interaction=excluded.cvss_user_interaction,
            cvss_scope=excluded.cvss_scope,
            cwe_ids=excluded.cwe_ids,
            reference_count=excluded.reference_count,
            raw_json=excluded.raw_json,
            collected_at=excluded.collected_at
        """,
        rows,
    )
    conn.commit()


def upsert_epss(conn: sqlite3.Connection, rows: list[dict]) -> None:
    if not rows:
        return
    now = _now()
    values = [(r["cve_id"], r["score_date"], r["epss"], r["percentile"], now) for r in rows]
    conn.executemany(
        """
        INSERT INTO epss_scores (cve_id, score_date, epss, percentile, collected_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cve_id, score_date) DO UPDATE SET
            epss=excluded.epss,
            percentile=excluded.percentile,
            collected_at=excluded.collected_at
        """,
        values,
    )
    conn.commit()


def upsert_kev(conn: sqlite3.Connection, rows: list[dict]) -> None:
    if not rows:
        return
    now = _now()
    values = [
        (
            r["cve_id"],
            r.get("vendor_project"),
            r.get("product"),
            r.get("vulnerability_name"),
            r.get("date_added"),
            r.get("short_description"),
            r.get("required_action"),
            r.get("due_date"),
            r.get("known_ransomware_campaign_use"),
            now,
        )
        for r in rows
    ]
    conn.executemany(
        """
        INSERT INTO kev (
            cve_id, vendor_project, product, vulnerability_name, date_added,
            short_description, required_action, due_date,
            known_ransomware_campaign_use, collected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            vendor_project=excluded.vendor_project,
            product=excluded.product,
            vulnerability_name=excluded.vulnerability_name,
            date_added=excluded.date_added,
            short_description=excluded.short_description,
            required_action=excluded.required_action,
            due_date=excluded.due_date,
            known_ransomware_campaign_use=excluded.known_ransomware_campaign_use,
            collected_at=excluded.collected_at
        """,
        values,
    )
    conn.commit()


def get_last_modified_date(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT MAX(last_modified_date) AS m FROM cves").fetchone()
    return row["m"] if row else None
