"""Turn the raw collected data (cves, epss_scores, kev) into a model-ready feature table."""

import argparse
import sqlite3
from datetime import datetime, timezone

import pandas as pd

from src.config import PROCESSED_DIR, get_logger
from src.collect.storage import get_connection
from src.features.cwe_mapping import categorize_cwe
from src.features.text_features import has_exploit_keyword, vendor_category

logger = get_logger(__name__)

ATTACK_VECTOR_MAP = {"NETWORK": 0, "ADJACENT_NETWORK": 1, "LOCAL": 2, "PHYSICAL": 3}
ATTACK_COMPLEXITY_MAP = {"LOW": 0, "HIGH": 1}
PRIVILEGES_REQUIRED_MAP = {"NONE": 0, "LOW": 1, "HIGH": 2}
USER_INTERACTION_MAP = {"NONE": 0, "REQUIRED": 1}
SCOPE_MAP = {"UNCHANGED": 0, "CHANGED": 1}

FEATURE_COLUMNS = [
    "cve_id",
    "published_date",
    "cvss_base_score",
    "cvss_impact_score",
    "cvss_exploitability_score",
    "cvss_attack_vector",
    "cvss_attack_complexity",
    "cvss_privileges_required",
    "cvss_user_interaction",
    "cvss_scope",
    "has_cwe",
    "cwe_category",
    "reference_count",
    "days_since_publication",
    "epss_score",
    "epss_percentile",
    "vendor_category",
    "has_exploit_keyword",
    "is_exploited",
]


def load_cves(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT cve_id, description, published_date, cwe_ids, reference_count, "
        "cvss_base_score, cvss_impact_score, cvss_exploitability_score, "
        "cvss_attack_vector, cvss_attack_complexity, cvss_privileges_required, "
        "cvss_user_interaction, cvss_scope FROM cves",
        conn,
    )


def load_latest_epss(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        """
        SELECT cve_id, epss AS epss_score, percentile AS epss_percentile
        FROM epss_scores
        WHERE (cve_id, score_date) IN (
            SELECT cve_id, MAX(score_date) FROM epss_scores GROUP BY cve_id
        )
        """,
        conn,
    )


def load_kev_ids(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT cve_id FROM kev").fetchall()
    return {row["cve_id"] for row in rows}


def encode_cvss(df: pd.DataFrame) -> pd.DataFrame:
    df["cvss_attack_vector"] = df["cvss_attack_vector"].map(ATTACK_VECTOR_MAP)
    df["cvss_attack_complexity"] = df["cvss_attack_complexity"].map(ATTACK_COMPLEXITY_MAP)
    df["cvss_privileges_required"] = df["cvss_privileges_required"].map(PRIVILEGES_REQUIRED_MAP)
    df["cvss_user_interaction"] = df["cvss_user_interaction"].map(USER_INTERACTION_MAP)
    df["cvss_scope"] = df["cvss_scope"].map(SCOPE_MAP)
    return df


def compute_days_since_publication(published_date: pd.Series, reference_date: datetime) -> pd.Series:
    published = pd.to_datetime(published_date, utc=True, errors="coerce")
    reference = pd.Timestamp(reference_date)
    if reference.tzinfo is None:
        reference = reference.tz_localize("UTC")
    return (reference - published).dt.days


def build_features(conn: sqlite3.Connection, reference_date: datetime | None = None) -> pd.DataFrame:
    reference_date = reference_date or datetime.now(timezone.utc)

    cves = load_cves(conn)
    epss = load_latest_epss(conn)
    kev_ids = load_kev_ids(conn)

    df = cves.merge(epss, on="cve_id", how="left")
    df = encode_cvss(df)

    df["has_cwe"] = df["cwe_ids"].fillna("").astype(bool)
    df["cwe_category"] = df["cwe_ids"].apply(categorize_cwe)
    df["days_since_publication"] = compute_days_since_publication(df["published_date"], reference_date)
    df["vendor_category"] = df["description"].apply(vendor_category)
    df["has_exploit_keyword"] = df["description"].apply(has_exploit_keyword)
    df["is_exploited"] = df["cve_id"].isin(kev_ids).astype(int)

    return df[FEATURE_COLUMNS]


def run(output_path=None, reference_date: datetime | None = None) -> pd.DataFrame:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    output_path = output_path or (PROCESSED_DIR / "features.csv")

    conn = get_connection()
    df = build_features(conn, reference_date)
    conn.close()

    df.to_csv(output_path, index=False)
    logger.info(
        "Saved %s rows (%s exploited, %.2f%%) to %s",
        len(df),
        df["is_exploited"].sum(),
        100 * df["is_exploited"].mean() if len(df) else 0.0,
        output_path,
    )
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the model-ready feature table from the collected data")
    parser.add_argument("--output", help="Output CSV path (default: data/processed/features.csv)")
    args = parser.parse_args()
    run(output_path=args.output)


if __name__ == "__main__":
    main()
