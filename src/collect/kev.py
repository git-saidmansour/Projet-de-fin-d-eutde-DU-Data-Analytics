"""Collect the CISA Known Exploited Vulnerabilities (KEV) catalog.

Used as the ground-truth label source: a CVE present in this catalog is
treated as `is_exploited = 1`.
"""

import argparse
import json

import requests

from src.config import DB_PATH, KEV_URL, RAW_DIR, get_logger
from src.collect.storage import get_connection, init_db, upsert_kev

logger = get_logger(__name__)


def parse_row(entry: dict) -> dict:
    return {
        "cve_id": entry["cveID"],
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "short_description": entry.get("shortDescription"),
        "required_action": entry.get("requiredAction"),
        "due_date": entry.get("dueDate"),
        "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
    }


def fetch_kev() -> list[dict]:
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    catalog = response.json()

    RAW_DIR.joinpath("kev").mkdir(parents=True, exist_ok=True)
    RAW_DIR.joinpath("kev", "kev_latest.json").write_text(json.dumps(catalog, indent=2), encoding="utf-8")

    return [parse_row(entry) for entry in catalog.get("vulnerabilities", [])]


def collect() -> int:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    init_db(conn)

    rows = fetch_kev()
    upsert_kev(conn, rows)

    logger.info("Saved %s KEV entries to %s", len(rows), DB_PATH)
    conn.close()
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect the CISA KEV catalog")
    parser.parse_args()
    collect()


if __name__ == "__main__":
    main()
