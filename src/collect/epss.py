"""Collect EPSS scores from the FIRST.org API (api.first.org/data/v1/epss)."""

import argparse
import time

import requests

from src.config import DB_PATH, EPSS_BASE_URL, get_logger
from src.collect.storage import get_connection, init_db, upsert_epss

logger = get_logger(__name__)

PAGE_LIMIT = 1000
SLEEP_BETWEEN_REQUESTS = 0.2
MAX_RETRIES = 5


def _get_page(params: dict) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        response = requests.get(EPSS_BASE_URL, params=params, timeout=30)
        if response.status_code == 200:
            return response.json()
        wait = min(30, 2**attempt)
        logger.warning("EPSS API returned %s, retrying in %ss (attempt %s)", response.status_code, wait, attempt)
        time.sleep(wait)
    raise RuntimeError(f"Failed to fetch EPSS page after {MAX_RETRIES} attempts: {params}")


def parse_row(row: dict) -> dict:
    return {
        "cve_id": row["cve"],
        "score_date": row["date"],
        "epss": float(row["epss"]),
        "percentile": float(row["percentile"]),
    }


def fetch_epss(score_date: str | None = None) -> list[dict]:
    """Fetch EPSS scores for all CVEs, optionally for a specific historical date (YYYY-MM-DD)."""
    all_rows: list[dict] = []
    offset = 0
    total = None

    while total is None or offset < total:
        params = {"offset": offset, "limit": PAGE_LIMIT}
        if score_date:
            params["date"] = score_date

        page = _get_page(params)
        total = page["total"]
        page_limit = page.get("limit", PAGE_LIMIT)
        data = page.get("data", [])
        all_rows.extend(parse_row(row) for row in data)

        logger.info("Fetched %s/%s EPSS scores", offset + len(data), total)
        offset += page_limit
        if offset < total:
            time.sleep(SLEEP_BETWEEN_REQUESTS)

    return all_rows


def collect(score_date: str | None = None) -> int:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    init_db(conn)

    rows = fetch_epss(score_date)
    upsert_epss(conn, rows)

    logger.info("Saved %s EPSS scores to %s", len(rows), DB_PATH)
    conn.close()
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect EPSS scores from the FIRST.org API")
    parser.add_argument("--date", help="Historical score date (YYYY-MM-DD); defaults to the most recent")
    args = parser.parse_args()
    collect(args.date)


if __name__ == "__main__":
    main()
