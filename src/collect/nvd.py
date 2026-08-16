"""Collect CVE data from the NVD API (services.nvd.nist.gov/rest/json/cves/2.0)."""

import argparse
import json
import time
from datetime import datetime, timedelta, timezone

import requests

from src.config import (
    DB_PATH,
    NVD_API_KEY,
    NVD_BASE_URL,
    NVD_RATE_LIMIT_REQUESTS,
    NVD_RATE_LIMIT_WINDOW,
    RAW_DIR,
    get_logger,
)
from src.collect.storage import get_connection, get_last_modified_date, init_db, upsert_cves

logger = get_logger(__name__)

RESULTS_PER_PAGE = 2000
SLEEP_BETWEEN_REQUESTS = NVD_RATE_LIMIT_WINDOW / NVD_RATE_LIMIT_REQUESTS
MAX_RETRIES = 5
# NVD rejects lastMod date ranges spanning more than 120 days.
MAX_DATE_RANGE_DAYS = 120


def _headers() -> dict:
    return {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}


def _get_page(params: dict) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        response = requests.get(NVD_BASE_URL, params=params, headers=_headers(), timeout=30)
        if response.status_code == 200:
            return response.json()
        if response.status_code in (403, 429, 503):
            wait = min(60, 2**attempt)
            logger.warning("NVD returned %s, retrying in %ss (attempt %s)", response.status_code, wait, attempt)
            time.sleep(wait)
            continue
        response.raise_for_status()
    raise RuntimeError(f"Failed to fetch NVD page after {MAX_RETRIES} attempts: {params}")


def _parse_cvss(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            data = entry["cvssData"]
            return {
                "cvss_base_score": data.get("baseScore"),
                "cvss_impact_score": entry.get("impactScore"),
                "cvss_exploitability_score": entry.get("exploitabilityScore"),
                "cvss_attack_vector": data.get("attackVector"),
                "cvss_attack_complexity": data.get("attackComplexity"),
                "cvss_privileges_required": data.get("privilegesRequired"),
                "cvss_user_interaction": data.get("userInteraction"),
                "cvss_scope": data.get("scope"),
            }
    return {
        "cvss_base_score": None,
        "cvss_impact_score": None,
        "cvss_exploitability_score": None,
        "cvss_attack_vector": None,
        "cvss_attack_complexity": None,
        "cvss_privileges_required": None,
        "cvss_user_interaction": None,
        "cvss_scope": None,
    }


def _parse_cwe_ids(cve: dict) -> str:
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids.append(value)
    return ",".join(dict.fromkeys(cwe_ids))


def _parse_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def parse_cve_item(item: dict) -> dict:
    cve = item["cve"]
    return {
        "cve_id": cve["id"],
        "description": _parse_description(cve),
        "published_date": cve.get("published"),
        "last_modified_date": cve.get("lastModified"),
        "cwe_ids": _parse_cwe_ids(cve),
        "reference_count": len(cve.get("references", [])),
        "raw_json": json.dumps(cve),
        **_parse_cvss(cve),
    }


def fetch_cves(start_date: str | None = None, end_date: str | None = None) -> list[dict]:
    """Fetch all CVEs, optionally filtered by lastModified date range (ISO 8601)."""
    all_cves: list[dict] = []
    start_index = 0
    total_results = None

    while total_results is None or start_index < total_results:
        params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
        if start_date and end_date:
            params["lastModStartDate"] = start_date
            params["lastModEndDate"] = end_date

        page = _get_page(params)
        total_results = page["totalResults"]
        vulnerabilities = page.get("vulnerabilities", [])
        all_cves.extend(parse_cve_item(item) for item in vulnerabilities)

        logger.info("Fetched %s/%s CVEs", start_index + len(vulnerabilities), total_results)
        start_index += RESULTS_PER_PAGE
        if start_index < total_results:
            time.sleep(SLEEP_BETWEEN_REQUESTS)

    return all_cves


def _date_windows(start: datetime, end: datetime):
    """Split [start, end] into chunks <= MAX_DATE_RANGE_DAYS, as required by the NVD API."""
    current = start
    while current < end:
        window_end = min(current + timedelta(days=MAX_DATE_RANGE_DAYS), end)
        yield current, window_end
        current = window_end


def collect(start_date: str | None = None, end_date: str | None = None, incremental: bool = False) -> int:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    init_db(conn)

    if incremental:
        last_modified = get_last_modified_date(conn)
        start_date = last_modified or "2024-01-01T00:00:00.000"
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    total_saved = 0
    if start_date and end_date:
        start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        for window_start, window_end in _date_windows(start_dt, end_dt):
            cves = fetch_cves(
                window_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            )
            upsert_cves(conn, cves)
            total_saved += len(cves)
    else:
        cves = fetch_cves()
        upsert_cves(conn, cves)
        total_saved += len(cves)

    logger.info("Saved %s CVEs to %s", total_saved, DB_PATH)
    conn.close()
    return total_saved


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect CVE data from the NVD API")
    parser.add_argument("--start-date", help="ISO 8601 lastModStartDate")
    parser.add_argument("--end-date", help="ISO 8601 lastModEndDate")
    parser.add_argument("--incremental", action="store_true", help="Only fetch CVEs modified since the last run")
    args = parser.parse_args()
    collect(args.start_date, args.end_date, args.incremental)


if __name__ == "__main__":
    main()
