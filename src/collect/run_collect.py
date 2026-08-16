"""Orchestrate collection from all three sources: NVD, EPSS, CISA KEV.

Usage:
    python -m src.collect.run_collect --full          # full NVD history + current EPSS/KEV
    python -m src.collect.run_collect --incremental    # only new/modified CVEs + refreshed EPSS/KEV
"""

import argparse

from src.collect import epss, kev, nvd
from src.config import get_logger

logger = get_logger(__name__)


def run(incremental: bool) -> None:
    logger.info("=== Collecting NVD ===")
    nvd_count = nvd.collect(incremental=incremental)

    logger.info("=== Collecting EPSS ===")
    epss_count = epss.collect()

    logger.info("=== Collecting CISA KEV ===")
    kev_count = kev.collect()

    logger.info("Done. NVD: %s, EPSS: %s, KEV: %s", nvd_count, epss_count, kev_count)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the full CVE/EPSS/KEV collection pipeline")
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="Only fetch NVD CVEs modified since the last run (EPSS/KEV are always refreshed in full)",
    )
    args = parser.parse_args()
    run(incremental=args.incremental)


if __name__ == "__main__":
    main()
