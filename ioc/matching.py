#!/usr/bin/env python3
"""Compatibility entry point for backend IOC-to-STIX matching."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.core.settings import settings
from backend.app.integrations.taxii.paths import TAXII_BUNDLES_DIR
from backend.app.services.intelligence.ioc_pipeline import generate_stix_bundles as _generate_stix_bundles
from backend.app.services.intelligence.ioc_pipeline import load_whitelist as _load_whitelist
from backend.app.services.intelligence.ioc_pipeline import parse_alerts as _parse_alerts
from backend.app.services.intelligence.ioc_pipeline import read_iocs as _read_iocs
from backend.app.workers.ioc_worker import main, monitor


def load_whitelist(file=None):
    return _load_whitelist(file or settings.ioc_whitelist_file)


def load_latest_iocs(iocs_file=None):
    return _read_iocs(iocs_file or settings.ioc_output_file)


def parse_alerts(log_file=None):
    return _parse_alerts(log_file or settings.detector_alert_log_path)


def generate_stix_bundles():
    return _generate_stix_bundles(
        settings.detector_alert_log_path,
        settings.ioc_output_file,
        settings.ioc_whitelist_file,
        TAXII_BUNDLES_DIR,
    )


def monitor_and_generate():
    """Preserve the original STIX-generation monitoring command."""
    monitor("stix")


if __name__ == "__main__":
    main(["--mode", "stix", *sys.argv[1:]])
